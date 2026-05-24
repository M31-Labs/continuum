package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
	cruntime "m31labs.dev/continuum/runtime"
	"m31labs.dev/continuum/subject"
)

func TestStatusCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"status"}, &out, &errOut); err != nil {
		t.Fatalf("run status: %v", err)
	}
	if !strings.Contains(out.String(), "pre-alpha") {
		t.Fatalf("status output = %q", out.String())
	}
}

func TestVersionCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"version"}, &out, &errOut); err != nil {
		t.Fatalf("run version: %v", err)
	}
	if !strings.Contains(out.String(), "version=dev") || !strings.Contains(out.String(), "commit=unknown") {
		t.Fatalf("version output = %q", out.String())
	}
	out.Reset()
	if err := run([]string{"version", "--json"}, &out, &errOut); err != nil {
		t.Fatalf("run version --json: %v", err)
	}
	if !strings.Contains(out.String(), `"version":"dev"`) {
		t.Fatalf("version json output = %q", out.String())
	}
}

func TestDoctorCommandReportsConfigAndPaths(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "continuum.toml")
	manifestDir := filepath.Join(dir, "capabilities")
	if err := os.MkdirAll(manifestDir, 0700); err != nil {
		t.Fatal(err)
	}
	policyPath, err := filepath.Abs("../../examples/agent-workdir/policies/main.arb")
	if err != nil {
		t.Fatal(err)
	}
	configText := `[project]
name = "doctor-test"
version = "0.1.0"

[policy]
bundle = "` + policyPath + `"

[audit]
kind = "jsonl"
path = "state/audit.jsonl"

[subject]
default_kind = "agent"
default_mode = "ask"

[capabilities]
horizon_manifest_dir = "capabilities"

[state]
policy_store = "state/policies.json"
grant_store = "state/grants.json"
delivery_store = "state/deliveries.json"
session_store = "state/sessions.json"
airlock_store = "state/airlock.json"

[enforcement]
network = "observe"
file = "observe"
process = "observe"

[approval]
kind = "cli"
`
	if err := os.WriteFile(configPath, []byte(configText), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if err := run([]string{"doctor", "--config", configPath}, &out, &errOut); err != nil {
		t.Fatalf("doctor: %v\noutput=%s", err, out.String())
	}
	for _, want := range []string{"continuum doctor: ok", "policy bundle", "capabilities", "warnings="} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("doctor output missing %q: %s", want, out.String())
		}
	}
	out.Reset()
	if err := run([]string{"doctor", "--config", configPath, "--json"}, &out, &errOut); err != nil {
		t.Fatalf("doctor json: %v", err)
	}
	var report doctorReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("decode doctor json: %v\n%s", err, out.String())
	}
	if !report.OK || report.Project != "doctor-test" {
		t.Fatalf("doctor json report = %+v", report)
	}
}

func TestDoctorCommandFailsMissingPolicy(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "continuum.toml")
	configText := `[project]
name = "doctor-missing-policy"

[policy]
bundle = "missing.arb"
`
	if err := os.WriteFile(configPath, []byte(configText), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	err := run([]string{"doctor", "--config", configPath}, &out, &errOut)
	if err == nil {
		t.Fatal("doctor succeeded with missing policy")
	}
	if !strings.Contains(out.String(), "fail policy bundle") {
		t.Fatalf("doctor output = %q", out.String())
	}
}

func TestAgentStartValidatesPolicyBeforeServing(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "continuum.toml")
	config := `
[project]
name = "invalid-policy"

[policy]
bundle = "missing.arb"

[audit]
kind = "jsonl"
path = ".continuum/audit.jsonl"

[subject]
default_kind = "agent"
default_mode = "ask"

[capabilities]
horizon_manifest_dir = ".continuum/capabilities"

[state]
policy_store = ".continuum/policies.json"
grant_store = ".continuum/grants.json"
delivery_store = ".continuum/deliveries.json"
session_store = ".continuum/sessions.json"
airlock_store = ".continuum/airlock.json"

[enforcement]
network = "observe"
file = "observe"
process = "observe"

[approval]
kind = "cli"
`
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var out, errOut bytes.Buffer
	err := runAgent([]string{"start", "--config", configPath}, &out, &errOut)
	if err == nil {
		t.Fatal("runAgent succeeded with missing policy")
	}
	if !strings.Contains(err.Error(), "daemon readiness failed") || !strings.Contains(err.Error(), "policy") {
		t.Fatalf("error = %v", err)
	}
}

func TestAgentStartPrunesExpiredGrants(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "continuum.toml")
	grantStore := filepath.Join(dir, "state", "grants.json")
	deliveryStore := filepath.Join(dir, "state", "deliveries.json")
	manifestDir := filepath.Join(dir, "capabilities")
	if err := os.MkdirAll(manifestDir, 0700); err != nil {
		t.Fatal(err)
	}
	policyPath, err := filepath.Abs("../../examples/agent-workdir/policies/main.arb")
	if err != nil {
		t.Fatal(err)
	}
	configText := `[project]
name = "agent-prune"

[policy]
bundle = "` + policyPath + `"

[capabilities]
horizon_manifest_dir = "capabilities"

[state]
policy_store = "state/policies.json"
grant_store = "state/grants.json"
delivery_store = "state/deliveries.json"
session_store = "state/sessions.json"
airlock_store = "state/airlock.json"
`
	if err := os.WriteFile(configPath, []byte(configText), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	grants := &capability.GrantStore{}
	if err := grants.Add(capability.Grant{ID: "grant_expired", Session: "s1", Capability: "network.connect", Scope: map[string]any{"host": "old.example"}, Reason: "expired", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := grants.Add(capability.Grant{ID: "grant_active", Session: "s1", Capability: "network.connect", Scope: map[string]any{"host": "github.com"}, Reason: "active", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := grants.Save(grantStore); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if err := runAgent([]string{"start", "--config", configPath}, &out, &errOut); err != nil {
		t.Fatalf("agent start: %v\nout=%s", err, out.String())
	}
	if !strings.Contains(out.String(), "pruned expired_grants=1") {
		t.Fatalf("agent start output = %q", out.String())
	}
	stored, err := capability.LoadGrantStore(grantStore)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Grants) != 1 || stored.Grants[0].ID != "grant_active" {
		t.Fatalf("stored grants = %+v", stored.Grants)
	}
	deliveries, err := cruntime.LoadDeliveryStore(deliveryStore)
	if err != nil {
		t.Fatal(err)
	}
	items := deliveries.List()
	if len(items) != 1 || items[0].Capability != cruntime.GrantRevocationCapability {
		t.Fatalf("delivery items = %+v", items)
	}
}

func TestStatusCommandInspectsStores(t *testing.T) {
	dir := t.TempDir()
	policyStore := filepath.Join(dir, "policies.json")
	grantStore := filepath.Join(dir, "grants.json")
	airlockStore := filepath.Join(dir, "airlock.json")
	auditPath := filepath.Join(dir, "audit.jsonl")
	var out, errOut bytes.Buffer
	if err := run([]string{"policy", "publish", "--store", policyStore, "../../examples/agent-workdir/policies/main.arb"}, &out, &errOut); err != nil {
		t.Fatalf("policy publish: %v", err)
	}
	out.Reset()
	if err := run([]string{"policy", "activate", "--store", policyStore, "agent-workdir"}, &out, &errOut); err != nil {
		t.Fatalf("policy activate: %v", err)
	}
	out.Reset()
	if err := run([]string{"grant", "--store", grantStore, "--session", "s1", "--capability", "network.connect", "--host", "github.com", "--reason", "test grant"}, &out, &errOut); err != nil {
		t.Fatalf("grant: %v", err)
	}
	out.Reset()
	if err := run([]string{"airlock", "enter", "--store", airlockStore, "--pid", "123", "--reason", "test"}, &out, &errOut); err != nil {
		t.Fatalf("airlock enter: %v", err)
	}
	out.Reset()
	subj := subject.NewAgent("claude", "s1", "/repo", "", 123)
	sink, err := audit.NewJSONLSink(auditPath)
	if err != nil {
		t.Fatalf("NewJSONLSink: %v", err)
	}
	bundle, err := arbiterx.CompileFile("../../examples/agent-workdir/policies/main.arb")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	engine := cruntime.NewEngine(bundle, sink)
	if _, _, err := engine.DecideEvent(context.Background(), event.NewFileAccess(subj, "/repo/main.go", "write")); err != nil {
		t.Fatalf("DecideEvent: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	out.Reset()
	if err := run([]string{"status", "--policy-store", policyStore, "--grant-store", grantStore, "--airlock-store", airlockStore, "--audit", auditPath}, &out, &errOut); err != nil {
		t.Fatalf("status: %v", err)
	}
	for _, want := range []string{"active=agent-workdir", "active_grants=1", "airlocks=1", "audit_events=1"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("status output missing %q: %s", want, out.String())
		}
	}
}

func TestPolicyPublishCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	store := filepath.Join(t.TempDir(), "policies.json")
	err := run([]string{"policy", "publish", "--store", store, "../../examples/agent-workdir/policies/main.arb"}, &out, &errOut)
	if err != nil {
		t.Fatalf("policy publish: %v", err)
	}
	if !strings.Contains(out.String(), "published policy") {
		t.Fatalf("publish output = %q", out.String())
	}
}

func TestPolicyCheckCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{"policy", "check", "../../examples/agent-workdir/policies/main.arb"}, &out, &errOut)
	if err != nil {
		t.Fatalf("policy check: %v", err)
	}
	if !strings.Contains(out.String(), "policy ok") || !strings.Contains(out.String(), "kind=agent-workdir") {
		t.Fatalf("check output = %q", out.String())
	}
}

func TestCapabilitiesCommandFiltersKind(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{"capabilities", "--manifest-dir", "../../testdata/horizon-manifests", "--kind", "source"}, &out, &errOut)
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	if !strings.Contains(out.String(), "kernel.process.exec.observe") {
		t.Fatalf("capabilities output = %q", out.String())
	}
	if strings.Contains(out.String(), "observe.audit") {
		t.Fatalf("source filter included sink: %q", out.String())
	}
}

func TestCapabilitiesCommandJSON(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{"capabilities", "--manifest-dir", "../../testdata/manifests", "--kind", "worker", "--json"}, &out, &errOut)
	if err != nil {
		t.Fatalf("capabilities json: %v", err)
	}
	if !strings.Contains(out.String(), `"name": "noop.enforcement"`) {
		t.Fatalf("json output = %q", out.String())
	}
}

func TestCapabilitiesCommandWarnsForDangerousCapabilities(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{"capabilities", "--kind", "worker"}, &out, &errOut)
	if err != nil {
		t.Fatalf("capabilities: %v", err)
	}
	if !strings.Contains(out.String(), "WARNING: privileged/destructive capabilities") || !strings.Contains(out.String(), "kernel.process.kill") {
		t.Fatalf("danger warning output = %q", out.String())
	}
}

func TestCapabilitiesInspectHorizonArtifacts(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{"capabilities", "inspect", "--json", "../../testdata/horizon-export"}, &out, &errOut)
	if err != nil {
		t.Fatalf("capabilities inspect: %v", err)
	}
	if !strings.Contains(out.String(), `"kind": "exported-package"`) || !strings.Contains(out.String(), `"kernel.process.exec.observe"`) || !strings.Contains(out.String(), `"kind": "bpf-object"`) {
		t.Fatalf("inspect output = %q", out.String())
	}
	out.Reset()
	err = run([]string{"capabilities", "inspect", "../../testdata/horizon-export/input.hzn"}, &out, &errOut)
	if err != nil {
		t.Fatalf("capabilities inspect hzn: %v", err)
	}
	if !strings.Contains(out.String(), "needs_export=true") || !strings.Contains(out.String(), "Horizon") {
		t.Fatalf("inspect hzn output = %q", out.String())
	}
}

func TestPolicyActivateCommand(t *testing.T) {
	store := filepath.Join(t.TempDir(), "policies.json")
	var out, errOut bytes.Buffer
	if err := run([]string{"policy", "publish", "--store", store, "../../examples/agent-workdir/policies/main.arb"}, &out, &errOut); err != nil {
		t.Fatalf("policy publish: %v", err)
	}
	out.Reset()
	if err := run([]string{"policy", "activate", "--store", store, "agent-workdir"}, &out, &errOut); err != nil {
		t.Fatalf("policy activate: %v", err)
	}
	if !strings.Contains(out.String(), "activated policy name=agent-workdir") {
		t.Fatalf("activate output = %q", out.String())
	}
}

func TestPolicyListAndShowCommands(t *testing.T) {
	store := filepath.Join(t.TempDir(), "policies.json")
	var out, errOut bytes.Buffer
	if err := run([]string{"policy", "publish", "--store", store, "../../examples/agent-workdir/policies/main.arb"}, &out, &errOut); err != nil {
		t.Fatalf("policy publish: %v", err)
	}
	out.Reset()
	if err := run([]string{"policy", "activate", "--store", store, "agent-workdir"}, &out, &errOut); err != nil {
		t.Fatalf("policy activate: %v", err)
	}
	out.Reset()
	if err := run([]string{"policy", "list", "--store", store}, &out, &errOut); err != nil {
		t.Fatalf("policy list: %v", err)
	}
	if !strings.Contains(out.String(), "* agent-workdir") {
		t.Fatalf("policy list output = %q", out.String())
	}
	out.Reset()
	if err := run([]string{"policy", "show", "--store", store, "agent-workdir"}, &out, &errOut); err != nil {
		t.Fatalf("policy show: %v", err)
	}
	if !strings.Contains(out.String(), "active=true") || !strings.Contains(out.String(), "kind=agent-workdir") {
		t.Fatalf("policy show output = %q", out.String())
	}
}

func TestConfigStatePathsDriveCommands(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "continuum.toml")
	policyStore := filepath.Join(dir, "state", "policies.json")
	grantStore := filepath.Join(dir, "state", "grants.json")
	deliveryStore := filepath.Join(dir, "state", "deliveries.json")
	sessionStore := filepath.Join(dir, "state", "sessions.json")
	airlockStore := filepath.Join(dir, "state", "airlock.json")
	auditPath := filepath.Join(dir, "state", "audit.jsonl")
	repoRoot := filepath.Join(dir, "repo")
	if err := os.MkdirAll(repoRoot, 0755); err != nil {
		t.Fatal(err)
	}
	configText := `[project]
name = "configured"
version = "0.1.0"

[policy]
bundle = "../../examples/agent-workdir/policies/main.arb"

[audit]
kind = "jsonl"
path = "state/audit.jsonl"

[subject]
default_kind = "agent"
default_mode = "ask"

[capabilities]
horizon_manifest_dir = "../../testdata/horizon-manifests"

[state]
policy_store = "state/policies.json"
grant_store = "state/grants.json"
delivery_store = "state/deliveries.json"
session_store = "state/sessions.json"
airlock_store = "state/airlock.json"

[enforcement]
network = "observe"
file = "observe"
process = "observe"

[approval]
kind = "cli"
`
	if err := os.WriteFile(configPath, []byte(configText), 0644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if err := run([]string{"policy", "publish", "--config", configPath, "../../examples/agent-workdir/policies/main.arb"}, &out, &errOut); err != nil {
		t.Fatalf("policy publish with config: %v", err)
	}
	if _, err := os.Stat(policyStore); err != nil {
		t.Fatalf("policy store not created at config path: %v", err)
	}
	out.Reset()
	if err := run([]string{"policy", "activate", "--config", configPath, "agent-workdir"}, &out, &errOut); err != nil {
		t.Fatalf("policy activate with config: %v", err)
	}
	out.Reset()
	if err := run([]string{"grant", "--config", configPath, "--session", "agent-session-42", "--capability", "network.connect", "--host", "github.com", "--reason", "test grant"}, &out, &errOut); err != nil {
		t.Fatalf("grant with config: %v", err)
	}
	if _, err := os.Stat(grantStore); err != nil {
		t.Fatalf("grant store not created at config path: %v", err)
	}
	out.Reset()
	if err := run([]string{"airlock", "enter", "--config", configPath, "--pid", "1234", "--reason", "test"}, &out, &errOut); err != nil {
		t.Fatalf("airlock enter with config: %v", err)
	}
	if _, err := os.Stat(airlockStore); err != nil {
		t.Fatalf("airlock store not created at config path: %v", err)
	}
	out.Reset()
	if err := run([]string{"run", "--config", configPath, "--agent", "claude", "--repo", repoRoot, "--", "/bin/true"}, &out, &errOut); err != nil {
		t.Fatalf("run with config: %v\nstderr=%s", err, errOut.String())
	}
	if _, err := os.Stat(sessionStore); err != nil {
		t.Fatalf("session store not created at config path: %v", err)
	}
	if _, err := os.Stat(auditPath); err != nil {
		t.Fatalf("audit log not created at config path: %v", err)
	}
	if _, err := os.Stat(deliveryStore); err != nil {
		t.Fatalf("delivery store not created at config path: %v", err)
	}
	out.Reset()
	if err := run([]string{"sessions", "list", "--config", configPath}, &out, &errOut); err != nil {
		t.Fatalf("sessions list with config: %v", err)
	}
	if !strings.Contains(out.String(), "agent-session-") {
		t.Fatalf("sessions list output = %q", out.String())
	}
}

func TestRunUsesActivePolicyStore(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "policies.json")
	var out, errOut bytes.Buffer
	if err := run([]string{"policy", "publish", "--store", store, "../../examples/agent-workdir/policies/main.arb"}, &out, &errOut); err != nil {
		t.Fatalf("policy publish: %v", err)
	}
	out.Reset()
	if err := run([]string{"policy", "activate", "--store", store, "agent-workdir"}, &out, &errOut); err != nil {
		t.Fatalf("policy activate: %v", err)
	}
	out.Reset()
	if err := run([]string{
		"run",
		"--policy-store", store,
		"--agent", "claude",
		"--repo", dir,
		"--audit", filepath.Join(dir, "audit.jsonl"),
		"--sessions", filepath.Join(dir, "sessions.json"),
		"--",
		"/bin/true",
	}, &out, &errOut); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), "policy=../../examples/agent-workdir/policies/main.arb") {
		t.Fatalf("run output = %q", out.String())
	}
}

func TestReplayDiffCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{
		"replay",
		"--baseline-policy", "../../examples/airlock/policies/main.arb",
		"--policy", "../../examples/agent-workdir/policies/main.arb",
		"--events", "../../testdata/events/file_secret_access.json",
	}, &out, &errOut)
	if err != nil {
		t.Fatalf("replay diff: %v", err)
	}
	if !strings.Contains(out.String(), "evt_secret") || !strings.Contains(out.String(), "audit") || !strings.Contains(out.String(), "deny") {
		t.Fatalf("diff output = %q", out.String())
	}
}

func TestRunCommandAuditsSyntheticProcess(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	sessionPath := filepath.Join(dir, "sessions.json")
	var out, errOut bytes.Buffer
	err := run([]string{
		"run",
		"--agent", "claude",
		"--repo", dir,
		"--policy", "../../examples/agent-workdir/policies/main.arb",
		"--audit", auditPath,
		"--sessions", sessionPath,
		"--",
		"/bin/true",
	}, &out, &errOut)
	if err != nil {
		t.Fatalf("run command: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "ALLOW process.exec true") {
		t.Fatalf("run output = %q", out.String())
	}
	out.Reset()
	if err := run([]string{"status", "--session-store", sessionPath, "--audit", auditPath}, &out, &errOut); err != nil {
		t.Fatalf("status after run: %v", err)
	}
	if !strings.Contains(out.String(), "sessions=1") {
		t.Fatalf("status output = %q", out.String())
	}
	out.Reset()
	if err := run([]string{"sessions", "list", "--store", sessionPath, "--state", "exited"}, &out, &errOut); err != nil {
		t.Fatalf("sessions list: %v", err)
	}
	if !strings.Contains(out.String(), "agent-session-") || !strings.Contains(out.String(), "/bin/true") {
		t.Fatalf("sessions output = %q", out.String())
	}
	sessionID := strings.Fields(out.String())[0]
	out.Reset()
	if err := run([]string{"sessions", "show", "--store", sessionPath, sessionID}, &out, &errOut); err != nil {
		t.Fatalf("sessions show: %v", err)
	}
	if !strings.Contains(out.String(), "state=exited") {
		t.Fatalf("sessions show output = %q", out.String())
	}
	if !strings.Contains(out.String(), "processes=1") {
		t.Fatalf("sessions show output missing process count = %q", out.String())
	}
}

func TestSessionsHeartbeatAndMarkStaleCommands(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	now := time.Now().UTC().Add(-time.Hour)
	store := &cruntime.SessionStore{}
	store.Upsert(cruntime.Session{
		ID:              "agent-session-1",
		State:           cruntime.SessionRunning,
		StartedAt:       now,
		LastHeartbeatAt: now,
	})
	if err := store.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	var out, errOut bytes.Buffer
	if err := run([]string{"sessions", "mark-stale", "--store", path, "--after", "10m"}, &out, &errOut); err != nil {
		t.Fatalf("sessions mark-stale: %v", err)
	}
	if !strings.Contains(out.String(), "stale_sessions=1") {
		t.Fatalf("mark-stale output = %q", out.String())
	}
	out.Reset()
	if err := run([]string{"sessions", "list", "--store", path, "--state", "stale"}, &out, &errOut); err != nil {
		t.Fatalf("sessions list stale: %v", err)
	}
	if !strings.Contains(out.String(), "agent-session-1") || !strings.Contains(out.String(), "stale") {
		t.Fatalf("stale list output = %q", out.String())
	}
	out.Reset()
	if err := run([]string{"sessions", "heartbeat", "--store", path, "agent-session-1"}, &out, &errOut); err != nil {
		t.Fatalf("sessions heartbeat: %v", err)
	}
	if !strings.Contains(out.String(), "state=running") {
		t.Fatalf("heartbeat output = %q", out.String())
	}
	out.Reset()
	if err := run([]string{"sessions", "show", "--store", path, "agent-session-1"}, &out, &errOut); err != nil {
		t.Fatalf("sessions show: %v", err)
	}
	if !strings.Contains(out.String(), "last_heartbeat=") || strings.Contains(out.String(), "last_heartbeat=-") {
		t.Fatalf("sessions show output = %q", out.String())
	}
}

func TestGrantCommandPersistsAndLists(t *testing.T) {
	store := filepath.Join(t.TempDir(), "grants.json")
	var out, errOut bytes.Buffer
	err := run([]string{
		"grant",
		"--store", store,
		"--session", "agent-session-42",
		"--capability", "network.connect",
		"--host", "github.com",
		"--port", "443",
		"--reason", "fetch dependency",
	}, &out, &errOut)
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if !strings.Contains(out.String(), "grant id=") {
		t.Fatalf("grant output = %q", out.String())
	}
	out.Reset()
	if err := run([]string{"grant", "list", "--store", store}, &out, &errOut); err != nil {
		t.Fatalf("grant list: %v", err)
	}
	if !strings.Contains(out.String(), "network.connect") {
		t.Fatalf("grant list output = %q", out.String())
	}
}

func TestGrantCommandRequiresReason(t *testing.T) {
	store := filepath.Join(t.TempDir(), "grants.json")
	var out, errOut bytes.Buffer
	err := run([]string{
		"grant",
		"--store", store,
		"--session", "agent-session-42",
		"--capability", "network.connect",
		"--host", "github.com",
	}, &out, &errOut)
	if err == nil {
		t.Fatal("grant succeeded without reason")
	}
	if !strings.Contains(err.Error(), "--reason") {
		t.Fatalf("error = %v", err)
	}
}

func TestGrantCommandRejectsTTLAboveConfiguredMax(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "continuum.toml")
	if err := os.WriteFile(configPath, []byte("[grant]\nmax_ttl = \"1m\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	err := run([]string{
		"grant",
		"--config", configPath,
		"--store", filepath.Join(dir, "grants.json"),
		"--session", "agent-session-42",
		"--capability", "network.connect",
		"--host", "github.com",
		"--ttl", "2m",
		"--reason", "fetch dependency",
	}, &out, &errOut)
	if err == nil {
		t.Fatal("grant succeeded with TTL above configured maximum")
	}
	if !strings.Contains(err.Error(), "exceeds configured maximum") {
		t.Fatalf("error = %v", err)
	}
}

func TestGrantCommandRejectsInvalidNetworkScope(t *testing.T) {
	store := filepath.Join(t.TempDir(), "grants.json")
	for _, args := range [][]string{
		{"grant", "--store", store, "--session", "agent-session-42", "--capability", "network.connect", "--host", "bad host", "--reason", "test"},
		{"grant", "--store", store, "--session", "agent-session-42", "--capability", "network.connect", "--host", "github.com", "--port", "70000", "--reason", "test"},
		{"grant", "--store", store, "--session", "agent-session-42", "--capability", "network.connect", "--host", "github.com:443", "--reason", "test"},
	} {
		var out, errOut bytes.Buffer
		err := run(args, &out, &errOut)
		if err == nil {
			t.Fatalf("grant succeeded for args %v", args)
		}
	}
}

func TestGrantCommandPersistsFileScope(t *testing.T) {
	store := filepath.Join(t.TempDir(), "grants.json")
	var out, errOut bytes.Buffer
	err := run([]string{
		"grant",
		"--store", store,
		"--session", "agent-session-42",
		"--capability", "file.write",
		"--path", "/repo/.github/workflows/test.yml",
		"--op", "write",
		"--reason", "approve CI workflow edit",
	}, &out, &errOut)
	if err != nil {
		t.Fatalf("grant file: %v", err)
	}
	if !strings.Contains(out.String(), "file.write") {
		t.Fatalf("grant output = %q", out.String())
	}
}

func TestGrantCommandRejectsInvalidFileScope(t *testing.T) {
	store := filepath.Join(t.TempDir(), "grants.json")
	for _, args := range [][]string{
		{"grant", "--store", store, "--session", "agent-session-42", "--capability", "file.write", "--path", ".", "--reason", "test"},
		{"grant", "--store", store, "--session", "agent-session-42", "--capability", "file.write", "--path-prefix", "/", "--reason", "test"},
		{"grant", "--store", store, "--session", "agent-session-42", "--capability", "file.write", "--path", "/repo/file", "--path-prefix", "/repo", "--reason", "test"},
	} {
		var out, errOut bytes.Buffer
		err := run(args, &out, &errOut)
		if err == nil {
			t.Fatalf("grant succeeded for args %v", args)
		}
	}
}

func TestAirlockCommandPersistsState(t *testing.T) {
	store := filepath.Join(t.TempDir(), "airlock.json")
	var out, errOut bytes.Buffer
	if err := run([]string{"airlock", "enter", "--store", store, "--pid", "1234", "--reason", "test"}, &out, &errOut); err != nil {
		t.Fatalf("airlock enter: %v", err)
	}
	if !strings.Contains(out.String(), "ENTER_AIRLOCK") {
		t.Fatalf("enter output = %q", out.String())
	}
	out.Reset()
	if err := run([]string{"airlock", "status", "--store", store}, &out, &errOut); err != nil {
		t.Fatalf("airlock status: %v", err)
	}
	if !strings.Contains(out.String(), "airlocked") {
		t.Fatalf("status output = %q", out.String())
	}
}

func TestAirlockAccumulateCommandEntersAirlock(t *testing.T) {
	dir := t.TempDir()
	subj := subject.NewAgent("claude", "agent-42", "/repo", "", 1234)
	var events []event.Event
	for i := 0; i < 21; i++ {
		events = append(events, event.NewProcessExec(subj, map[string]any{
			"comm":      "sh",
			"argv_text": "sh -c true",
			"cwd":       "/repo",
		}))
	}
	for i := 0; i < 51; i++ {
		events = append(events, event.NewNetworkConnect(subj, "host-"+strconv.Itoa(i)+".example", "10.0.0."+strconv.Itoa(i), 443))
	}
	data, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	eventsPath := filepath.Join(dir, "events.json")
	if err := os.WriteFile(eventsPath, data, 0644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if err := run([]string{
		"airlock", "accumulate",
		"--events", eventsPath,
		"--policy", "../../examples/airlock/policies/main.arb",
		"--audit", filepath.Join(dir, "audit.jsonl"),
		"--store", filepath.Join(dir, "airlock.json"),
	}, &out, &errOut); err != nil {
		t.Fatalf("airlock accumulate: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "ENTER_AIRLOCK") || !strings.Contains(out.String(), "worm-like process/network fanout") {
		t.Fatalf("accumulate output = %q", out.String())
	}
}

func TestLoadEventsAcceptsAuditJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := audit.NewJSONLSink(path)
	if err != nil {
		t.Fatalf("NewJSONLSink: %v", err)
	}
	bundle, err := arbiterx.CompileFile("../../examples/agent-workdir/policies/main.arb")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	engine := cruntime.NewEngine(bundle, sink)
	subj := subject.NewAgent("claude", "agent-42", "/repo", "", 123)
	if _, _, err := engine.DecideEvent(context.Background(), event.NewFileAccess(subj, "/repo/main.go", "write")); err != nil {
		t.Fatalf("DecideEvent: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	events, err := loadEvents(path)
	if err != nil {
		t.Fatalf("loadEvents: %v", err)
	}
	if len(events) != 1 || events[0].Kind != event.KindFileAccess {
		t.Fatalf("events = %+v", events)
	}
}

func TestLoadEventsAcceptsPrettySingleEvent(t *testing.T) {
	events, err := loadEvents("../../testdata/events/file_secret_access.json")
	if err != nil {
		t.Fatalf("loadEvents: %v", err)
	}
	if len(events) != 1 || events[0].Kind != event.KindFileOpen {
		t.Fatalf("events = %+v", events)
	}
}

func TestIngestCommandEvaluatesAndAuditsFixture(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	var out, errOut bytes.Buffer
	err := run([]string{
		"ingest",
		"--policy", "../../examples/agent-workdir/policies/main.arb",
		"--events", "../../testdata/events/file_secret_access.json",
		"--audit", auditPath,
	}, &out, &errOut)
	if err != nil {
		t.Fatalf("ingest: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "DENY file.open") || !strings.Contains(out.String(), "ingested=1") {
		t.Fatalf("ingest output = %q", out.String())
	}
	events, err := audit.ReadJSONL(auditPath)
	if err != nil {
		t.Fatalf("ReadJSONL: %v", err)
	}
	if len(events) != 1 || events[0].Decision != "deny" {
		t.Fatalf("audit events = %+v", events)
	}
}

func TestIngestCommandAccumulatesAirlockBehavior(t *testing.T) {
	dir := t.TempDir()
	subj := subject.NewAgent("claude", "agent-42", "/repo", "", 123)
	var events []event.Event
	for i := 0; i < 21; i++ {
		events = append(events, event.NewProcessExec(subj, map[string]any{
			"comm":      "sh",
			"argv_text": "sh -c true",
			"cwd":       "/repo",
		}))
	}
	for i := 0; i < 51; i++ {
		events = append(events, event.NewNetworkConnect(subj, "host-"+strconv.Itoa(i)+".example", "10.0.0."+strconv.Itoa(i), 443))
	}
	data, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	eventsPath := filepath.Join(dir, "events.json")
	if err := os.WriteFile(eventsPath, data, 0644); err != nil {
		t.Fatal(err)
	}
	airlockStore := filepath.Join(dir, "airlock.json")
	var out, errOut bytes.Buffer
	if err := run([]string{
		"ingest",
		"--policy", "../../examples/agent-workdir/policies/main.arb",
		"--airlock-policy", "../../examples/airlock/policies/main.arb",
		"--events", eventsPath,
		"--audit", filepath.Join(dir, "audit.jsonl"),
		"--airlock-store", airlockStore,
	}, &out, &errOut); err != nil {
		t.Fatalf("ingest: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "ENTER_AIRLOCK") || !strings.Contains(out.String(), "worm-like process/network fanout") {
		t.Fatalf("ingest output = %q", out.String())
	}
	var statusOut bytes.Buffer
	if err := run([]string{"airlock", "status", "--store", airlockStore}, &statusOut, &errOut); err != nil {
		t.Fatalf("airlock status: %v", err)
	}
	if !strings.Contains(statusOut.String(), "airlocked") {
		t.Fatalf("airlock status output = %q", statusOut.String())
	}
}

func TestIngestCommandAcceptsHorizonEnvelope(t *testing.T) {
	dir := t.TempDir()
	eventPath := filepath.Join(dir, "horizon.json")
	sessionPath := filepath.Join(dir, "sessions.json")
	if err := os.WriteFile(eventPath, []byte(`{
  "id": "hzn_1",
  "capability": "kernel.process.exec.observe",
  "subject": {
    "kind": "agent",
    "session": "agent-42",
    "agent_name": "claude",
    "repo_root": "/repo"
  },
  "fields": {
    "pid": 777,
    "comm": "go",
    "argv_text": "go test ./...",
    "cwd": "/repo"
  }
}`), 0644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	err := run([]string{
		"ingest",
		"--manifest-dir", "../../testdata/horizon-manifests",
		"--policy", "../../examples/agent-workdir/policies/main.arb",
		"--events", eventPath,
		"--audit", filepath.Join(dir, "audit.jsonl"),
		"--sessions", sessionPath,
	}, &out, &errOut)
	if err != nil {
		t.Fatalf("ingest horizon: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "ALLOW process.exec go") || !strings.Contains(out.String(), "process_events=1") {
		t.Fatalf("ingest output = %q", out.String())
	}
	sessions, err := cruntime.LoadSessionStore(sessionPath)
	if err != nil {
		t.Fatalf("LoadSessionStore: %v", err)
	}
	if len(sessions.Sessions) != 1 || sessions.Sessions[0].ProcessTree == nil || sessions.Sessions[0].ProcessTree.RootPID != 777 {
		t.Fatalf("sessions = %+v", sessions.Sessions)
	}
}

func TestIngestApprovalAllowCreatesGrant(t *testing.T) {
	dir := t.TempDir()
	eventPath := filepath.Join(dir, "ci-write.json")
	if err := os.WriteFile(eventPath, []byte(`{
  "id": "evt_ci",
  "kind": "file.access",
  "subject": {
    "kind": "agent",
    "session": "agent-42",
    "agent_name": "claude",
    "repo_root": "/repo"
  },
  "fields": {
    "path": "/repo/.github/workflows/test.yml",
    "op": "write"
  }
}`), 0644); err != nil {
		t.Fatal(err)
	}
	grantPath := filepath.Join(dir, "grants.json")
	var out, errOut bytes.Buffer
	err := run([]string{
		"ingest",
		"--policy", "../../examples/agent-workdir/policies/main.arb",
		"--events", eventPath,
		"--audit", filepath.Join(dir, "audit.jsonl"),
		"--grants", grantPath,
		"--approval", "allow",
	}, &out, &errOut)
	if err != nil {
		t.Fatalf("ingest approval: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "ASK file.access") || !strings.Contains(out.String(), "approval=granted") {
		t.Fatalf("approval output = %q", out.String())
	}
	out.Reset()
	if err := run([]string{"grant", "list", "--store", grantPath}, &out, &errOut); err != nil {
		t.Fatalf("grant list: %v", err)
	}
	if !strings.Contains(out.String(), "file.write") {
		t.Fatalf("grant output = %q", out.String())
	}
	store, err := capability.LoadGrantStore(grantPath)
	if err != nil {
		t.Fatalf("LoadGrantStore: %v", err)
	}
	if len(store.Grants) != 1 || store.Grants[0].Reason == "" {
		t.Fatalf("approval grant missing reason: %+v", store.Grants)
	}
	out.Reset()
	if err := run([]string{
		"ingest",
		"--policy", "../../examples/agent-workdir/policies/main.arb",
		"--events", eventPath,
		"--audit", filepath.Join(dir, "audit-second.jsonl"),
		"--grants", grantPath,
		"--approval", "deny",
	}, &out, &errOut); err != nil {
		t.Fatalf("ingest with grant: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "ALLOW file.access") || strings.Contains(out.String(), "approval=denied") {
		t.Fatalf("grant-backed ingest output = %q", out.String())
	}
}

func TestGrantRevokeQueuesDelivery(t *testing.T) {
	dir := t.TempDir()
	grantPath := filepath.Join(dir, "grants.json")
	deliveryPath := filepath.Join(dir, "deliveries.json")
	var out, errOut bytes.Buffer
	if err := run([]string{"grant", "--store", grantPath, "--session", "agent-42", "--capability", "network.connect", "--host", "github.com", "--reason", "fetch dependency"}, &out, &errOut); err != nil {
		t.Fatalf("grant: %v", err)
	}
	fields := strings.Fields(out.String())
	var grantID string
	for _, field := range fields {
		if strings.HasPrefix(field, "id=") {
			grantID = strings.TrimPrefix(field, "id=")
		}
	}
	if grantID == "" {
		t.Fatalf("grant output missing id: %q", out.String())
	}
	out.Reset()
	if err := run([]string{"grant", "revoke", "--store", grantPath, "--delivery-store", deliveryPath, grantID}, &out, &errOut); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !strings.Contains(out.String(), "delivery=") {
		t.Fatalf("revoke output = %q", out.String())
	}
	queue, err := cruntime.LoadDeliveryStore(deliveryPath)
	if err != nil {
		t.Fatalf("LoadDeliveryStore: %v", err)
	}
	items := queue.ByStatus(cruntime.DeliveryPending)
	if len(items) != 1 || items[0].Capability != cruntime.GrantRevocationCapability {
		t.Fatalf("delivery items = %+v", queue.List())
	}
}

func TestAuditListFilters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := audit.NewJSONLSink(path)
	if err != nil {
		t.Fatalf("NewJSONLSink: %v", err)
	}
	bundle, err := arbiterx.CompileFile("../../examples/agent-workdir/policies/main.arb")
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	engine := cruntime.NewEngine(bundle, sink)
	subj := subject.NewAgent("claude", "agent-42", "/repo", "", 123)
	if _, _, err := engine.DecideEvent(context.Background(), event.NewFileAccess(subj, "/repo/main.go", "write")); err != nil {
		t.Fatalf("DecideEvent allow: %v", err)
	}
	if _, _, err := engine.DecideEvent(context.Background(), event.NewFileAccess(subj, "/home/draco/.ssh/id_ed25519", "read")); err != nil {
		t.Fatalf("DecideEvent deny: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	var out, errOut bytes.Buffer
	if err := run([]string{"audit", "list", "--path", path, "--decision", "deny", "--kind", "file.access"}, &out, &errOut); err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if !strings.Contains(out.String(), "DenyHostSecrets") || strings.Contains(out.String(), "AllowInsideRepo") {
		t.Fatalf("audit filter output = %q", out.String())
	}
	out.Reset()
	if err := run([]string{"audit", "list", "--path", path, "--offset", "1", "--limit", "1", "--json"}, &out, &errOut); err != nil {
		t.Fatalf("audit list paged: %v", err)
	}
	var paged []audit.Event
	if err := json.Unmarshal(out.Bytes(), &paged); err != nil {
		t.Fatalf("decode paged audit list: %v", err)
	}
	if len(paged) != 1 || paged[0].Outcome.Rule != "DenyHostSecrets" {
		t.Fatalf("paged audit output = %+v", paged)
	}
	out.Reset()
	exportPath := filepath.Join(t.TempDir(), "exports", "audit-redacted.jsonl")
	if err := run([]string{"audit", "export", "--path", path, "--out", exportPath, "--offset", "1", "--limit", "1", "--redact-fields", "path", "--redact-subject", "--redact-raw"}, &out, &errOut); err != nil {
		t.Fatalf("audit export: %v", err)
	}
	if !strings.Contains(out.String(), "exported audit events=1") || !strings.Contains(out.String(), "redacted=true") {
		t.Fatalf("audit export output = %q", out.String())
	}
	exportData, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatalf("ReadFile export: %v", err)
	}
	info, err := os.Stat(exportPath)
	if err != nil {
		t.Fatalf("Stat export: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("export mode = %v, want 0600", got)
	}
	if strings.Contains(string(exportData), "/home/draco/.ssh") || strings.Contains(string(exportData), "chain_hash") {
		t.Fatalf("redacted export leaked source values or chain hash: %s", string(exportData))
	}
	var exported audit.Event
	if err := json.Unmarshal(bytes.TrimSpace(exportData), &exported); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	if exported.InputEvent.Fields["path"] != "[REDACTED]" || exported.Subject.Session != "" {
		t.Fatalf("redacted export event = %+v", exported)
	}
	out.Reset()
	if err := run([]string{"audit", "verify", "--path", path}, &out, &errOut); err != nil {
		t.Fatalf("audit verify: %v", err)
	}
	if !strings.Contains(out.String(), "audit chain ok events=2") {
		t.Fatalf("audit verify output = %q", out.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), "DenyHostSecrets", "DenyTampered", 1)), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	out.Reset()
	err = run([]string{"audit", "verify", "--path", path}, &out, &errOut)
	if err == nil {
		t.Fatal("audit verify succeeded on tampered log")
	}
	if !strings.Contains(out.String(), "audit chain failed") {
		t.Fatalf("tamper verify output = %q", out.String())
	}
}
