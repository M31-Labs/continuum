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

	"m31labs.dev/continuum/airlock"
	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/policy"
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
	if !strings.Contains(out.String(), "policy ok") || !strings.Contains(out.String(), "kind=agent-workdir") || !strings.Contains(out.String(), "inputs=") || !strings.Contains(out.String(), "routes=") {
		t.Fatalf("check output = %q", out.String())
	}
	out.Reset()
	err = run([]string{"policy", "check", "--json", "../../examples/agent-workdir/policies/main.arb"}, &out, &errOut)
	if err != nil {
		t.Fatalf("policy check json: %v", err)
	}
	var report policyCheckReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("decode policy check json: %v\n%s", err, out.String())
	}
	if report.Kind != "agent-workdir" || len(report.Inputs.Fields) == 0 || len(report.Routes.Routes) == 0 {
		t.Fatalf("policy check json = %+v", report)
	}
}

func TestPolicyCheckRejectsUnsupportedOutcomeRoute(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unsupported.arb")
	if err := os.WriteFile(path, []byte(`
input {
	file: {
		path: string
	}
}

outcome Quarantine {
	reason: string
}

rule Unsupported priority 1 {
	when {
		file.path == "/tmp/x"
	}
	then Quarantine {
		reason: "unsupported",
	}
}
`), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var out, errOut bytes.Buffer
	err := run([]string{"policy", "check", path}, &out, &errOut)
	if err == nil {
		t.Fatalf("policy check succeeded: %s", out.String())
	}
	if !strings.Contains(err.Error(), "policy outcome route validation failed") || !strings.Contains(err.Error(), "Quarantine") {
		t.Fatalf("policy check error = %v", err)
	}
}

func TestPolicyCheckRejectsUnsupportedInputField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unsupported-input.arb")
	if err := os.WriteFile(path, []byte(`
input {
	kernel: {
		raw_pid: number
	}
}

outcome Allow {
	reason: string
}

rule UnsupportedInput priority 1 {
	when {
		kernel.raw_pid > 0
	}
	then Allow {
		reason: "unsupported",
	}
}
`), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var out, errOut bytes.Buffer
	err := run([]string{"policy", "check", path}, &out, &errOut)
	if err == nil {
		t.Fatalf("policy check succeeded: %s", out.String())
	}
	if !strings.Contains(err.Error(), "policy input validation failed") || !strings.Contains(err.Error(), "input.kernel") {
		t.Fatalf("policy check error = %v", err)
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
	if !strings.Contains(out.String(), `"name": "continuum.airlock.decoy.filesystem"`) || !strings.Contains(out.String(), `"real_enforcement": false`) {
		t.Fatalf("decoy capability missing from json output = %q", out.String())
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

func TestPolicyRollbackCommand(t *testing.T) {
	store := filepath.Join(t.TempDir(), "policies.json")
	var out, errOut bytes.Buffer
	if err := run([]string{"policy", "publish", "--store", store, "../../examples/agent-workdir/policies/main.arb"}, &out, &errOut); err != nil {
		t.Fatalf("policy publish agent: %v", err)
	}
	out.Reset()
	if err := run([]string{"policy", "publish", "--store", store, "../../examples/airlock/policies/main.arb"}, &out, &errOut); err != nil {
		t.Fatalf("policy publish airlock: %v", err)
	}
	out.Reset()
	if err := run([]string{"policy", "activate", "--store", store, "agent-workdir"}, &out, &errOut); err != nil {
		t.Fatalf("policy activate agent: %v", err)
	}
	out.Reset()
	if err := run([]string{"policy", "activate", "--store", store, "airlock"}, &out, &errOut); err != nil {
		t.Fatalf("policy activate airlock: %v", err)
	}
	out.Reset()
	if err := run([]string{"policy", "rollback", "--store", store}, &out, &errOut); err != nil {
		t.Fatalf("policy rollback: %v", err)
	}
	if !strings.Contains(out.String(), "rolled back policy name=agent-workdir") || !strings.Contains(out.String(), "previous=airlock") {
		t.Fatalf("rollback output = %q", out.String())
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
	if !strings.Contains(out.String(), "active=true") || !strings.Contains(out.String(), "kind=agent-workdir") || !strings.Contains(out.String(), "source_sha256=") {
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
	idStore := filepath.Join(dir, "state", "ids.json")
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
id_store = "state/ids.json"

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
	if _, err := os.Stat(idStore); err != nil {
		t.Fatalf("id store not created at config path: %v", err)
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
	out.Reset()
	err = run([]string{
		"replay",
		"--baseline-policy", "../../examples/airlock/policies/main.arb",
		"--policy", "../../examples/agent-workdir/policies/main.arb",
		"--events", "../../testdata/events/file_secret_access.json",
		"--json",
	}, &out, &errOut)
	if err != nil {
		t.Fatalf("replay diff json: %v", err)
	}
	var report replayDiffReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("decode replay diff json: %v\n%s", err, out.String())
	}
	if report.Events != 1 || report.Passed || len(report.Diffs) != 1 || report.Diffs[0].EventID != "evt_secret" {
		t.Fatalf("replay diff json = %+v", report)
	}
}

func TestReplayCommandJSON(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{
		"replay",
		"--policy", "../../examples/agent-workdir/policies/main.arb",
		"--events", "../../testdata/events/file_secret_access.json",
		"--json",
	}, &out, &errOut); err != nil {
		t.Fatalf("replay json: %v\nstderr=%s", err, errOut.String())
	}
	var report replayReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("decode replay json: %v\n%s", err, out.String())
	}
	if report.Events != 1 || len(report.Results) != 1 || report.Results[0].Decision.Selected == nil || report.Results[0].Decision.Selected.Decision() != "deny" {
		t.Fatalf("replay json = %+v", report)
	}
}

func TestExplainCommandJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	evt := audit.Event{
		ID:       "evt_explain",
		Decision: "deny",
		Reason:   "agent cannot access host credential material",
		Outcome: arbiterx.NewOutcome(arbiterx.OutcomeDeny, "DenyHostSecrets", map[string]any{
			"reason": "agent cannot access host credential material",
		}),
		Arbitraces: []arbiterx.Step{{Rule: "DenyHostSecrets", Result: "matched"}},
	}
	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if err := run([]string{"explain", "--path", path, "--json", "evt_explain"}, &out, &errOut); err != nil {
		t.Fatalf("explain json: %v\nstderr=%s", err, errOut.String())
	}
	var exp struct {
		EventID  string          `json:"event_id"`
		Decision string          `json:"decision"`
		Reason   string          `json:"reason"`
		Trace    []arbiterx.Step `json:"trace"`
	}
	if err := json.Unmarshal(out.Bytes(), &exp); err != nil {
		t.Fatalf("decode explain json: %v\n%s", err, out.String())
	}
	if exp.EventID != "evt_explain" || exp.Decision != "deny" || len(exp.Trace) != 1 {
		t.Fatalf("explain json = %+v", exp)
	}
}

func TestReplayGateFailsOnDecisionDiff(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{
		"replay",
		"--baseline-policy", "../../examples/airlock/policies/main.arb",
		"--policy", "../../examples/agent-workdir/policies/main.arb",
		"--events", "../../testdata/events/file_secret_access.json",
		"--fail-on-diff",
	}, &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "replay gate failed: 1 decision diff(s)") {
		t.Fatalf("replay gate error = %v", err)
	}
	if !strings.Contains(out.String(), "evt_secret") || !strings.Contains(out.String(), "audit") || !strings.Contains(out.String(), "deny") {
		t.Fatalf("replay gate diff output = %q", out.String())
	}
}

func TestReplayGatePassesWithoutDecisionDiff(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{
		"replay",
		"--baseline-policy", "../../examples/agent-workdir/policies/main.arb",
		"--policy", "../../examples/agent-workdir/policies/main.arb",
		"--events", "../../testdata/events/file_secret_access.json",
		"--fail-on-diff",
	}, &out, &errOut)
	if err != nil {
		t.Fatalf("replay gate: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "replay gate passed diffs=0 events=1") {
		t.Fatalf("replay gate pass output = %q", out.String())
	}
}

func TestReplayAirlockReviewFixtures(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{
		"replay",
		"--policy", "../../examples/airlock/policies/main.arb",
		"--events", "../../testdata/events/airlock_false_positive_review.json",
	}, &out, &errOut); err != nil {
		t.Fatalf("replay false positive fixtures: %v\nstderr=%s", err, errOut.String())
	}
	if strings.Contains(out.String(), "enter_airlock") {
		t.Fatalf("false-positive replay entered airlock: %q", out.String())
	}
	for _, want := range []string{"evt_airlock_fp_package_install", "evt_airlock_fp_bulk_formatter", "audit"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("false-positive replay output missing %q: %q", want, out.String())
		}
	}
	out.Reset()
	if err := run([]string{
		"replay",
		"--policy", "../../examples/airlock/policies/main.arb",
		"--events", "../../testdata/events/airlock_true_positive_review.json",
	}, &out, &errOut); err != nil {
		t.Fatalf("replay true positive fixtures: %v\nstderr=%s", err, errOut.String())
	}
	for _, want := range []string{"evt_airlock_tp_worm_fanout", "evt_airlock_tp_ransomware_rewrite", "enter_airlock"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("true-positive replay output missing %q: %q", want, out.String())
		}
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

func TestRunCommandRedactsEnvironmentAssignments(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	sessionPath := filepath.Join(dir, "sessions.json")
	idStorePath := filepath.Join(dir, "ids.json")
	secret := "super-secret-value"
	var out, errOut bytes.Buffer
	err := run([]string{
		"run",
		"--agent", "claude",
		"--repo", dir,
		"--policy", "../../examples/agent-workdir/policies/main.arb",
		"--audit", auditPath,
		"--sessions", sessionPath,
		"--id-store", idStorePath,
		"--",
		"env", "AWS_SECRET_ACCESS_KEY=" + secret, "/bin/true",
	}, &out, &errOut)
	if err != nil {
		t.Fatalf("run command: %v\nstderr=%s", err, errOut.String())
	}
	auditBytes, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	sessionBytes, err := os.ReadFile(sessionPath)
	if err != nil {
		t.Fatalf("read sessions: %v", err)
	}
	for name, data := range map[string][]byte{"audit": auditBytes, "sessions": sessionBytes} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("%s output leaked secret: %s", name, string(data))
		}
		if !bytes.Contains(data, []byte("AWS_SECRET_ACCESS_KEY=[REDACTED]")) {
			t.Fatalf("%s output missing redacted assignment: %s", name, string(data))
		}
	}
	events, err := audit.ReadJSONL(auditPath)
	if err != nil {
		t.Fatalf("ReadJSONL: %v", err)
	}
	if len(events) != 1 || events[0].InputEvent.Fields["argv_text"] != "env AWS_SECRET_ACCESS_KEY=[REDACTED] /bin/true" {
		t.Fatalf("audit events = %+v", events)
	}
	sessions, err := cruntime.LoadSessionStore(sessionPath)
	if err != nil {
		t.Fatalf("LoadSessionStore: %v", err)
	}
	if len(sessions.Sessions) != 1 || strings.Contains(strings.Join(sessions.Sessions[0].Command, " "), secret) {
		t.Fatalf("sessions = %+v", sessions.Sessions)
	}
	if sessions.Sessions[0].Subject.Task != "env AWS_SECRET_ACCESS_KEY=[REDACTED] /bin/true" {
		t.Fatalf("subject task = %q", sessions.Sessions[0].Subject.Task)
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
	out.Reset()
	if err := run([]string{"grant", "list", "--store", store, "--json"}, &out, &errOut); err != nil {
		t.Fatalf("grant list json: %v", err)
	}
	var grants []struct {
		ID         string         `json:"id"`
		Session    string         `json:"session"`
		Capability string         `json:"capability"`
		State      string         `json:"state"`
		Scope      map[string]any `json:"scope"`
	}
	if err := json.Unmarshal(out.Bytes(), &grants); err != nil {
		t.Fatalf("decode grant list json: %v\n%s", err, out.String())
	}
	if len(grants) != 1 || grants[0].Session != "agent-session-42" || grants[0].Capability != "network.connect" || grants[0].State != "active" {
		t.Fatalf("grant list json = %+v", grants)
	}
}

func TestGrantRenewCommandExtendsGrant(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "grants.json")
	var out, errOut bytes.Buffer
	if err := run([]string{
		"grant",
		"--store", storePath,
		"--session", "agent-session-42",
		"--capability", "network.connect",
		"--host", "github.com",
		"--ttl", "1m",
		"--reason", "fetch dependency",
	}, &out, &errOut); err != nil {
		t.Fatalf("grant: %v", err)
	}
	grantID := ""
	for _, field := range strings.Fields(out.String()) {
		if strings.HasPrefix(field, "id=") {
			grantID = strings.TrimPrefix(field, "id=")
			break
		}
	}
	if grantID == "" {
		t.Fatalf("grant output missing id: %q", out.String())
	}
	out.Reset()
	if err := run([]string{"grant", "renew", "--store", storePath, "--ttl", "10m", "--reason", "dependency update still running", grantID}, &out, &errOut); err != nil {
		t.Fatalf("grant renew: %v", err)
	}
	if !strings.Contains(out.String(), "renewed grant id="+grantID) || !strings.Contains(out.String(), "renewals=1") {
		t.Fatalf("renew output = %q", out.String())
	}
	store, err := capability.LoadGrantStore(storePath)
	if err != nil {
		t.Fatalf("LoadGrantStore: %v", err)
	}
	if len(store.Grants) != 1 || len(store.Grants[0].Renewals) != 1 || store.Grants[0].Renewals[0].Reason == "" {
		t.Fatalf("stored grant = %+v", store.Grants)
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
	out.Reset()
	if err := run([]string{"airlock", "status", "--store", store, "--json"}, &out, &errOut); err != nil {
		t.Fatalf("airlock status json: %v", err)
	}
	var sessions []airlock.Session
	if err := json.Unmarshal(out.Bytes(), &sessions); err != nil {
		t.Fatalf("decode airlock status json: %v\n%s", err, out.String())
	}
	if len(sessions) != 1 || sessions[0].State != airlock.StateAirlocked {
		t.Fatalf("airlock status json = %+v", sessions)
	}
}

func TestAirlockReleaseAndRemediateWriteAuditEvents(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "airlock.json")
	auditPath := filepath.Join(dir, "audit.jsonl")
	idStore := filepath.Join(dir, "ids.json")
	var out, errOut bytes.Buffer
	if err := run([]string{"airlock", "enter", "--store", store, "--id-store", idStore, "--pid", "1234", "--reason", "test"}, &out, &errOut); err != nil {
		t.Fatalf("airlock enter release target: %v", err)
	}
	releaseSession := outputField(out.String(), "session")
	out.Reset()
	if err := run([]string{"airlock", "release", "--store", store, "--audit", auditPath, "--id-store", idStore, "--reason", "operator verified", releaseSession}, &out, &errOut); err != nil {
		t.Fatalf("airlock release: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "RELEASE_AIRLOCK") || !strings.Contains(out.String(), "audit=evt_airlock_1") {
		t.Fatalf("release output = %q", out.String())
	}

	out.Reset()
	if err := run([]string{"airlock", "enter", "--store", store, "--id-store", idStore, "--pid", "5678", "--reason", "test"}, &out, &errOut); err != nil {
		t.Fatalf("airlock enter remediation target: %v", err)
	}
	remediateSession := outputField(out.String(), "session")
	out.Reset()
	if err := run([]string{"airlock", "remediate", "--store", store, "--audit", auditPath, "--id-store", idStore, "--reason", "patched and isolated", remediateSession}, &out, &errOut); err != nil {
		t.Fatalf("airlock remediate: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "REMEDIATE_AIRLOCK") || !strings.Contains(out.String(), "audit=evt_airlock_2") {
		t.Fatalf("remediate output = %q", out.String())
	}

	events, err := audit.ReadJSONL(auditPath)
	if err != nil {
		t.Fatalf("ReadJSONL: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("audit events = %+v", events)
	}
	assertAirlockTransitionAudit(t, events[0], "AirlockRelease", "release_airlock", "airlock.release", "continuum.airlock.release", "airlocked", "released", "operator verified")
	assertAirlockTransitionAudit(t, events[1], "AirlockRemediation", "remediate_airlock", "airlock.remediate", "continuum.airlock.remediate", "airlocked", "remediated", "patched and isolated")
	if events[0].ChainHash == "" || events[1].ChainHash == "" || events[1].ChainPrev != events[0].ChainHash {
		t.Fatalf("audit chain not linked: first=%+v second=%+v", events[0], events[1])
	}
}

func TestAirlockNoteCommandPersistsAndListsNotes(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "airlock.json")
	idStore := filepath.Join(dir, "ids.json")
	var out, errOut bytes.Buffer
	if err := run([]string{"airlock", "enter", "--store", store, "--id-store", idStore, "--pid", "1234", "--reason", "test"}, &out, &errOut); err != nil {
		t.Fatalf("airlock enter: %v", err)
	}
	session := outputField(out.String(), "session")
	out.Reset()
	if err := run([]string{"airlock", "note", "--store", store, "--operator", "oscar", "--text", "reviewed containment state", session}, &out, &errOut); err != nil {
		t.Fatalf("airlock note: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "NOTE_AIRLOCK") || !strings.Contains(out.String(), "notes=1") || !strings.Contains(out.String(), `operator="oscar"`) {
		t.Fatalf("note output = %q", out.String())
	}
	out.Reset()
	if err := run([]string{"airlock", "notes", "--store", store, session}, &out, &errOut); err != nil {
		t.Fatalf("airlock notes: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "oscar") || !strings.Contains(out.String(), "reviewed containment state") {
		t.Fatalf("notes output = %q", out.String())
	}
	out.Reset()
	if err := run([]string{"airlock", "notes", "--store", store, "--json", session}, &out, &errOut); err != nil {
		t.Fatalf("airlock notes json: %v\nstderr=%s", err, errOut.String())
	}
	var notes struct {
		Session string         `json:"session"`
		Notes   []airlock.Note `json:"notes"`
	}
	if err := json.Unmarshal(out.Bytes(), &notes); err != nil {
		t.Fatalf("decode airlock notes json: %v\n%s", err, out.String())
	}
	if notes.Session != session || len(notes.Notes) != 1 || notes.Notes[0].Operator != "oscar" {
		t.Fatalf("airlock notes json = %+v", notes)
	}
	if err := run([]string{"airlock", "note", "--store", store, "--text", "   ", session}, &out, &errOut); err == nil {
		t.Fatal("airlock note accepted empty text")
	}
}

func TestAirlockExportAndCompactCommands(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "airlock.json")
	exportPath := filepath.Join(dir, "exports", "airlocks.json")
	store := airlock.NewStore()
	now := time.Now().UTC()
	if _, err := store.Enter("old-released", subject.NewProcessTree("old-released", 1), "test", now.Add(-72*time.Hour)); err != nil {
		t.Fatalf("Enter old released: %v", err)
	}
	if _, err := store.Release("old-released", "done", now.Add(-70*time.Hour)); err != nil {
		t.Fatalf("Release old: %v", err)
	}
	if _, _, err := store.AddNote("old-released", "oscar", "sensitive note", now.Add(-69*time.Hour)); err != nil {
		t.Fatalf("AddNote old: %v", err)
	}
	if _, err := store.Enter("new-released", subject.NewProcessTree("new-released", 2), "test", now.Add(-48*time.Hour)); err != nil {
		t.Fatalf("Enter new released: %v", err)
	}
	if _, err := store.Release("new-released", "done", now.Add(-30*time.Minute)); err != nil {
		t.Fatalf("Release new: %v", err)
	}
	if _, err := store.Enter("active", subject.NewProcessTree("active", 3), "still contained", now.Add(-72*time.Hour)); err != nil {
		t.Fatalf("Enter active: %v", err)
	}
	if err := store.Save(storePath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	var out, errOut bytes.Buffer
	if err := run([]string{"airlock", "export", "--store", storePath, "--out", exportPath, "--state", "released", "--redact-notes"}, &out, &errOut); err != nil {
		t.Fatalf("airlock export: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "exported airlock sessions=2") || !strings.Contains(out.String(), "redacted_notes=true") {
		t.Fatalf("export output = %q", out.String())
	}
	exported, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatalf("ReadFile export: %v", err)
	}
	if strings.Contains(string(exported), "sensitive note") || strings.Contains(string(exported), `"notes"`) {
		t.Fatalf("export did not redact notes: %s", exported)
	}
	if strings.Contains(string(exported), "active") {
		t.Fatalf("export state filter included active session: %s", exported)
	}

	out.Reset()
	if err := run([]string{"airlock", "compact", "--store", storePath, "--retain", "1", "--older-than", "1h"}, &out, &errOut); err != nil {
		t.Fatalf("airlock compact: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "before=3") || !strings.Contains(out.String(), "after=2") || !strings.Contains(out.String(), "removed=1") {
		t.Fatalf("compact output = %q", out.String())
	}
	reloaded, err := airlock.LoadStore(storePath)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if _, ok := reloaded.Get("old-released"); ok {
		t.Fatal("old released airlock retained after compact")
	}
	if _, ok := reloaded.Get("new-released"); !ok {
		t.Fatal("new released airlock removed after compact")
	}
	if _, ok := reloaded.Get("active"); !ok {
		t.Fatal("active airlock removed after compact")
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

func outputField(output, name string) string {
	prefix := name + "="
	for _, field := range strings.Fields(output) {
		if strings.HasPrefix(field, prefix) {
			return strings.Trim(strings.TrimPrefix(field, prefix), "\"")
		}
	}
	return ""
}

func assertAirlockTransitionAudit(t *testing.T, evt audit.Event, rule, decision, kind, capability, from, to, reason string) {
	t.Helper()
	if evt.Outcome.Name != arbiterx.OutcomeAudit || evt.Outcome.Rule != rule || evt.Decision != decision {
		t.Fatalf("audit outcome mismatch: %+v", evt)
	}
	if evt.InputEvent.Kind != kind || evt.Reason != reason {
		t.Fatalf("audit event mismatch: %+v", evt)
	}
	if evt.Capability != capability {
		t.Fatalf("capability mismatch: %+v", evt)
	}
	if evt.Clock == nil || evt.Clock.Source != audit.ClockSourceAirlockCLI || evt.Clock.EventTimeSource != audit.EventTimeSourceRecordedClock {
		t.Fatalf("clock metadata mismatch: %+v", evt)
	}
	if got := evt.InputEvent.Fields["from_state"]; got != from {
		t.Fatalf("from_state = %v, want %s", got, from)
	}
	if got := evt.InputEvent.Fields["to_state"]; got != to {
		t.Fatalf("to_state = %v, want %s", got, to)
	}
	if got := evt.InputEvent.Fields["reason"]; got != reason {
		t.Fatalf("reason field = %v, want %s", got, reason)
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
		"--airlock-accumulators", filepath.Join(dir, "airlock-accumulators.json"),
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
	if store.Grants[0].Requester == nil || store.Grants[0].Requester.Session != "agent-42" || store.Grants[0].Requester.AgentName != "claude" {
		t.Fatalf("approval grant missing requester identity: %+v", store.Grants[0].Requester)
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

func TestIngestApprovalDenyWritesAuditEvent(t *testing.T) {
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
	auditPath := filepath.Join(dir, "audit.jsonl")
	var out, errOut bytes.Buffer
	err := run([]string{
		"ingest",
		"--policy", "../../examples/agent-workdir/policies/main.arb",
		"--events", eventPath,
		"--audit", auditPath,
		"--grants", filepath.Join(dir, "grants.json"),
		"--approval", "deny",
		"--no-airlock",
	}, &out, &errOut)
	if err != nil {
		t.Fatalf("ingest approval deny: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "approval=denied") || !strings.Contains(out.String(), "audit=evt_ci_approval_denied") {
		t.Fatalf("approval deny output = %q", out.String())
	}
	events, err := audit.ReadJSONL(auditPath)
	if err != nil {
		t.Fatalf("ReadJSONL: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("audit events = %+v", events)
	}
	if events[0].Decision != "ask" || events[1].Decision != "deny" || events[1].Outcome.Rule != "ApprovalDenied" {
		t.Fatalf("approval audit events = %+v", events)
	}
	if events[1].Outcome.Fields["approval_event_id"] != "evt_ci" {
		t.Fatalf("approval event link = %+v", events[1].Outcome.Fields)
	}
	requester, ok := events[1].Outcome.Fields["requester"].(map[string]any)
	if !ok || requester["session"] != "agent-42" || requester["agent_name"] != "claude" {
		t.Fatalf("requester identity = %#v", events[1].Outcome.Fields["requester"])
	}
	if events[1].ChainPrev == "" || events[1].ChainHash == "" {
		t.Fatalf("approval denial audit was not hash chained: %+v", events[1])
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
	out.Reset()
	if err := run([]string{"grant", "retry-revocations", "--delivery-store", deliveryPath}, &out, &errOut); err != nil {
		t.Fatalf("retry revocations: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "attempted=1") || !strings.Contains(out.String(), "delivered=1") {
		t.Fatalf("retry output = %q", out.String())
	}
	queue, err = cruntime.LoadDeliveryStore(deliveryPath)
	if err != nil {
		t.Fatalf("reload delivery store: %v", err)
	}
	items = queue.ByStatus(cruntime.DeliveryDelivered)
	if len(items) != 1 || len(items[0].Attempts) != 1 {
		t.Fatalf("delivered revocation items = %+v", queue.List())
	}
}

func TestStateCompactionCommands(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	var out, errOut bytes.Buffer

	auditPath := filepath.Join(dir, "audit.jsonl")
	sink, err := audit.NewJSONLSink(auditPath)
	if err != nil {
		t.Fatalf("NewJSONLSink: %v", err)
	}
	for _, id := range []string{"evt_1", "evt_2"} {
		if err := sink.Write(context.Background(), audit.Event{ID: id, Time: now, Outcome: arbiterx.NewOutcome(arbiterx.OutcomeAudit, "Audit", map[string]any{"reason": id})}); err != nil {
			t.Fatalf("audit write %s: %v", id, err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("audit close: %v", err)
	}
	if err := run([]string{"audit", "compact", "--path", auditPath, "--retain", "1"}, &out, &errOut); err != nil {
		t.Fatalf("audit compact: %v\nstderr=%s", err, errOut.String())
	}
	events, err := audit.ReadJSONL(auditPath)
	if err != nil {
		t.Fatalf("ReadJSONL: %v", err)
	}
	if len(events) != 1 || events[0].ID != "evt_2" {
		t.Fatalf("compacted audit events = %+v", events)
	}

	sessionPath := filepath.Join(dir, "sessions.json")
	sessions := &cruntime.SessionStore{Sessions: []cruntime.Session{
		{ID: "old", State: cruntime.SessionExited, StartedAt: now.Add(-3 * time.Hour), EndedAt: now.Add(-3 * time.Hour)},
		{ID: "new", State: cruntime.SessionExited, StartedAt: now.Add(-time.Hour), EndedAt: now.Add(-time.Hour)},
		{
			ID:    "running",
			State: cruntime.SessionRunning,
			ProcessTree: &cruntime.ProcessTree{RootPID: 10, Processes: []cruntime.ProcessRecord{
				{PID: 10, State: cruntime.ProcessRunning, StartedAt: now.Add(-4 * time.Hour)},
				{PID: 11, ParentPID: 10, State: cruntime.ProcessExited, StartedAt: now.Add(-3 * time.Hour), EndedAt: now.Add(-3 * time.Hour)},
				{PID: 12, ParentPID: 10, State: cruntime.ProcessExited, StartedAt: now.Add(-time.Hour), EndedAt: now.Add(-time.Hour)},
			}},
			StartedAt:       now.Add(-4 * time.Hour),
			LastHeartbeatAt: now.Add(-4 * time.Hour),
		},
	}}
	if err := sessions.Save(sessionPath); err != nil {
		t.Fatalf("sessions Save: %v", err)
	}
	out.Reset()
	if err := run([]string{"sessions", "compact", "--store", sessionPath, "--retain", "1", "--max-processes", "2"}, &out, &errOut); err != nil {
		t.Fatalf("sessions compact: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "process_records_removed=1") {
		t.Fatalf("sessions compact output = %q", out.String())
	}
	reloadedSessions, err := cruntime.LoadSessionStore(sessionPath)
	if err != nil {
		t.Fatalf("LoadSessionStore: %v", err)
	}
	if len(reloadedSessions.Sessions) != 2 {
		t.Fatalf("compacted sessions = %+v", reloadedSessions.Sessions)
	}
	runningSession, ok := findSession(reloadedSessions.Sessions, "running")
	if !ok || runningSession.ProcessTree == nil || len(runningSession.ProcessTree.Processes) != 2 {
		t.Fatalf("compacted running session = %+v", runningSession)
	}

	deliveryPath := filepath.Join(dir, "deliveries.json")
	deliveries, err := cruntime.LoadDeliveryStore(deliveryPath)
	if err != nil {
		t.Fatalf("LoadDeliveryStore: %v", err)
	}
	for _, item := range []cruntime.DeliveryItem{
		{ID: "old", AuditID: "evt_old", Capability: "observe.audit", Status: cruntime.DeliveryDelivered, CreatedAt: now.Add(-3 * time.Hour)},
		{ID: "new", AuditID: "evt_new", Capability: "observe.audit", Status: cruntime.DeliveryDelivered, CreatedAt: now.Add(-time.Hour)},
		{ID: "pending", AuditID: "evt_pending", Capability: "observe.audit", Status: cruntime.DeliveryPending, CreatedAt: now.Add(-4 * time.Hour)},
	} {
		if _, err := deliveries.Enqueue(item); err != nil {
			t.Fatalf("Enqueue %s: %v", item.ID, err)
		}
	}
	if err := deliveries.Save(); err != nil {
		t.Fatalf("deliveries Save: %v", err)
	}
	out.Reset()
	if err := run([]string{"delivery", "compact", "--delivery-store", deliveryPath, "--retain", "1"}, &out, &errOut); err != nil {
		t.Fatalf("delivery compact: %v\nstderr=%s", err, errOut.String())
	}
	reloadedDeliveries, err := cruntime.LoadDeliveryStore(deliveryPath)
	if err != nil {
		t.Fatalf("reload deliveries: %v", err)
	}
	if len(reloadedDeliveries.List()) != 2 || len(reloadedDeliveries.ByStatus(cruntime.DeliveryPending)) != 1 {
		t.Fatalf("compacted deliveries = %+v", reloadedDeliveries.List())
	}
}

func TestStateExportBackupImportCommands(t *testing.T) {
	dir := t.TempDir()
	src := commandStatePaths(filepath.Join(dir, "src"))
	dst := commandStatePaths(filepath.Join(dir, "dst"))
	archivePath := filepath.Join(dir, "continuum-state.json")
	backupPath := filepath.Join(dir, "backup", "continuum-state.json")
	policyPath := filepath.Join("..", "..", "examples", "agent-workdir", "policies", "main.arb")
	var out, errOut bytes.Buffer

	if err := run([]string{"policy", "publish", "--store", src.policyStore, policyPath}, &out, &errOut); err != nil {
		t.Fatalf("policy publish: %v\nstderr=%s", err, errOut.String())
	}
	out.Reset()
	if err := run([]string{"policy", "activate", "--store", src.policyStore, "agent-workdir"}, &out, &errOut); err != nil {
		t.Fatalf("policy activate: %v\nstderr=%s", err, errOut.String())
	}
	out.Reset()
	if err := run([]string{"grant", "--store", src.grantStore, "--id-store", src.idStore, "--session", "agent-42", "--capability", "network.connect", "--host", "github.com", "--reason", "fetch dependency"}, &out, &errOut); err != nil {
		t.Fatalf("grant: %v\nstderr=%s", err, errOut.String())
	}
	grantID := fieldValue(out.String(), "id")
	if grantID == "" {
		t.Fatalf("grant output missing id: %q", out.String())
	}
	out.Reset()
	if err := run([]string{"grant", "revoke", "--store", src.grantStore, "--delivery-store", src.deliveryStore, grantID}, &out, &errOut); err != nil {
		t.Fatalf("grant revoke: %v\nstderr=%s", err, errOut.String())
	}
	sessions := &cruntime.SessionStore{Sessions: []cruntime.Session{{
		ID:        "agent-42",
		Subject:   subject.NewAgent("claude", "agent-42", "/repo", "", 4321),
		State:     cruntime.SessionRunning,
		StartedAt: time.Date(2026, 5, 24, 3, 0, 0, 0, time.UTC),
	}}}
	if err := sessions.Save(src.sessionStore); err != nil {
		t.Fatalf("sessions Save: %v", err)
	}
	out.Reset()
	if err := run([]string{"airlock", "enter", "--store", src.airlockStore, "--id-store", src.idStore, "--pid", "4321", "--reason", "worm-like fanout"}, &out, &errOut); err != nil {
		t.Fatalf("airlock enter: %v\nstderr=%s", err, errOut.String())
	}
	accumulators := airlock.NewAccumulatorStore()
	accumulators.ObserveEvents([]event.Event{
		event.NewProcessExec(subject.NewAgent("claude", "agent-42", "/repo", "", 4321), map[string]any{"comm": "sh", "argv_text": "sh -c true"}),
	}, func() time.Time { return time.Date(2026, 5, 24, 3, 0, 0, 0, time.UTC) })
	if err := accumulators.Save(src.airlockAccumulatorStore); err != nil {
		t.Fatalf("airlock accumulator Save: %v", err)
	}
	sink, err := audit.NewJSONLSink(src.audit)
	if err != nil {
		t.Fatalf("NewJSONLSink: %v", err)
	}
	if err := sink.Write(context.Background(), audit.Event{ID: "evt_state_export", Time: time.Date(2026, 5, 24, 3, 0, 0, 0, time.UTC), Decision: "allow", Reason: "fixture"}); err != nil {
		t.Fatalf("audit write: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("audit close: %v", err)
	}

	out.Reset()
	if err := run(append([]string{"state", "export", "--out", archivePath}, src.args()...), &out, &errOut); err != nil {
		t.Fatalf("state export: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "exported state items=8") {
		t.Fatalf("state export output = %q", out.String())
	}
	out.Reset()
	if err := run(append([]string{"state", "backup", "--out", backupPath}, src.args()...), &out, &errOut); err != nil {
		t.Fatalf("state backup: %v\nstderr=%s", err, errOut.String())
	}
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("backup archive missing: %v", err)
	}

	out.Reset()
	if err := run(append([]string{"state", "import", "--in", archivePath, "--dry-run"}, dst.args()...), &out, &errOut); err != nil {
		t.Fatalf("state import dry-run: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "would_import=8") {
		t.Fatalf("state import dry-run output = %q", out.String())
	}
	out.Reset()
	if err := run(append([]string{"state", "import", "--in", archivePath}, dst.args()...), &out, &errOut); err != nil {
		t.Fatalf("state import: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "imported state items=8") {
		t.Fatalf("state import output = %q", out.String())
	}
	reloadedPolicy, err := policy.LoadStore(dst.policyStore)
	if err != nil {
		t.Fatalf("policy LoadStore: %v", err)
	}
	if reloadedPolicy.Active != "agent-workdir" {
		t.Fatalf("imported policy active = %q", reloadedPolicy.Active)
	}
	reloadedGrants, err := capability.LoadGrantStore(dst.grantStore)
	if err != nil {
		t.Fatalf("LoadGrantStore: %v", err)
	}
	if len(reloadedGrants.Grants) != 1 || reloadedGrants.Grants[0].ID != grantID {
		t.Fatalf("imported grants = %+v", reloadedGrants.Grants)
	}
	reloadedEvents, err := audit.ReadJSONL(dst.audit)
	if err != nil {
		t.Fatalf("ReadJSONL imported audit: %v", err)
	}
	if len(reloadedEvents) != 1 || reloadedEvents[0].ID != "evt_state_export" {
		t.Fatalf("imported audit events = %+v", reloadedEvents)
	}
	reloadedAccumulators, err := airlock.LoadAccumulatorStore(dst.airlockAccumulatorStore)
	if err != nil {
		t.Fatalf("LoadAccumulatorStore: %v", err)
	}
	if len(reloadedAccumulators.List()) != 1 {
		t.Fatalf("imported airlock accumulators = %+v", reloadedAccumulators.List())
	}

	out.Reset()
	err = run(append([]string{"state", "import", "--in", archivePath}, dst.args()...), &out, &errOut)
	if err == nil || !strings.Contains(err.Error(), "use --force") {
		t.Fatalf("state import without force error = %v", err)
	}
	out.Reset()
	if err := run(append([]string{"state", "import", "--in", archivePath, "--force"}, dst.args()...), &out, &errOut); err != nil {
		t.Fatalf("state import force: %v\nstderr=%s", err, errOut.String())
	}
	matches, err := filepath.Glob(dst.grantStore + ".preimport.*")
	if err != nil {
		t.Fatalf("Glob backups: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("forced import did not preserve pre-import backup")
	}
}

type commandStatePathSet struct {
	policyStore             string
	grantStore              string
	deliveryStore           string
	sessionStore            string
	airlockStore            string
	airlockAccumulatorStore string
	idStore                 string
	audit                   string
}

func commandStatePaths(dir string) commandStatePathSet {
	return commandStatePathSet{
		policyStore:             filepath.Join(dir, "policies.json"),
		grantStore:              filepath.Join(dir, "grants.json"),
		deliveryStore:           filepath.Join(dir, "deliveries.json"),
		sessionStore:            filepath.Join(dir, "sessions.json"),
		airlockStore:            filepath.Join(dir, "airlock.json"),
		airlockAccumulatorStore: filepath.Join(dir, "airlock-accumulators.json"),
		idStore:                 filepath.Join(dir, "ids.json"),
		audit:                   filepath.Join(dir, "audit.jsonl"),
	}
}

func (p commandStatePathSet) args() []string {
	return []string{
		"--policy-store", p.policyStore,
		"--grant-store", p.grantStore,
		"--delivery-store", p.deliveryStore,
		"--session-store", p.sessionStore,
		"--airlock-store", p.airlockStore,
		"--airlock-accumulators", p.airlockAccumulatorStore,
		"--id-store", p.idStore,
		"--audit", p.audit,
	}
}

func fieldValue(text, name string) string {
	prefix := name + "="
	for _, field := range strings.Fields(text) {
		if strings.HasPrefix(field, prefix) {
			return strings.TrimPrefix(field, prefix)
		}
	}
	return ""
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
