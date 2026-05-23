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

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/audit"
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
	if err := run([]string{"grant", "--store", grantStore, "--session", "s1", "--capability", "network.connect", "--host", "github.com"}, &out, &errOut); err != nil {
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
	if err := run([]string{"grant", "--config", configPath, "--session", "agent-session-42", "--capability", "network.connect", "--host", "github.com"}, &out, &errOut); err != nil {
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

func TestIngestCommandAcceptsHorizonEnvelope(t *testing.T) {
	dir := t.TempDir()
	eventPath := filepath.Join(dir, "horizon.json")
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
	}, &out, &errOut)
	if err != nil {
		t.Fatalf("ingest horizon: %v\nstderr=%s", err, errOut.String())
	}
	if !strings.Contains(out.String(), "ALLOW process.exec go") {
		t.Fatalf("ingest output = %q", out.String())
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
}
