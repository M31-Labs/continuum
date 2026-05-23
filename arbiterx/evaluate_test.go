package arbiterx_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"m31labs.dev/continuum/airlock"
	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/subject"
)

func TestAgentGuardHostSecretDenied(t *testing.T) {
	evt := readEvent(t, filepath.Join("..", "testdata", "events", "file_secret_access.json"))
	decision := evaluate(t, event.Normalize(evt))
	assertSelected(t, decision, arbiterx.OutcomeDeny, "DenyHostSecrets")
	if decision.Selected.Reason() != "agent cannot access host credential material" {
		t.Fatalf("reason = %q", decision.Selected.Reason())
	}
}

func TestAgentGuardRepoFileAllowed(t *testing.T) {
	subj := subject.NewAgent("claude", "agent-42", "/home/draco/src/app", "", 123)
	evt := event.NewFileAccess(subj, "/home/draco/src/app/main.go", "write")
	decision := evaluate(t, event.Normalize(evt))
	assertSelected(t, decision, arbiterx.OutcomeAllow, "AllowInsideRepo")
}

func TestAgentGuardCIWriteAsks(t *testing.T) {
	subj := subject.NewAgent("claude", "agent-42", "/home/draco/src/app", "", 123)
	evt := event.NewFileAccess(subj, "/home/draco/src/app/.github/workflows/test.yml", "write")
	decision := evaluate(t, event.Normalize(evt))
	assertSelected(t, decision, arbiterx.OutcomeAskHuman, "AskOnCIWrites")
}

func TestAgentGuardMetadataDenied(t *testing.T) {
	evt := readEvent(t, filepath.Join("..", "testdata", "events", "network_metadata_access.json"))
	decision := evaluate(t, event.Normalize(evt))
	assertSelected(t, decision, arbiterx.OutcomeDeny, "DenyCloudMetadata")
}

func TestAgentGuardTemporaryGrantAllowsNetwork(t *testing.T) {
	subj := subject.NewAgent("claude", "agent-42", "/repo", "", 123)
	facts := event.Normalize(event.NewNetworkConnect(subj, "github.com", "140.82.112.3", 443))
	facts = append(facts, arbiterx.NewFact(arbiterx.FactCapabilityGrant, subj, map[string]any{
		"id":         "grant_1",
		"session":    "agent-42",
		"capability": "network.connect",
		"host":       "github.com",
		"port":       443,
	}))
	decision := evaluate(t, facts)
	assertSelected(t, decision, arbiterx.OutcomeAllow, "AllowTemporaryGrant")
}

func TestAgentGuardTemporaryGrantAllowsCIWrite(t *testing.T) {
	subj := subject.NewAgent("claude", "agent-42", "/repo", "", 123)
	facts := event.Normalize(event.NewFileAccess(subj, "/repo/.github/workflows/test.yml", "write"))
	facts = append(facts, arbiterx.NewFact(arbiterx.FactCapabilityGrant, subj, map[string]any{
		"id":         "grant_file",
		"session":    "agent-42",
		"capability": "file.write",
		"path":       "/repo/.github/workflows/test.yml",
		"op":         "write",
	}))
	decision := evaluate(t, facts)
	assertSelected(t, decision, arbiterx.OutcomeAllow, "AllowTemporaryGrant")
}

func TestAgentGuardTemporaryGrantAllowsProcessExec(t *testing.T) {
	subj := subject.NewAgent("claude", "agent-42", "/repo", "", 123)
	facts := event.Normalize(event.NewProcessExec(subj, map[string]any{
		"comm":      "/usr/bin/go",
		"argv_text": "go env GOPATH",
		"cwd":       "/tmp",
	}))
	facts = append(facts, arbiterx.NewFact(arbiterx.FactCapabilityGrant, subj, map[string]any{
		"id":         "grant_process",
		"session":    "agent-42",
		"capability": "process.exec",
		"comm":       "go",
	}))
	decision := evaluate(t, facts)
	assertSelected(t, decision, arbiterx.OutcomeAllow, "AllowTemporaryGrant")
}

func TestAgentGuardMetadataDenyBeatsGrant(t *testing.T) {
	subj := subject.NewAgent("claude", "agent-42", "/repo", "", 123)
	facts := event.Normalize(event.NewNetworkConnect(subj, "169.254.169.254", "169.254.169.254", 80))
	facts = append(facts, arbiterx.NewFact(arbiterx.FactCapabilityGrant, subj, map[string]any{
		"id":         "grant_1",
		"session":    "agent-42",
		"capability": "network.connect",
		"host":       "169.254.169.254",
		"port":       80,
	}))
	decision := evaluate(t, facts)
	assertSelected(t, decision, arbiterx.OutcomeDeny, "DenyCloudMetadata")
}

func TestAirlockWormlikeFanout(t *testing.T) {
	behavior, err := airlock.LoadBehaviorFixture(filepath.Join("..", "testdata", "events", "worm_fanout.json"))
	if err != nil {
		t.Fatal(err)
	}
	decision := evaluate(t, []arbiterx.Fact{behavior.Fact()})
	assertSelected(t, decision, arbiterx.OutcomeEnterAirlock, "DetectWormLikeFanout")
}

func TestAirlockRansomwareRewrite(t *testing.T) {
	behavior, err := airlock.LoadBehaviorFixture(filepath.Join("..", "testdata", "events", "ransomware_rewrite.json"))
	if err != nil {
		t.Fatal(err)
	}
	decision := evaluate(t, []arbiterx.Fact{behavior.Fact()})
	assertSelected(t, decision, arbiterx.OutcomeEnterAirlock, "DetectRansomwareLikeRewrite")
}

func evaluate(t *testing.T, facts []arbiterx.Fact) arbiterx.Decision {
	t.Helper()
	policyPath := filepath.Join("..", "examples", "agent-workdir", "policies", "main.arb")
	for _, fact := range facts {
		if fact.Type == arbiterx.FactBehavior {
			policyPath = filepath.Join("..", "examples", "airlock", "policies", "main.arb")
			break
		}
	}
	bundle, err := arbiterx.CompileFile(policyPath)
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	decision, err := arbiterx.Evaluate(context.Background(), bundle, facts)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return decision
}

func assertSelected(t *testing.T, decision arbiterx.Decision, name, rule string) {
	t.Helper()
	if decision.Selected == nil {
		t.Fatal("selected outcome is nil")
	}
	if decision.Selected.Name != name || decision.Selected.Rule != rule {
		t.Fatalf("selected = %+v, want %s/%s", decision.Selected, name, rule)
	}
}

func readEvent(t *testing.T, path string) event.Event {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read event: %v", err)
	}
	var evt event.Event
	if err := json.Unmarshal(data, &evt); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	return evt
}
