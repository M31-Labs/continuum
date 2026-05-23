package event

import (
	"testing"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/subject"
)

func TestNormalizeFileAccess(t *testing.T) {
	subj := subject.NewAgent("claude", "agent-42", "/repo", "edit", 123)
	facts := Normalize(NewFileAccess(subj, "/repo/main.go", "write"))
	if len(facts) != 2 {
		t.Fatalf("facts len = %d", len(facts))
	}
	if facts[0].Type != arbiterx.FactAgentContext {
		t.Fatalf("first fact = %s", facts[0].Type)
	}
	if facts[1].Type != arbiterx.FactFileAccess {
		t.Fatalf("second fact = %s", facts[1].Type)
	}
	if facts[1].Fields["path"] != "/repo/main.go" {
		t.Fatalf("path field = %v", facts[1].Fields["path"])
	}
}

func TestNormalizeNetworkConnect(t *testing.T) {
	subj := subject.NewAgent("claude", "agent-42", "/repo", "", 123)
	facts := Normalize(NewNetworkConnect(subj, "github.com", "140.82.112.3", 443))
	if got := facts[1].Fields["port"]; got != 443 {
		t.Fatalf("port = %v", got)
	}
}
