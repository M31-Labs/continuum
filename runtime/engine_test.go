package runtime

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/subject"
)

func TestEngineDecideEventWritesAudit(t *testing.T) {
	bundle, err := arbiterx.CompileFile(filepath.Join("..", "examples", "agent-workdir", "policies", "main.arb"))
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	sink := &memorySink{}
	engine := NewEngine(bundle, sink)
	engine.Now = func() time.Time { return time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC) }
	engine.NewID = func() string { return "evt_test" }

	subj := subject.NewAgent("claude", "agent-42", "/repo", "", 123)
	record, decision, err := engine.DecideEvent(context.Background(), event.NewFileAccess(subj, "/home/draco/.ssh/id_ed25519", "read"))
	if err != nil {
		t.Fatalf("DecideEvent: %v", err)
	}
	if decision.Selected == nil || decision.Selected.Name != arbiterx.OutcomeDeny {
		t.Fatalf("selected = %+v", decision.Selected)
	}
	if record.ID != "evt_test" || record.Decision != "deny" {
		t.Fatalf("record = %+v", record)
	}
	if record.Capability != "kernel.file.open.deny" || record.Enforcement != "observe" {
		t.Fatalf("route = capability %s enforcement %s", record.Capability, record.Enforcement)
	}
	if len(sink.events) != 1 {
		t.Fatalf("audit writes = %d", len(sink.events))
	}
}

func TestEngineAddsActiveGrantFacts(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	bundle, err := arbiterx.CompileFile(filepath.Join("..", "examples", "agent-workdir", "policies", "main.arb"))
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	engine := NewEngine(bundle, audit.NopSink{})
	engine.Now = func() time.Time { return now }
	engine.Grants = []capability.Grant{{
		ID:         "grant_1",
		Session:    "agent-42",
		Capability: "network.connect",
		Scope:      map[string]any{"host": "github.com", "port": 443},
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Minute),
	}}
	subj := subject.NewAgent("claude", "agent-42", "/repo", "", 123)
	record, decision, err := engine.DecideEvent(context.Background(), event.NewNetworkConnect(subj, "github.com", "140.82.112.3", 443))
	if err != nil {
		t.Fatalf("DecideEvent: %v", err)
	}
	if decision.Selected == nil || decision.Selected.Rule != "AllowTemporaryGrant" {
		t.Fatalf("selected = %+v", decision.Selected)
	}
	if record.Decision != "allow" {
		t.Fatalf("record decision = %s", record.Decision)
	}
}

func TestDaemonStartRegistersBuiltInCapabilities(t *testing.T) {
	daemon := NewDaemon(nil)
	if err := daemon.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	health := daemon.Health()
	if health.Capabilities < 2 || health.SinkCount < 1 || health.WorkerCount < 1 {
		t.Fatalf("health = %+v", health)
	}
	if _, ok := daemon.Registry.Get("observe.audit"); !ok {
		t.Fatal("observe.audit not registered")
	}
}

type memorySink struct {
	events []audit.Event
}

func (s *memorySink) Write(_ context.Context, evt audit.Event) error {
	s.events = append(s.events, evt)
	return nil
}
