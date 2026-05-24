package runtime

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/enforcement"
	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/internal/testutil"
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
	engine.NewID = func() (string, error) { return "evt_test", nil }

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
	if record.Clock == nil || record.Clock.Source != audit.ClockSourceRuntimeEngine || record.Clock.EventTimeSource != audit.EventTimeSourceRecordedClock || !record.Clock.RecordedAt.Equal(record.Time) {
		t.Fatalf("clock = %+v time=%s", record.Clock, record.Time)
	}
	if !record.InputEvent.Time.Equal(record.Time) {
		t.Fatalf("input event time = %s, want audit time %s", record.InputEvent.Time, record.Time)
	}
	if len(sink.events) != 1 {
		t.Fatalf("audit writes = %d", len(sink.events))
	}
	if len(sink.events[0].Delivery) != 1 || sink.events[0].Delivery[0].Status != "delivered" {
		t.Fatalf("delivery = %+v", sink.events[0].Delivery)
	}
}

func TestEngineRecordsInputEventClockSource(t *testing.T) {
	bundle, err := arbiterx.CompileFile(filepath.Join("..", "examples", "agent-workdir", "policies", "main.arb"))
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	eventTime := now.Add(-time.Minute)
	engine := NewEngine(bundle, audit.NopSink{})
	engine.Now = func() time.Time { return now }
	subj := subject.NewAgent("claude", "agent-42", "/repo", "", 123)
	evt := event.NewFileAccess(subj, "/repo/main.go", "write")
	evt.Time = eventTime
	record, _, err := engine.DecideEvent(context.Background(), evt)
	if err != nil {
		t.Fatalf("DecideEvent: %v", err)
	}
	if record.Clock == nil || record.Clock.EventTimeSource != audit.EventTimeSourceInputEvent {
		t.Fatalf("clock = %+v", record.Clock)
	}
	if !record.InputEvent.Time.Equal(eventTime) || !record.Time.Equal(now) {
		t.Fatalf("times input=%s audit=%s", record.InputEvent.Time, record.Time)
	}
}

func TestEnginePersistsFailedDeliveryAttempt(t *testing.T) {
	bundle, err := arbiterx.CompileFile(filepath.Join("..", "examples", "agent-workdir", "policies", "main.arb"))
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	sink := &memorySink{}
	engine := NewEngine(bundle, sink)
	engine.File = failingFileBackend{}
	subj := subject.NewAgent("claude", "agent-42", "/repo", "", 123)
	_, _, err = engine.DecideEvent(context.Background(), event.NewFileAccess(subj, "/home/draco/.ssh/id_ed25519", "read"))
	if err == nil {
		t.Fatal("expected delivery error")
	}
	if len(sink.events) != 1 {
		t.Fatalf("audit writes = %d", len(sink.events))
	}
	delivery := sink.events[0].Delivery
	if len(delivery) != 1 || delivery[0].Status != "failed" || delivery[0].Error == "" {
		t.Fatalf("delivery = %+v", delivery)
	}
}

func TestOutcomeAuditRoutingGolden(t *testing.T) {
	bundle, err := arbiterx.CompileFile(filepath.Join("..", "examples", "agent-workdir", "policies", "main.arb"))
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	engine := NewEngine(bundle, audit.NopSink{})
	engine.Now = func() time.Time { return time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC) }
	evt := testutil.ReadJSON[event.Event](t, filepath.Join("..", "testdata", "events", "file_secret_access.json"))
	record, _, err := engine.DecideEvent(context.Background(), evt)
	if err != nil {
		t.Fatalf("DecideEvent: %v", err)
	}
	projection := struct {
		Decision       string `json:"decision"`
		Outcome        string `json:"outcome"`
		Rule           string `json:"rule"`
		Reason         string `json:"reason"`
		Capability     string `json:"capability"`
		Enforcement    string `json:"enforcement"`
		DeliveryStatus string `json:"delivery_status"`
	}{
		Decision:    record.Decision,
		Outcome:     record.Outcome.Name,
		Rule:        record.Outcome.Rule,
		Reason:      record.Reason,
		Capability:  record.Capability,
		Enforcement: record.Enforcement,
	}
	if len(record.Delivery) > 0 {
		projection.DeliveryStatus = record.Delivery[0].Status
	}
	testutil.EqualGoldenJSON(t, filepath.Join("..", "testdata", "golden", "file_secret_access_audit_route.json"), projection)
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
	decoy, ok := daemon.Registry.Get("continuum.airlock.decoy.filesystem")
	if !ok {
		t.Fatal("airlock decoy capability not registered")
	}
	if decoy.Danger != capability.DangerObserve || decoy.Backend != "observe" {
		t.Fatalf("decoy capability claims enforcement: %+v", decoy)
	}
}

type memorySink struct {
	events []audit.Event
}

func (s *memorySink) Write(_ context.Context, evt audit.Event) error {
	s.events = append(s.events, evt)
	return nil
}

type failingFileBackend struct {
	enforcement.ObserveBackend
}

func (failingFileBackend) DenyPath(context.Context, enforcement.FileDeny) error {
	return fmt.Errorf("deny path failed")
}
