package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/subject"
)

func TestJSONLWriteReadFind(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := NewJSONLSink(path)
	if err != nil {
		t.Fatalf("NewJSONLSink: %v", err)
	}
	event := Event{
		ID:       "evt_123",
		Time:     time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC),
		Outcome:  arbiterx.NewOutcome(arbiterx.OutcomeDeny, "DenyHostSecrets", map[string]any{"reason": "no"}),
		Decision: "deny",
		Reason:   "no",
	}
	if err := sink.Write(context.Background(), event); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	events, err := ReadJSONL(path)
	if err != nil {
		t.Fatalf("ReadJSONL: %v", err)
	}
	got, ok := Find(events, "evt_123")
	if !ok || got.Decision != "deny" {
		t.Fatalf("Find = %+v, %v", got, ok)
	}
}

func TestQueryFiltersAuditEvents(t *testing.T) {
	events := []Event{
		{ID: "evt_1", Decision: "allow", InputEvent: event.Event{Kind: "process.exec"}, Subject: subject.Subject{Session: "s1"}},
		{ID: "evt_2", Decision: "deny", InputEvent: event.Event{Kind: "file.open"}, Subject: subject.Subject{Session: "s1"}},
		{ID: "evt_3", Decision: "deny", InputEvent: event.Event{Kind: "network.connect"}, Subject: subject.Subject{Session: "s2"}},
	}
	got := Query(events, Filter{Decision: "deny", Subject: "s1"})
	if len(got) != 1 || got[0].ID != "evt_2" {
		t.Fatalf("filtered = %+v", got)
	}
	got = Query(events, Filter{Decision: "deny", Limit: 1})
	if len(got) != 1 || got[0].ID != "evt_3" {
		t.Fatalf("limited = %+v", got)
	}
}
