package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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
	if got.ChainHash == "" {
		t.Fatalf("audit event missing chain hash: %+v", got)
	}
	report, err := VerifyJSONL(path)
	if err != nil {
		t.Fatalf("VerifyJSONL: %v", err)
	}
	if !report.OK || report.Events != 1 || report.LastHash != got.ChainHash {
		t.Fatalf("verify report = %+v", report)
	}
}

func TestJSONLSinkAppendsAndUsesPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for _, id := range []string{"evt_1", "evt_2"} {
		sink, err := NewJSONLSink(path)
		if err != nil {
			t.Fatalf("NewJSONLSink: %v", err)
		}
		if err := sink.Write(context.Background(), Event{ID: id, Time: time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)}); err != nil {
			t.Fatalf("Write %s: %v", id, err)
		}
		if err := sink.Close(); err != nil {
			t.Fatalf("Close %s: %v", id, err)
		}
	}
	events, err := ReadJSONL(path)
	if err != nil {
		t.Fatalf("ReadJSONL: %v", err)
	}
	if len(events) != 2 || events[0].ID != "evt_1" || events[1].ID != "evt_2" {
		t.Fatalf("events = %+v", events)
	}
	if events[0].ChainPrev != "" || events[0].ChainHash == "" || events[1].ChainPrev != events[0].ChainHash || events[1].ChainHash == "" {
		t.Fatalf("chain fields = %+v", events)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("mode = %v", got)
	}
}

func TestVerifyJSONLDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := NewJSONLSink(path)
	if err != nil {
		t.Fatalf("NewJSONLSink: %v", err)
	}
	for _, id := range []string{"evt_1", "evt_2"} {
		if err := sink.Write(context.Background(), Event{ID: id, Time: time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)}); err != nil {
			t.Fatalf("Write %s: %v", id, err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	tampered := strings.Replace(string(data), `"id":"evt_2"`, `"id":"evt_bad"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	report, err := VerifyJSONL(path)
	if err != nil {
		t.Fatalf("VerifyJSONL: %v", err)
	}
	if report.OK || report.Line != 2 || report.EventID != "evt_bad" {
		t.Fatalf("verify report = %+v", report)
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
