package audit

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestCompactJSONLRechainsKeptEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := NewJSONLSink(path)
	if err != nil {
		t.Fatalf("NewJSONLSink: %v", err)
	}
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	for i, id := range []string{"evt_1", "evt_2", "evt_3"} {
		if err := sink.Write(context.Background(), Event{
			ID:       id,
			Time:     now.Add(time.Duration(i) * time.Minute),
			Outcome:  arbiterx.NewOutcome(arbiterx.OutcomeAudit, "Audit", map[string]any{"reason": id}),
			Decision: "audit",
			Reason:   id,
		}); err != nil {
			t.Fatalf("Write %s: %v", id, err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	report, err := CompactJSONL(path, CompactOptions{Retain: 2, Now: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("CompactJSONL: %v", err)
	}
	if report.Before != 3 || report.After != 2 || report.Removed != 1 {
		t.Fatalf("report = %+v", report)
	}
	events, err := ReadJSONL(path)
	if err != nil {
		t.Fatalf("ReadJSONL: %v", err)
	}
	if len(events) != 2 || events[0].ID != "evt_2" || events[1].ID != "evt_3" {
		t.Fatalf("events = %+v", events)
	}
	verify, err := VerifyJSONL(path)
	if err != nil {
		t.Fatalf("VerifyJSONL: %v", err)
	}
	if !verify.OK || verify.Events != 2 {
		t.Fatalf("verify = %+v", verify)
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

func TestJSONLEventSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := NewJSONLSink(path)
	if err != nil {
		t.Fatalf("NewJSONLSink: %v", err)
	}
	err = sink.Write(context.Background(), Event{
		ID:     "evt_large",
		Time:   time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC),
		Reason: strings.Repeat("x", MaxEventBytes),
	})
	if err == nil {
		t.Fatal("Write succeeded for oversized audit event")
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := os.WriteFile(path, []byte(strings.Repeat("x", MaxEventBytes+2)), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := ReadJSONL(path); err == nil {
		t.Fatal("ReadJSONL succeeded for oversized audit line")
	}
	if _, err := VerifyJSONL(path); err == nil {
		t.Fatal("VerifyJSONL succeeded for oversized audit line")
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
	got = Query(events, Filter{Offset: 1, Limit: 1})
	if len(got) != 1 || got[0].ID != "evt_2" {
		t.Fatalf("paged = %+v", got)
	}
	got = Query(events, Filter{Offset: 3})
	if len(got) != 0 {
		t.Fatalf("offset past end = %+v", got)
	}
}

func TestExportRedactsAuditEvents(t *testing.T) {
	evt := Event{
		ID:      "evt_1",
		Subject: subject.Subject{Kind: "agent", Session: "agent-42", AgentName: "claude", RepoRoot: "/repo"},
		InputEvent: event.Event{
			Kind:    "file.access",
			Subject: subject.Subject{Kind: "agent", Session: "agent-42", AgentName: "claude", RepoRoot: "/repo"},
			Fields: map[string]any{
				"path": "/home/draco/.ssh/id_ed25519",
				"op":   "read",
			},
			Raw: map[string]any{
				"path": "/home/draco/.ssh/id_ed25519",
			},
		},
		Outcome:   arbiterx.NewOutcome(arbiterx.OutcomeDeny, "DenyHostSecrets", map[string]any{"host": "github.com", "reason": "blocked"}),
		Decision:  "deny",
		ChainPrev: "prev",
		ChainHash: "hash",
	}

	var buf bytes.Buffer
	if err := ExportJSONL(&buf, []Event{evt}, RedactionOptions{
		FieldNames:    []string{"path", "host"},
		RedactRaw:     true,
		RedactSubject: true,
	}); err != nil {
		t.Fatalf("ExportJSONL: %v", err)
	}
	if strings.Contains(buf.String(), "/home/draco/.ssh") || strings.Contains(buf.String(), "github.com") {
		t.Fatalf("export leaked redacted values: %s", buf.String())
	}
	var got Event
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &got); err != nil {
		t.Fatalf("Unmarshal export: %v", err)
	}
	if got.Subject.Kind != "agent" || got.Subject.Session != "" || got.Subject.AgentName != "" {
		t.Fatalf("subject not redacted: %+v", got.Subject)
	}
	if got.InputEvent.Raw != nil {
		t.Fatalf("raw not redacted: %+v", got.InputEvent.Raw)
	}
	if got.InputEvent.Fields["path"] != redactedValue || got.Outcome.Fields["host"] != redactedValue {
		t.Fatalf("fields not redacted: input=%+v outcome=%+v", got.InputEvent.Fields, got.Outcome.Fields)
	}
	if got.ChainPrev != "" || got.ChainHash != "" {
		t.Fatalf("redacted export preserved chain fields: prev=%q hash=%q", got.ChainPrev, got.ChainHash)
	}
	if evt.InputEvent.Fields["path"] != "/home/draco/.ssh/id_ed25519" || evt.Outcome.Fields["host"] != "github.com" {
		t.Fatalf("source event mutated: %+v", evt)
	}
}
