package runtime

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/subject"
)

func TestDeliveryStorePersistsAttempts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deliveries.json")
	store, err := LoadDeliveryStore(path)
	if err != nil {
		t.Fatalf("LoadDeliveryStore: %v", err)
	}
	item, err := store.Enqueue(DeliveryItem{
		AuditID:    "evt_1",
		EventID:    "evt_1",
		Capability: "observe.audit",
		Status:     DeliveryPending,
		CreatedAt:  time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, err := store.RecordAttempt(item.ID, audit.DeliveryAttempt{
		Time:       time.Date(2026, 5, 23, 12, 0, 1, 0, time.UTC),
		Capability: "observe.audit",
		Status:     string(DeliveryDelivered),
	}); err != nil {
		t.Fatalf("RecordAttempt: %v", err)
	}
	if err := store.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	reloaded, err := LoadDeliveryStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.ByStatus(DeliveryDelivered); len(got) != 1 || len(got[0].Attempts) != 1 {
		t.Fatalf("delivered = %+v", got)
	}
}

func TestEngineWritesDeliveryQueue(t *testing.T) {
	bundle, err := arbiterx.CompileFile(filepath.Join("..", "examples", "agent-workdir", "policies", "main.arb"))
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	path := filepath.Join(t.TempDir(), "deliveries.json")
	queue, err := LoadDeliveryStore(path)
	if err != nil {
		t.Fatalf("LoadDeliveryStore: %v", err)
	}
	sink := &memorySink{}
	engine := NewEngine(bundle, sink)
	engine.Queue = queue
	engine.Now = func() time.Time { return time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC) }
	engine.NewID = func() string { return "evt_delivery_link" }
	subj := subject.NewAgent("claude", "agent-42", "/repo", "", 123)
	evt := event.NewFileAccess(subj, "/repo/main.go", "write")
	evt.ID = "evt_input_file_write"
	record, _, err := engine.DecideEvent(context.Background(), evt)
	if err != nil {
		t.Fatalf("DecideEvent: %v", err)
	}
	if len(sink.events) != 1 || len(record.Delivery) != 1 || len(sink.events[0].Delivery) != 1 {
		t.Fatalf("audit delivery records record=%+v sink=%+v", record.Delivery, sink.events)
	}
	reloaded, err := LoadDeliveryStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	items := reloaded.List()
	if len(items) != 1 || items[0].Status != DeliveryDelivered || len(items[0].Attempts) != 1 {
		t.Fatalf("items = %+v", items)
	}
	item := items[0]
	if item.AuditID != record.ID || item.EventID != evt.ID || item.Capability != record.Capability || item.Enforcement != record.Enforcement {
		t.Fatalf("delivery item linkage item=%+v record=%+v event=%+v", item, record, evt)
	}
	if record.Delivery[0].DeliveryID != item.ID || item.Attempts[0].DeliveryID != item.ID {
		t.Fatalf("attempt delivery IDs item=%s audit=%+v queue=%+v", item.ID, record.Delivery[0], item.Attempts[0])
	}
	if record.Delivery[0].Status != item.Attempts[0].Status || record.Delivery[0].Capability != item.Attempts[0].Capability || record.Delivery[0].Enforcement != item.Attempts[0].Enforcement {
		t.Fatalf("attempt mismatch audit=%+v queue=%+v", record.Delivery[0], item.Attempts[0])
	}
}
