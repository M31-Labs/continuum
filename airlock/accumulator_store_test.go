package airlock

import (
	"path/filepath"
	"testing"
	"time"

	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/subject"
)

func TestAccumulatorStorePersistsObservedBehavior(t *testing.T) {
	path := filepath.Join(t.TempDir(), "airlock-accumulators.json")
	now := time.Date(2026, 5, 24, 3, 0, 0, 0, time.UTC)
	subj := subject.NewProcessTree("demo", 123)
	store := NewAccumulatorStore()
	behaviors := store.ObserveEvents([]event.Event{
		event.NewProcessExec(subj, map[string]any{"comm": "sh"}),
		event.NewNetworkConnect(subj, "host-1.example", "", 443),
		event.NewNetworkConnect(subj, "host-1.example", "", 443),
	}, func() time.Time { return now })
	if len(behaviors) != 1 || behaviors[0].ExecCount != 1 || behaviors[0].UniqueNetworkTargets != 1 {
		t.Fatalf("behaviors = %+v", behaviors)
	}
	if err := store.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	reloaded, err := LoadAccumulatorStore(path)
	if err != nil {
		t.Fatalf("LoadAccumulatorStore: %v", err)
	}
	snapshot, ok := reloaded.Get("process-tree:demo")
	if !ok {
		t.Fatal("missing persisted process-tree accumulator")
	}
	if snapshot.ExecCount != 1 || len(snapshot.NetworkTargets) != 1 || !snapshot.UpdatedAt.Equal(now) {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}
