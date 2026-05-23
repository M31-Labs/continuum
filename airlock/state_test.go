package airlock

import (
	"path/filepath"
	"testing"
	"time"

	"m31labs.dev/continuum/subject"
)

func TestStateTransitions(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	session := Session{ID: "airlock-1", Subject: subject.NewProcessTree("demo", 123)}
	if err := session.Transition(StateAirlocked, "wormlike fanout", now); err != nil {
		t.Fatalf("Transition airlocked: %v", err)
	}
	if err := session.Transition(StateNormal, "back", now); err == nil {
		t.Fatal("expected invalid transition")
	}
	if err := session.Transition(StateReleased, "done", now); err != nil {
		t.Fatalf("Transition released: %v", err)
	}
}

func TestLoadBehaviorFixture(t *testing.T) {
	behavior, err := LoadBehaviorFixture(filepath.Join("..", "testdata", "events", "worm_fanout.json"))
	if err != nil {
		t.Fatalf("LoadBehaviorFixture: %v", err)
	}
	if behavior.UniqueNetworkTargets != 88 {
		t.Fatalf("targets = %d", behavior.UniqueNetworkTargets)
	}
	if behavior.Fact().Type == "" {
		t.Fatal("expected behavior fact")
	}
}

func TestStorePersistsSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "airlock.json")
	store := NewStore()
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	session, err := store.Enter("airlock-1", subject.NewProcessTree("demo", 123), "test", now)
	if err != nil {
		t.Fatalf("Enter: %v", err)
	}
	if session.State != StateAirlocked {
		t.Fatalf("state = %s", session.State)
	}
	if err := store.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	reloaded, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	list := reloaded.List()
	if len(list) != 1 || list[0].ID != "airlock-1" {
		t.Fatalf("reloaded = %+v", list)
	}
}
