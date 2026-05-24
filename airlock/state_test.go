package airlock

import (
	"os"
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

func TestStateTransitionValidationCoversDeclaredGraph(t *testing.T) {
	states := []State{"", StateNormal, StateSuspicious, StateContained, StateAirlocked, StateReleased, StateRemediated, StateDestroyed}
	legal := map[State]map[State]bool{
		"": {
			StateNormal:     true,
			StateSuspicious: true,
			StateContained:  true,
			StateAirlocked:  true,
		},
		StateNormal: {
			StateNormal:     true,
			StateSuspicious: true,
			StateContained:  true,
			StateAirlocked:  true,
		},
		StateSuspicious: {
			StateSuspicious: true,
			StateContained:  true,
			StateAirlocked:  true,
			StateReleased:   true,
		},
		StateContained: {
			StateContained:  true,
			StateAirlocked:  true,
			StateReleased:   true,
			StateRemediated: true,
			StateDestroyed:  true,
		},
		StateAirlocked: {
			StateAirlocked:  true,
			StateReleased:   true,
			StateRemediated: true,
			StateDestroyed:  true,
		},
		StateReleased: {
			StateReleased: true,
		},
		StateRemediated: {
			StateRemediated: true,
		},
		StateDestroyed: {
			StateDestroyed: true,
		},
	}
	for _, from := range states {
		for _, to := range states {
			want := legal[from][to]
			if got := validTransition(from, to); got != want {
				t.Fatalf("validTransition(%q, %q) = %v, want %v", from, to, got, want)
			}
		}
	}
}

func TestStateTransitionValidationRejectsUnknownStates(t *testing.T) {
	for _, tc := range []struct {
		name string
		from State
		to   State
	}{
		{name: "unknown self", from: State("unknown"), to: State("unknown")},
		{name: "unknown source", from: State("unknown"), to: StateAirlocked},
		{name: "unknown target", from: StateAirlocked, to: State("unknown")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if validTransition(tc.from, tc.to) {
				t.Fatalf("validTransition(%q, %q) = true, want false", tc.from, tc.to)
			}
		})
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
	if reloaded.SchemaVersion != StoreSchemaVersion {
		t.Fatalf("schema version = %d", reloaded.SchemaVersion)
	}
}

func TestStoreSchemaMigration(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "legacy-airlock.json")
	if err := os.WriteFile(legacyPath, []byte(`[{"id":"airlock-1","state":"airlocked"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	legacy, err := LoadStore(legacyPath)
	if err != nil {
		t.Fatalf("LoadStore legacy: %v", err)
	}
	if legacy.SchemaVersion != StoreSchemaVersion || len(legacy.List()) != 1 {
		t.Fatalf("legacy store version=%d sessions=%+v", legacy.SchemaVersion, legacy.List())
	}
	futurePath := filepath.Join(dir, "future-airlock.json")
	if err := os.WriteFile(futurePath, []byte(`{"schema_version":99,"sessions":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStore(futurePath); err == nil {
		t.Fatal("future airlock store schema loaded without error")
	}
}
