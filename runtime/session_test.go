package runtime

import (
	"path/filepath"
	"testing"
	"time"

	"m31labs.dev/continuum/subject"
)

func TestSessionStorePersistsAndFinishes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	store := &SessionStore{}
	store.Upsert(Session{
		ID:        "agent-session-1",
		Subject:   subject.NewAgent("claude", "agent-session-1", "/repo", "", 123),
		Command:   []string{"go", "test", "./..."},
		State:     SessionRunning,
		StartedAt: now,
	})
	if len(store.Running()) != 1 {
		t.Fatalf("running = %+v", store.Running())
	}
	if _, err := store.Finish("agent-session-1", SessionExited, 0, now.Add(time.Second)); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if len(store.Running()) != 0 {
		t.Fatalf("running after finish = %+v", store.Running())
	}
	if err := store.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	reloaded, err := LoadSessionStore(path)
	if err != nil {
		t.Fatalf("LoadSessionStore: %v", err)
	}
	if len(reloaded.Sessions) != 1 || reloaded.Sessions[0].State != SessionExited {
		t.Fatalf("reloaded = %+v", reloaded.Sessions)
	}
}
