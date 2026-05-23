package policy

import (
	"path/filepath"
	"testing"
	"time"
)

func TestStorePublishActivateAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policies.json")
	store, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	bundle, err := Load("agent-workdir", filepath.Join("..", "examples", "agent-workdir", "policies", "main.arb"))
	if err != nil {
		t.Fatalf("Load bundle: %v", err)
	}
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	if err := store.Publish(bundle, now); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if err := store.Activate("agent-workdir"); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if err := store.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	reloaded, err := LoadStore(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	active, ok := reloaded.ActiveBundle()
	if !ok || active.Name != "agent-workdir" {
		t.Fatalf("active = %+v, %v", active, ok)
	}
}
