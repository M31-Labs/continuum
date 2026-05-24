package policy

import (
	"os"
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
	if active.Provenance.SourceSHA256 == "" || active.Provenance.SourceBytes == 0 || active.Provenance.Compiler == "" {
		t.Fatalf("missing provenance: %+v", active.Provenance)
	}
}

func TestStoreSchemaMigration(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "legacy-policies.json")
	if err := os.WriteFile(legacyPath, []byte(`{"bundles":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	legacy, err := LoadStore(legacyPath)
	if err != nil {
		t.Fatalf("LoadStore legacy: %v", err)
	}
	if legacy.SchemaVersion != StoreSchemaVersion {
		t.Fatalf("legacy schema version = %d", legacy.SchemaVersion)
	}
	futurePath := filepath.Join(dir, "future-policies.json")
	if err := os.WriteFile(futurePath, []byte(`{"schema_version":99,"bundles":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStore(futurePath); err == nil {
		t.Fatal("future policy store schema loaded without error")
	}
}

func TestStoreRollbackRestoresPreviousActivation(t *testing.T) {
	store := &Store{Bundles: map[string]StoredBundle{}}
	agent, err := Load("agent-workdir", filepath.Join("..", "examples", "agent-workdir", "policies", "main.arb"))
	if err != nil {
		t.Fatalf("Load agent: %v", err)
	}
	airlock, err := Load("airlock", filepath.Join("..", "examples", "airlock", "policies", "main.arb"))
	if err != nil {
		t.Fatalf("Load airlock: %v", err)
	}
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	if err := store.Publish(agent, now); err != nil {
		t.Fatalf("Publish agent: %v", err)
	}
	if err := store.Publish(airlock, now); err != nil {
		t.Fatalf("Publish airlock: %v", err)
	}
	if err := store.ActivateAt("agent-workdir", now); err != nil {
		t.Fatalf("Activate agent: %v", err)
	}
	if err := store.ActivateAt("airlock", now.Add(time.Minute)); err != nil {
		t.Fatalf("Activate airlock: %v", err)
	}
	rolledBack, err := store.Rollback()
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if rolledBack.Name != "agent-workdir" || store.Active != "agent-workdir" {
		t.Fatalf("rollback = %+v active=%s", rolledBack, store.Active)
	}
	if _, err := store.Rollback(); err == nil {
		t.Fatal("second rollback succeeded without a previous activation")
	}
}
