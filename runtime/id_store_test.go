package runtime

import (
	"path/filepath"
	"testing"
)

func TestIDStoreNextSurvivesReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ids.json")
	first, err := NextID(path, "evt")
	if err != nil {
		t.Fatalf("NextID first: %v", err)
	}
	second, err := NextID(path, "evt")
	if err != nil {
		t.Fatalf("NextID second: %v", err)
	}
	if first != "evt_1" || second != "evt_2" {
		t.Fatalf("ids = %q %q", first, second)
	}
	reloaded, err := LoadIDStore(path)
	if err != nil {
		t.Fatalf("LoadIDStore: %v", err)
	}
	if reloaded.Counters["evt"] != 2 {
		t.Fatalf("counter = %+v", reloaded.Counters)
	}
	third, err := NextID(path, "evt")
	if err != nil {
		t.Fatalf("NextID third: %v", err)
	}
	if third != "evt_3" {
		t.Fatalf("third id = %q", third)
	}
}

func TestIDStoreSeparator(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ids.json")
	id, err := NextIDWithSeparator(path, "airlock", "-")
	if err != nil {
		t.Fatalf("NextIDWithSeparator: %v", err)
	}
	if id != "airlock-1" {
		t.Fatalf("id = %q", id)
	}
}
