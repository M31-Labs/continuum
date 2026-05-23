package testutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func ReadJSON[T any](t *testing.T, rel string) T {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(rel))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("parse fixture %s: %v", rel, err)
	}
	return out
}
