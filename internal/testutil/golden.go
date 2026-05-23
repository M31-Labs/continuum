package testutil

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func Equal[T comparable](t *testing.T, got, want T) {
	t.Helper()
	if got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func EqualGoldenJSON(t *testing.T, rel string, got any) {
	t.Helper()
	data, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("marshal golden value: %v", err)
	}
	data = append(data, '\n')
	want, err := os.ReadFile(filepath.Clean(rel))
	if err != nil {
		t.Fatalf("read golden %s: %v", rel, err)
	}
	if !bytes.Equal(data, want) {
		t.Fatalf("golden %s mismatch\nwant:\n%s\ngot:\n%s", rel, want, data)
	}
}
