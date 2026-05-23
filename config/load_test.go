package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadExampleConfig(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "examples", "agent-workdir", "continuum.toml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Project.Name != "agent-workdir" {
		t.Fatalf("project name = %q", cfg.Project.Name)
	}
	if cfg.Policy.Bundle != "policies/main.arb" {
		t.Fatalf("policy bundle = %q", cfg.Policy.Bundle)
	}
	if cfg.Enforcement.Network != "observe" {
		t.Fatalf("network backend = %q", cfg.Enforcement.Network)
	}
}

func TestLoadRejectsUnknownKey(t *testing.T) {
	_, err := LoadBytes([]byte("[project]\nname = \"x\"\nunknown = \"y\"\n"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadReportsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "continuum.toml")
	if err := os.WriteFile(path, []byte("[audit]\nkind = \"sqlite\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestResolvePathsRelativeToConfig(t *testing.T) {
	cfg := Default()
	resolved := Resolve(cfg, filepath.Join("examples", "agent-workdir", "continuum.toml"))
	if resolved.Policy.Bundle != filepath.Join("examples", "agent-workdir", "policies", "main.arb") {
		t.Fatalf("policy path = %q", resolved.Policy.Bundle)
	}
	if resolved.Audit.Path != filepath.Join("examples", "agent-workdir", ".continuum", "audit.jsonl") {
		t.Fatalf("audit path = %q", resolved.Audit.Path)
	}
}
