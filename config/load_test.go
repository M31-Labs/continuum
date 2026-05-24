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
	if cfg.State.PolicyStore != ".continuum/policies.json" {
		t.Fatalf("policy store = %q", cfg.State.PolicyStore)
	}
	if cfg.State.DeliveryStore != ".continuum/deliveries.json" {
		t.Fatalf("delivery store = %q", cfg.State.DeliveryStore)
	}
	if cfg.State.IDStore != ".continuum/ids.json" {
		t.Fatalf("id store = %q", cfg.State.IDStore)
	}
	if cfg.Grant.MaxTTL != "24h" {
		t.Fatalf("grant max ttl = %q", cfg.Grant.MaxTTL)
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

func TestLoadRejectsUnsupportedApprovalKind(t *testing.T) {
	_, err := LoadBytes([]byte("[approval]\nkind = \"webhook\"\n"))
	if err == nil {
		t.Fatal("expected unsupported approval kind error")
	}
}

func TestLoadDaemonConfig(t *testing.T) {
	cfg, err := LoadBytes([]byte("[daemon]\ncors_origins = \"https://console.example,https://ops.example\"\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Daemon.CORSOrigins != "https://console.example,https://ops.example" {
		t.Fatalf("daemon config = %+v", cfg.Daemon)
	}
}

func TestLoadGrantConfig(t *testing.T) {
	cfg, err := LoadBytes([]byte("[grant]\nmax_ttl = \"2h\"\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Grant.MaxTTL != "2h" {
		t.Fatalf("grant config = %+v", cfg.Grant)
	}
}

func TestLoadCapabilitySignatureConfig(t *testing.T) {
	cfg, err := LoadBytes([]byte("[capabilities]\nhorizon_manifest_dir = \"caps\"\nmanifest_signature_mode = \"warn\"\nmanifest_signature_public_keys = \"keys/a.pub,keys/b.pub\"\n"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Capabilities.ManifestSignatureMode != "warn" {
		t.Fatalf("signature mode = %q", cfg.Capabilities.ManifestSignatureMode)
	}
	if cfg.Capabilities.ManifestSignaturePublicKeys != "keys/a.pub,keys/b.pub" {
		t.Fatalf("signature keys = %q", cfg.Capabilities.ManifestSignaturePublicKeys)
	}
}

func TestLoadRejectsRequireSignatureWithoutKeys(t *testing.T) {
	_, err := LoadBytes([]byte("[capabilities]\nmanifest_signature_mode = \"require\"\n"))
	if err == nil {
		t.Fatal("expected require signature without keys error")
	}
}

func TestLoadRejectsInvalidGrantTTL(t *testing.T) {
	_, err := LoadBytes([]byte("[grant]\nmax_ttl = \"0s\"\n"))
	if err == nil {
		t.Fatal("expected invalid grant max_ttl error")
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
	if resolved.State.GrantStore != filepath.Join("examples", "agent-workdir", ".continuum", "grants.json") {
		t.Fatalf("grant store = %q", resolved.State.GrantStore)
	}
	if resolved.State.DeliveryStore != filepath.Join("examples", "agent-workdir", ".continuum", "deliveries.json") {
		t.Fatalf("delivery store = %q", resolved.State.DeliveryStore)
	}
	if resolved.State.IDStore != filepath.Join("examples", "agent-workdir", ".continuum", "ids.json") {
		t.Fatalf("id store = %q", resolved.State.IDStore)
	}
	cfg.Capabilities.ManifestSignaturePublicKeys = "keys/a.pub,/etc/continuum/b.pub"
	resolved = Resolve(cfg, filepath.Join("examples", "agent-workdir", "continuum.toml"))
	wantKeys := filepath.Join("examples", "agent-workdir", "keys", "a.pub") + ",/etc/continuum/b.pub"
	if resolved.Capabilities.ManifestSignaturePublicKeys != wantKeys {
		t.Fatalf("signature keys = %q", resolved.Capabilities.ManifestSignaturePublicKeys)
	}
}
