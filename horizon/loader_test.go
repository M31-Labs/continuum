package horizon

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/internal/testutil"
)

func TestLoadHorizonManifests(t *testing.T) {
	caps, err := LoadDir(filepath.Join("..", "testdata", "manifests"))
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(caps) != 2 {
		t.Fatalf("caps len = %d", len(caps))
	}
	exec := caps[0]
	if exec.Name != "kernel.network.connect.observe" && exec.Name != "kernel.process.exec.observe" {
		t.Fatalf("unexpected first cap: %+v", exec)
	}
	found := false
	for _, cap := range caps {
		if cap.Name == "kernel.process.exec.observe" {
			found = true
			if cap.Kind != capability.KindSource || cap.Owner != "horizon" || cap.Output != "ExecEvent" {
				t.Fatalf("bad exec cap: %+v", cap)
			}
		}
	}
	if !found {
		t.Fatal("exec capability not loaded")
	}
}

func TestLoadHorizonV0Manifest(t *testing.T) {
	manifest, err := LoadFile(filepath.Join("..", "testdata", "horizon-manifests", "exec.cap.json"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	caps, err := manifest.ContinuumCapabilities()
	if err != nil {
		t.Fatalf("ContinuumCapabilities: %v", err)
	}
	if len(caps) != 1 {
		t.Fatalf("caps len = %d", len(caps))
	}
	cap := caps[0]
	if cap.Name != "kernel.process.exec.observe" || cap.Owner != "horizon" {
		t.Fatalf("cap identity = %+v", cap)
	}
	if cap.Output != "ExecEvent" || cap.Program != "OnExec" || cap.Section != "tracepoint/sched:sched_process_exec" {
		t.Fatalf("cap route = %+v", cap)
	}
	if got := cap.Metadata["horizon.package"]; got != "probes" {
		t.Fatalf("metadata package = %v", got)
	}
	events, ok := cap.Metadata["horizon.maps.events"].([]string)
	if !ok || len(events) != 1 || events[0] != "ExecEvents" {
		t.Fatalf("metadata events = %#v", cap.Metadata["horizon.maps.events"])
	}
}

func TestLoadHorizonV0Dir(t *testing.T) {
	caps, err := LoadDir(filepath.Join("..", "testdata", "horizon-manifests"))
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(caps) != 1 || caps[0].Name != "kernel.process.exec.observe" {
		t.Fatalf("caps = %+v", caps)
	}
}

func TestHorizonManifestToRegistryCapabilityGolden(t *testing.T) {
	caps, err := LoadDir(filepath.Join("..", "testdata", "horizon-manifests"))
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	testutil.EqualGoldenJSON(t, filepath.Join("..", "testdata", "golden", "horizon_exec_capabilities.json"), caps)
}

func TestLoadDirRequiresSignedManifest(t *testing.T) {
	dir, pub := writeSignedManifestFixture(t)
	caps, err := LoadDirWithOptions(dir, LoadOptions{
		Signature: SignatureOptions{
			Mode:       SignatureRequire,
			PublicKeys: []TrustedPublicKey{{ID: "test-key", Key: pub}},
		},
	})
	if err != nil {
		t.Fatalf("LoadDirWithOptions: %v", err)
	}
	if len(caps) != 1 {
		t.Fatalf("caps = %+v", caps)
	}
	if got := caps[0].Metadata["continuum.horizon.manifest_signature.verified"]; got != true {
		t.Fatalf("signature verified metadata = %#v", got)
	}
	if got := caps[0].Metadata["continuum.horizon.manifest_signature.key_id"]; got != "test-key" {
		t.Fatalf("signature key id = %#v", got)
	}
}

func TestLoadDirRequiresSignatureSidecar(t *testing.T) {
	dir := copyManifestFixture(t)
	_, err := LoadDirWithOptions(dir, LoadOptions{
		Signature: SignatureOptions{
			Mode:       SignatureRequire,
			PublicKeys: []TrustedPublicKey{{ID: "test-key", Key: make(ed25519.PublicKey, ed25519.PublicKeySize)}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "read signature sidecar") {
		t.Fatalf("LoadDirWithOptions error = %v", err)
	}
}

func TestLoadDirRejectsTamperedSignedManifest(t *testing.T) {
	dir, pub := writeSignedManifestFixture(t)
	path := filepath.Join(dir, "exec.cap.json")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = LoadDirWithOptions(dir, LoadOptions{
		Signature: SignatureOptions{
			Mode:       SignatureRequire,
			PublicKeys: []TrustedPublicKey{{ID: "test-key", Key: pub}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("LoadDirWithOptions error = %v", err)
	}
}

func TestLoadDirWarnsOnUnsignedManifest(t *testing.T) {
	dir := copyManifestFixture(t)
	caps, err := LoadDirWithOptions(dir, LoadOptions{
		Signature: SignatureOptions{Mode: SignatureWarn},
	})
	if err != nil {
		t.Fatalf("LoadDirWithOptions: %v", err)
	}
	if len(caps) != 1 {
		t.Fatalf("caps = %+v", caps)
	}
	if got := caps[0].Metadata["continuum.horizon.manifest_signature.verified"]; got != false {
		t.Fatalf("signature verified metadata = %#v", got)
	}
	if got := caps[0].Metadata["continuum.horizon.manifest_signature.error"]; got == "" {
		t.Fatalf("missing signature warning metadata: %+v", caps[0].Metadata)
	}
}

func TestLoadDirVerifiesDigestPin(t *testing.T) {
	dir := copyManifestFixture(t)
	path := filepath.Join(dir, "exec.cap.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	caps, err := LoadDirWithOptions(dir, LoadOptions{
		DigestPins: map[string]string{"exec.cap.json": SHA256Hex(data)},
	})
	if err != nil {
		t.Fatalf("LoadDirWithOptions: %v", err)
	}
	if len(caps) != 1 {
		t.Fatalf("caps = %+v", caps)
	}
	if got := caps[0].Metadata["continuum.horizon.manifest_digest.verified"]; got != true {
		t.Fatalf("digest verified metadata = %#v", got)
	}
	if got := caps[0].Metadata["continuum.horizon.manifest_digest.actual"]; got != SHA256Hex(data) {
		t.Fatalf("digest actual metadata = %#v", got)
	}
}

func TestLoadDirRejectsDigestPinMismatch(t *testing.T) {
	dir := copyManifestFixture(t)
	_, err := LoadDirWithOptions(dir, LoadOptions{
		DigestPins: map[string]string{"exec.cap.json": strings.Repeat("0", 64)},
	})
	if err == nil || !strings.Contains(err.Error(), "sha256 digest pin mismatch") {
		t.Fatalf("LoadDirWithOptions error = %v", err)
	}
}

func writeSignedManifestFixture(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	dir := copyManifestFixture(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "exec.cap.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	envelope := signatureEnvelope{
		Schema:    SignatureSchemaV0,
		Algorithm: "ed25519",
		KeyID:     "test-key",
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data)),
	}
	sig, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sig", sig, 0600); err != nil {
		t.Fatal(err)
	}
	return dir, pub
}

func copyManifestFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "horizon-manifests", "exec.cap.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "exec.cap.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}
