package horizon

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"m31labs.dev/continuum/capability"
)

const horizonV1Fixture = `{
  "schema": "m31labs.dev/horizon/capability/v1",
  "package": "mercutio",
  "programs": [{"name":"GateExec","kind":"lsm","attach":"bprm_check_security","section":"lsm/bprm_check_security","capabilities":["kernel.process.exec.block"]}],
  "capabilities": [{
    "name":"kernel.process.exec.block",
    "kind":"source",
    "danger":{"mode":"control","scope":"process","reversibility":"restart"},
    "program":"GateExec",
    "section":"lsm/bprm_check_security",
    "maps":{"read":["CellScope"],"write":[],"events":["ExecEvents"]},
    "requirements":{"min_kernel":"5.7","features":["bpf_lsm"],"permissions":["bpf_program_load"]}
  }]
}`

func TestLoadHorizonV1ManifestPreservesDangerAxes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mercutio.cap.json")
	if err := os.WriteFile(path, []byte(horizonV1Fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	caps, err := manifest.ContinuumCapabilities()
	if err != nil {
		t.Fatalf("ContinuumCapabilities: %v", err)
	}
	if len(caps) != 1 || caps[0].Danger != capability.DangerEnforcement || caps[0].Output != "KernelEvent" {
		t.Fatalf("capabilities = %+v", caps)
	}
	if got := caps[0].Metadata["horizon.danger.scope"]; got != "process" {
		t.Fatalf("danger scope = %#v", got)
	}
	if len(caps[0].Requires) == 0 {
		t.Fatal("v1 kernel requirements were not preserved")
	}
}

func TestPreflightRequiresSignedPinnedManifestAndObject(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "mercutio.cap.json")
	objectPath := filepath.Join(dir, "mercutio.bpf.o")
	manifest := []byte(horizonV1Fixture)
	object := []byte("ELF fixture")
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objectPath, object, 0o600); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignPayload(manifest, "release", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath+".sig", signature, 0o600); err != nil {
		t.Fatal(err)
	}
	options := PreflightOptions{
		ManifestPath: manifestPath,
		ObjectPath:   objectPath,
		PublicKeys:   []TrustedPublicKey{{ID: "release", Key: publicKey}},
		DigestPins: map[string]string{
			filepath.Base(manifestPath): SHA256Hex(manifest),
			filepath.Base(objectPath):   SHA256Hex(object),
		},
	}
	result, err := Preflight(options)
	if err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if !result.Verification.Signature.Verified || !result.Verification.Digest.Verified || !result.ObjectDigest.Verified {
		t.Fatalf("verification = %+v", result)
	}
	delete(options.DigestPins, filepath.Base(objectPath))
	if _, err := Preflight(options); err == nil || !strings.Contains(err.Error(), "not digest-pinned") {
		t.Fatalf("missing object pin error = %v", err)
	}
}
