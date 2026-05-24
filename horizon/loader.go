package horizon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"m31labs.dev/continuum/capability"
)

type LoadOptions struct {
	Signature SignatureOptions
}

func LoadFile(path string) (Manifest, error) {
	manifest, _, err := LoadFileWithOptions(path, LoadOptions{})
	return manifest, err
}

func LoadFileWithOptions(path string, opts LoadOptions) (Manifest, SignatureVerification, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, SignatureVerification{}, fmt.Errorf("read manifest %s: %w", path, err)
	}
	verification, err := VerifyManifestSignature(path, data, opts.Signature)
	if err != nil {
		return Manifest{}, verification, err
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, verification, fmt.Errorf("parse manifest %s: %w", path, err)
	}
	if _, err := manifest.ContinuumCapabilities(); err != nil {
		return Manifest{}, verification, err
	}
	return manifest, verification, nil
}

func LoadDir(dir string) ([]capability.Capability, error) {
	return LoadDirWithOptions(dir, LoadOptions{})
}

func LoadDirWithOptions(dir string, opts LoadOptions) ([]capability.Capability, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read manifest dir %s: %w", dir, err)
	}
	var caps []capability.Capability
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".cap.json") {
			continue
		}
		manifest, verification, err := LoadFileWithOptions(filepath.Join(dir, entry.Name()), opts)
		if err != nil {
			return nil, err
		}
		manifestCaps, err := manifest.ContinuumCapabilities()
		if err != nil {
			return nil, err
		}
		manifestCaps = annotateSignature(manifestCaps, verification)
		caps = append(caps, manifestCaps...)
	}
	slices.SortFunc(caps, func(a, b capability.Capability) int {
		return strings.Compare(a.Name, b.Name)
	})
	return caps, nil
}

func annotateSignature(caps []capability.Capability, verification SignatureVerification) []capability.Capability {
	if verification.Mode == SignatureOff && !verification.Signed && !verification.Verified && verification.Error == "" {
		return caps
	}
	out := make([]capability.Capability, len(caps))
	for i, cap := range caps {
		out[i] = cap
		metadata := map[string]any{}
		for key, value := range cap.Metadata {
			metadata[key] = value
		}
		metadata["continuum.horizon.manifest_signature.mode"] = string(verification.Mode)
		metadata["continuum.horizon.manifest_signature.signed"] = verification.Signed
		metadata["continuum.horizon.manifest_signature.verified"] = verification.Verified
		if verification.Algorithm != "" {
			metadata["continuum.horizon.manifest_signature.algorithm"] = verification.Algorithm
		}
		if verification.KeyID != "" {
			metadata["continuum.horizon.manifest_signature.key_id"] = verification.KeyID
		}
		if verification.KeyFingerprint != "" {
			metadata["continuum.horizon.manifest_signature.key_fingerprint"] = verification.KeyFingerprint
		}
		if verification.SignaturePath != "" {
			metadata["continuum.horizon.manifest_signature.path"] = verification.SignaturePath
		}
		if verification.Error != "" {
			metadata["continuum.horizon.manifest_signature.error"] = verification.Error
		}
		out[i].Metadata = metadata
	}
	return out
}
