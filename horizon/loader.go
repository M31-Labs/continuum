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
	Signature  SignatureOptions
	DigestPins map[string]string
}

type ManifestVerification struct {
	Digest    DigestVerification    `json:"digest,omitempty"`
	Signature SignatureVerification `json:"signature,omitempty"`
}

func LoadFile(path string) (Manifest, error) {
	manifest, _, err := LoadFileWithOptions(path, LoadOptions{})
	return manifest, err
}

func LoadFileWithOptions(path string, opts LoadOptions) (Manifest, ManifestVerification, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, ManifestVerification{}, fmt.Errorf("read manifest %s: %w", path, err)
	}
	digest, err := VerifyManifestDigestPin(path, data, opts.DigestPins)
	if err != nil {
		return Manifest{}, ManifestVerification{Digest: digest}, err
	}
	signature, err := VerifyManifestSignature(path, data, opts.Signature)
	verification := ManifestVerification{Digest: digest, Signature: signature}
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
		manifestCaps = annotateManifestVerification(manifestCaps, verification)
		caps = append(caps, manifestCaps...)
	}
	slices.SortFunc(caps, func(a, b capability.Capability) int {
		return strings.Compare(a.Name, b.Name)
	})
	return caps, nil
}

func annotateManifestVerification(caps []capability.Capability, verification ManifestVerification) []capability.Capability {
	if verification.Digest == (DigestVerification{}) &&
		verification.Signature.Mode == SignatureOff && !verification.Signature.Signed && !verification.Signature.Verified && verification.Signature.Error == "" {
		return caps
	}
	out := make([]capability.Capability, len(caps))
	for i, cap := range caps {
		out[i] = cap
		metadata := map[string]any{}
		for key, value := range cap.Metadata {
			metadata[key] = value
		}
		if verification.Digest != (DigestVerification{}) {
			metadata["continuum.horizon.manifest_digest.pinned"] = verification.Digest.Pinned
			metadata["continuum.horizon.manifest_digest.verified"] = verification.Digest.Verified
			if verification.Digest.PinKey != "" {
				metadata["continuum.horizon.manifest_digest.pin_key"] = verification.Digest.PinKey
			}
			if verification.Digest.Expected != "" {
				metadata["continuum.horizon.manifest_digest.expected"] = verification.Digest.Expected
			}
			if verification.Digest.Actual != "" {
				metadata["continuum.horizon.manifest_digest.actual"] = verification.Digest.Actual
			}
			if verification.Digest.Error != "" {
				metadata["continuum.horizon.manifest_digest.error"] = verification.Digest.Error
			}
		}
		if verification.Signature.Mode != SignatureOff || verification.Signature.Signed || verification.Signature.Verified || verification.Signature.Error != "" {
			metadata["continuum.horizon.manifest_signature.mode"] = string(verification.Signature.Mode)
			metadata["continuum.horizon.manifest_signature.signed"] = verification.Signature.Signed
			metadata["continuum.horizon.manifest_signature.verified"] = verification.Signature.Verified
		}
		if verification.Signature.Algorithm != "" {
			metadata["continuum.horizon.manifest_signature.algorithm"] = verification.Signature.Algorithm
		}
		if verification.Signature.KeyID != "" {
			metadata["continuum.horizon.manifest_signature.key_id"] = verification.Signature.KeyID
		}
		if verification.Signature.KeyFingerprint != "" {
			metadata["continuum.horizon.manifest_signature.key_fingerprint"] = verification.Signature.KeyFingerprint
		}
		if verification.Signature.SignaturePath != "" {
			metadata["continuum.horizon.manifest_signature.path"] = verification.Signature.SignaturePath
		}
		if verification.Signature.Error != "" {
			metadata["continuum.horizon.manifest_signature.error"] = verification.Signature.Error
		}
		out[i].Metadata = metadata
	}
	return out
}
