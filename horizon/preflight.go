package horizon

import (
	"fmt"
	"os"
)

// PreflightOptions defines the fail-closed trust inputs for a Horizon object.
// Both the manifest and object must be digest-pinned, and the manifest must be
// signed by one of the configured keys.
type PreflightOptions struct {
	ManifestPath string
	ObjectPath   string
	DigestPins   map[string]string
	PublicKeys   []TrustedPublicKey
}

type PreflightResult struct {
	Manifest     Manifest             `json:"manifest"`
	Verification ManifestVerification `json:"verification"`
	ObjectDigest DigestVerification   `json:"object_digest"`
}

func Preflight(options PreflightOptions) (PreflightResult, error) {
	if options.ManifestPath == "" || options.ObjectPath == "" {
		return PreflightResult{}, fmt.Errorf("manifest and object paths are required")
	}
	manifest, verification, err := LoadFileWithOptions(options.ManifestPath, LoadOptions{
		Signature:  SignatureOptions{Mode: SignatureRequire, PublicKeys: options.PublicKeys},
		DigestPins: options.DigestPins,
	})
	result := PreflightResult{Manifest: manifest, Verification: verification}
	if err != nil {
		return result, err
	}
	if !verification.Digest.Pinned || !verification.Digest.Verified {
		return result, fmt.Errorf("manifest %s is not digest-pinned", options.ManifestPath)
	}
	object, err := os.ReadFile(options.ObjectPath)
	if err != nil {
		return result, fmt.Errorf("read Horizon object %s: %w", options.ObjectPath, err)
	}
	result.ObjectDigest, err = VerifyManifestDigestPin(options.ObjectPath, object, options.DigestPins)
	if err != nil {
		return result, err
	}
	if !result.ObjectDigest.Pinned || !result.ObjectDigest.Verified {
		return result, fmt.Errorf("Horizon object %s is not digest-pinned", options.ObjectPath)
	}
	return result, nil
}
