package horizon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
)

type DigestVerification struct {
	Pinned   bool   `json:"pinned"`
	Verified bool   `json:"verified"`
	PinKey   string `json:"pin_key,omitempty"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Error    string `json:"error,omitempty"`
}

func VerifyManifestDigestPin(path string, payload []byte, pins map[string]string) (DigestVerification, error) {
	if len(pins) == 0 {
		return DigestVerification{}, nil
	}
	pinKey, expected, ok := findDigestPin(path, pins)
	if !ok {
		return DigestVerification{}, nil
	}
	actual := SHA256Hex(payload)
	verification := DigestVerification{
		Pinned:   true,
		PinKey:   pinKey,
		Expected: normalizeSHA256(expected),
		Actual:   actual,
	}
	if len(verification.Expected) != sha256.Size*2 {
		verification.Error = fmt.Sprintf("digest pin %s has invalid sha256 length %d", pinKey, len(verification.Expected))
		return verification, fmt.Errorf("manifest %s: %s", path, verification.Error)
	}
	if _, err := hex.DecodeString(verification.Expected); err != nil {
		verification.Error = fmt.Sprintf("digest pin %s is not valid hex: %v", pinKey, err)
		return verification, fmt.Errorf("manifest %s: %s", path, verification.Error)
	}
	if actual != verification.Expected {
		verification.Error = "sha256 digest pin mismatch"
		return verification, fmt.Errorf("manifest %s: %s: got %s expected %s", path, verification.Error, actual, verification.Expected)
	}
	verification.Verified = true
	return verification, nil
}

func SHA256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func findDigestPin(path string, pins map[string]string) (string, string, bool) {
	candidates := []string{filepath.Clean(path)}
	if abs, err := filepath.Abs(path); err == nil {
		candidates = append(candidates, filepath.Clean(abs))
	}
	candidates = append(candidates, filepath.Base(path))
	for _, candidate := range candidates {
		if expected, ok := pins[candidate]; ok {
			return candidate, expected, true
		}
	}
	return "", "", false
}

func normalizeSHA256(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "sha256:")
	return value
}
