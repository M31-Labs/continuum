package horizon

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const SignatureSchemaV0 = "m31labs.dev/continuum/horizon-manifest-signature/v0"

type SignatureMode string

const (
	SignatureOff     SignatureMode = "off"
	SignatureWarn    SignatureMode = "warn"
	SignatureRequire SignatureMode = "require"
)

type TrustedPublicKey struct {
	ID  string
	Key ed25519.PublicKey
}

type SignatureOptions struct {
	Mode       SignatureMode
	PublicKeys []TrustedPublicKey
}

type SignatureVerification struct {
	Mode           SignatureMode `json:"mode,omitempty"`
	Signed         bool          `json:"signed"`
	Verified       bool          `json:"verified"`
	Algorithm      string        `json:"algorithm,omitempty"`
	KeyID          string        `json:"key_id,omitempty"`
	KeyFingerprint string        `json:"key_fingerprint,omitempty"`
	SignaturePath  string        `json:"signature_path,omitempty"`
	Error          string        `json:"error,omitempty"`
}

type signatureEnvelope struct {
	Schema    string `json:"schema,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	KeyID     string `json:"key_id,omitempty"`
	Signature string `json:"signature"`
}

func NormalizeSignatureMode(mode SignatureMode) (SignatureMode, error) {
	switch mode {
	case "", SignatureOff:
		return SignatureOff, nil
	case SignatureWarn, SignatureRequire:
		return mode, nil
	default:
		return "", fmt.Errorf("manifest signature mode %q is not supported", mode)
	}
}

func VerifyManifestSignature(path string, payload []byte, opts SignatureOptions) (SignatureVerification, error) {
	mode, err := NormalizeSignatureMode(opts.Mode)
	if err != nil {
		return SignatureVerification{}, err
	}
	verification := SignatureVerification{Mode: mode, SignaturePath: path + ".sig"}
	if mode == SignatureOff {
		return verification, nil
	}
	sigData, err := os.ReadFile(verification.SignaturePath)
	if err != nil {
		verification.Error = fmt.Sprintf("read signature sidecar: %v", err)
		if mode == SignatureRequire {
			return verification, fmt.Errorf("manifest %s: %s", path, verification.Error)
		}
		return verification, nil
	}
	verification.Signed = true
	envelope, err := parseSignatureEnvelope(sigData)
	if err != nil {
		verification.Error = err.Error()
		if mode == SignatureRequire {
			return verification, fmt.Errorf("manifest %s: %s", path, verification.Error)
		}
		return verification, nil
	}
	verification.Algorithm = envelope.Algorithm
	verification.KeyID = envelope.KeyID
	if len(opts.PublicKeys) == 0 {
		verification.Error = "no trusted manifest signing keys configured"
		if mode == SignatureRequire {
			return verification, fmt.Errorf("manifest %s: %s", path, verification.Error)
		}
		return verification, nil
	}
	sig, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		sig, err = base64.RawStdEncoding.DecodeString(envelope.Signature)
	}
	if err != nil {
		verification.Error = fmt.Sprintf("decode signature: %v", err)
		if mode == SignatureRequire {
			return verification, fmt.Errorf("manifest %s: %s", path, verification.Error)
		}
		return verification, nil
	}
	if len(sig) != ed25519.SignatureSize {
		verification.Error = fmt.Sprintf("signature length %d is invalid", len(sig))
		if mode == SignatureRequire {
			return verification, fmt.Errorf("manifest %s: %s", path, verification.Error)
		}
		return verification, nil
	}
	for _, key := range opts.PublicKeys {
		if len(key.Key) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(key.Key, payload, sig) {
			verification.Verified = true
			verification.KeyID = key.ID
			if verification.KeyID == "" {
				verification.KeyID = envelope.KeyID
			}
			verification.KeyFingerprint = PublicKeyFingerprint(key.Key)
			return verification, nil
		}
	}
	verification.Error = "signature verification failed"
	if mode == SignatureRequire {
		return verification, fmt.Errorf("manifest %s: %s", path, verification.Error)
	}
	return verification, nil
}

func parseSignatureEnvelope(data []byte) (signatureEnvelope, error) {
	trimmed := strings.TrimSpace(string(data))
	var envelope signatureEnvelope
	if strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal([]byte(trimmed), &envelope); err != nil {
			return signatureEnvelope{}, fmt.Errorf("parse signature envelope: %w", err)
		}
		if envelope.Schema != "" && envelope.Schema != SignatureSchemaV0 {
			return signatureEnvelope{}, fmt.Errorf("unsupported signature schema %q", envelope.Schema)
		}
	} else {
		envelope.Signature = trimmed
	}
	if envelope.Algorithm == "" {
		envelope.Algorithm = "ed25519"
	}
	if !strings.EqualFold(envelope.Algorithm, "ed25519") {
		return signatureEnvelope{}, fmt.Errorf("unsupported signature algorithm %q", envelope.Algorithm)
	}
	if strings.TrimSpace(envelope.Signature) == "" {
		return signatureEnvelope{}, fmt.Errorf("signature is required")
	}
	envelope.Signature = strings.TrimSpace(envelope.Signature)
	return envelope, nil
}

func LoadTrustedPublicKeyFile(path string) (TrustedPublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return TrustedPublicKey{}, fmt.Errorf("read manifest public key %s: %w", path, err)
	}
	key, err := ParseTrustedPublicKey(data)
	if err != nil {
		return TrustedPublicKey{}, fmt.Errorf("parse manifest public key %s: %w", path, err)
	}
	return TrustedPublicKey{
		ID:  filepath.Base(path),
		Key: key,
	}, nil
}

func ParseTrustedPublicKey(data []byte) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(string(data))
	if block, _ := pem.Decode(data); block != nil {
		if parsed, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if key, ok := parsed.(ed25519.PublicKey); ok {
				return key, nil
			}
		}
		if len(block.Bytes) == ed25519.PublicKeySize {
			return ed25519.PublicKey(block.Bytes), nil
		}
		return nil, fmt.Errorf("PEM block has unexpected Ed25519 public key size %d", len(block.Bytes))
	}
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(decoded) == ed25519.PublicKeySize {
		return ed25519.PublicKey(decoded), nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil && len(decoded) == ed25519.PublicKeySize {
		return ed25519.PublicKey(decoded), nil
	}
	if decoded, err := hex.DecodeString(trimmed); err == nil && len(decoded) == ed25519.PublicKeySize {
		return ed25519.PublicKey(decoded), nil
	}
	if len(data) == ed25519.PublicKeySize {
		return ed25519.PublicKey(data), nil
	}
	return nil, fmt.Errorf("not a valid Ed25519 public key")
}

func PublicKeyFingerprint(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}
