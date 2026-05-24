package main

import (
	"fmt"
	"strings"

	"m31labs.dev/continuum/config"
	"m31labs.dev/continuum/horizon"
)

func horizonProviderFromConfig(cfg config.Config) (horizon.DirProvider, error) {
	opts, err := horizonLoadOptionsFromConfig(cfg)
	if err != nil {
		return horizon.DirProvider{}, err
	}
	return horizon.DirProvider{Dir: cfg.Capabilities.HorizonManifestDir, Options: opts}, nil
}

func horizonLoadOptionsFromConfig(cfg config.Config) (horizon.LoadOptions, error) {
	return horizonLoadOptionsFromValues(cfg.Capabilities.ManifestSignatureMode, cfg.Capabilities.ManifestSignaturePublicKeys, cfg.Capabilities.ManifestDigestPins)
}

func horizonLoadOptionsFromValues(mode, keyPaths, digestPins string) (horizon.LoadOptions, error) {
	signatureMode, err := horizon.NormalizeSignatureMode(horizon.SignatureMode(mode))
	if err != nil {
		return horizon.LoadOptions{}, err
	}
	var keys []horizon.TrustedPublicKey
	for _, path := range splitCSV(keyPaths) {
		key, err := horizon.LoadTrustedPublicKeyFile(path)
		if err != nil {
			return horizon.LoadOptions{}, err
		}
		keys = append(keys, key)
	}
	if signatureMode == horizon.SignatureRequire && len(keys) == 0 {
		return horizon.LoadOptions{}, fmt.Errorf("manifest signature public keys are required when signature mode is require")
	}
	pins, err := parseManifestDigestPins(digestPins)
	if err != nil {
		return horizon.LoadOptions{}, err
	}
	return horizon.LoadOptions{
		Signature: horizon.SignatureOptions{
			Mode:       signatureMode,
			PublicKeys: keys,
		},
		DigestPins: pins,
	}, nil
}

func parseManifestDigestPins(value string) (map[string]string, error) {
	pins := map[string]string{}
	for _, item := range splitCSV(value) {
		path, digest, ok := strings.Cut(item, "=")
		if !ok {
			return nil, fmt.Errorf("manifest digest pin %q must be path=sha256", item)
		}
		path = strings.TrimSpace(path)
		digest = strings.TrimSpace(digest)
		if path == "" || digest == "" {
			return nil, fmt.Errorf("manifest digest pin %q must be path=sha256", item)
		}
		pins[path] = digest
	}
	return pins, nil
}

type repeatStringFlag []string

func (f *repeatStringFlag) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(*f, ",")
}

func (f *repeatStringFlag) Set(value string) error {
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			*f = append(*f, item)
		}
	}
	return nil
}
