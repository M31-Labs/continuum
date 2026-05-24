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
	return horizonLoadOptionsFromValues(cfg.Capabilities.ManifestSignatureMode, cfg.Capabilities.ManifestSignaturePublicKeys)
}

func horizonLoadOptionsFromValues(mode, keyPaths string) (horizon.LoadOptions, error) {
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
	return horizon.LoadOptions{
		Signature: horizon.SignatureOptions{
			Mode:       signatureMode,
			PublicKeys: keys,
		},
	}, nil
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
