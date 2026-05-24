package config

import (
	"path/filepath"
	"strings"
)

func ResolvePath(configPath, value string) string {
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	base := "."
	if configPath != "" && configPath != "<default>" {
		base = filepath.Dir(configPath)
	}
	return filepath.Clean(filepath.Join(base, value))
}

func Resolve(cfg Config, configPath string) Config {
	cfg.Policy.Bundle = ResolvePath(configPath, cfg.Policy.Bundle)
	cfg.Audit.Path = ResolvePath(configPath, cfg.Audit.Path)
	cfg.Capabilities.HorizonManifestDir = ResolvePath(configPath, cfg.Capabilities.HorizonManifestDir)
	cfg.Capabilities.ManifestSignaturePublicKeys = ResolvePathList(configPath, cfg.Capabilities.ManifestSignaturePublicKeys)
	cfg.State.PolicyStore = ResolvePath(configPath, cfg.State.PolicyStore)
	cfg.State.GrantStore = ResolvePath(configPath, cfg.State.GrantStore)
	cfg.State.DeliveryStore = ResolvePath(configPath, cfg.State.DeliveryStore)
	cfg.State.SessionStore = ResolvePath(configPath, cfg.State.SessionStore)
	cfg.State.AirlockStore = ResolvePath(configPath, cfg.State.AirlockStore)
	cfg.State.AirlockAccumulatorStore = ResolvePath(configPath, cfg.State.AirlockAccumulatorStore)
	cfg.State.IDStore = ResolvePath(configPath, cfg.State.IDStore)
	return cfg
}

func ResolvePathList(configPath, value string) string {
	if value == "" {
		return ""
	}
	parts := strings.Split(value, ",")
	for i, part := range parts {
		parts[i] = ResolvePath(configPath, strings.TrimSpace(part))
	}
	return strings.Join(parts, ",")
}
