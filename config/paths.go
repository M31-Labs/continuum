package config

import "path/filepath"

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
	cfg.State.PolicyStore = ResolvePath(configPath, cfg.State.PolicyStore)
	cfg.State.GrantStore = ResolvePath(configPath, cfg.State.GrantStore)
	cfg.State.DeliveryStore = ResolvePath(configPath, cfg.State.DeliveryStore)
	cfg.State.SessionStore = ResolvePath(configPath, cfg.State.SessionStore)
	cfg.State.AirlockStore = ResolvePath(configPath, cfg.State.AirlockStore)
	return cfg
}
