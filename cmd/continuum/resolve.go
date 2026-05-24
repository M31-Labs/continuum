package main

import (
	"fmt"

	"m31labs.dev/continuum/config"
	"m31labs.dev/continuum/policy"
)

const (
	defaultPolicyStorePath             = ".continuum/policies.json"
	defaultGrantStorePath              = ".continuum/grants.json"
	defaultDeliveryStorePath           = ".continuum/deliveries.json"
	defaultSessionStorePath            = ".continuum/sessions.json"
	defaultAirlockStorePath            = ".continuum/airlock.json"
	defaultAirlockAccumulatorStorePath = ".continuum/airlock-accumulators.json"
	defaultIDStorePath                 = ".continuum/ids.json"
	defaultAuditPath                   = ".continuum/audit.jsonl"
)

type cliConfig struct {
	ConfigPath string
	Config     config.Config
}

func loadOptionalConfig(path string) (cliConfig, error) {
	if path == "" {
		return cliConfig{ConfigPath: "<default>", Config: config.Default()}, nil
	}
	cfg, err := config.Load(path)
	if err != nil {
		return cliConfig{}, err
	}
	return cliConfig{ConfigPath: path, Config: config.Resolve(cfg, path)}, nil
}

func loadConfigOrDefault(path string) (cliConfig, error) {
	if path == "" {
		return loadOptionalConfig("")
	}
	if fileExists(path) {
		return loadOptionalConfig(path)
	}
	if path == "continuum.toml" {
		return cliConfig{ConfigPath: "<default>", Config: config.Default()}, nil
	}
	return cliConfig{}, fmt.Errorf("config %s does not exist", path)
}

func resolvePolicyPath(explicitPath, policyStorePath string, cfg cliConfig) (string, error) {
	if explicitPath != "" {
		return explicitPath, nil
	}
	if policyStorePath != "" {
		store, err := policy.LoadStore(policyStorePath)
		if err != nil {
			return "", err
		}
		if active, ok := store.ActiveBundle(); ok {
			return active.Path, nil
		}
	}
	if cfg.ConfigPath != "<default>" && cfg.Config.Policy.Bundle != "" {
		return cfg.Config.Policy.Bundle, nil
	}
	return "examples/agent-workdir/policies/main.arb", nil
}

func resolveAuditPath(explicitPath string, explicitSet bool, cfg cliConfig) string {
	if explicitSet || explicitPath != "" && explicitPath != defaultAuditPath {
		return explicitPath
	}
	if cfg.Config.Audit.Path != "" {
		return cfg.Config.Audit.Path
	}
	return explicitPath
}

func resolvePolicyStorePath(path string, cfg cliConfig) string {
	if path != "" && path != defaultPolicyStorePath {
		return path
	}
	if cfg.ConfigPath != "<default>" && cfg.Config.State.PolicyStore != "" {
		return cfg.Config.State.PolicyStore
	}
	return path
}

func resolveGrantStorePath(path string, cfg cliConfig) string {
	if path != "" && path != defaultGrantStorePath {
		return path
	}
	if cfg.ConfigPath != "<default>" && cfg.Config.State.GrantStore != "" {
		return cfg.Config.State.GrantStore
	}
	return path
}

func resolveDeliveryStorePath(path string, cfg cliConfig) string {
	if path != "" && path != defaultDeliveryStorePath {
		return path
	}
	if cfg.ConfigPath != "<default>" && cfg.Config.State.DeliveryStore != "" {
		return cfg.Config.State.DeliveryStore
	}
	return path
}

func resolveSessionStorePath(path string, cfg cliConfig) string {
	if path != "" && path != defaultSessionStorePath {
		return path
	}
	if cfg.ConfigPath != "<default>" && cfg.Config.State.SessionStore != "" {
		return cfg.Config.State.SessionStore
	}
	return path
}

func resolveAirlockStorePath(path string, cfg cliConfig) string {
	if path != "" && path != defaultAirlockStorePath {
		return path
	}
	if cfg.ConfigPath != "<default>" && cfg.Config.State.AirlockStore != "" {
		return cfg.Config.State.AirlockStore
	}
	return path
}

func resolveAirlockAccumulatorStorePath(path string, cfg cliConfig) string {
	if path != "" && path != defaultAirlockAccumulatorStorePath {
		return path
	}
	if cfg.ConfigPath != "<default>" && cfg.Config.State.AirlockAccumulatorStore != "" {
		return cfg.Config.State.AirlockAccumulatorStore
	}
	return path
}

func resolveIDStorePath(path string, cfg cliConfig) string {
	if path != "" && path != defaultIDStorePath {
		return path
	}
	if cfg.ConfigPath != "<default>" && cfg.Config.State.IDStore != "" {
		return cfg.Config.State.IDStore
	}
	return path
}
