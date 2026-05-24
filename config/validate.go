package config

import (
	"fmt"
	"strings"
	"time"
)

func Validate(cfg Config) error {
	if cfg.Project.Name == "" {
		return fmt.Errorf("project.name is required")
	}
	if cfg.Policy.Bundle == "" {
		return fmt.Errorf("policy.bundle is required")
	}
	if cfg.Audit.Kind != "jsonl" {
		return fmt.Errorf("audit.kind %q is not supported", cfg.Audit.Kind)
	}
	if cfg.Audit.Path == "" {
		return fmt.Errorf("audit.path is required")
	}
	if cfg.Subject.DefaultKind == "" {
		return fmt.Errorf("subject.default_kind is required")
	}
	if cfg.Approval.Kind == "" {
		return fmt.Errorf("approval.kind is required")
	}
	if cfg.Grant.MaxTTL == "" {
		return fmt.Errorf("grant.max_ttl is required")
	}
	switch cfg.Capabilities.ManifestSignatureMode {
	case "", "off", "warn", "require":
	default:
		return fmt.Errorf("capabilities.manifest_signature_mode %q is not supported", cfg.Capabilities.ManifestSignatureMode)
	}
	if cfg.Capabilities.ManifestSignatureMode == "require" && cfg.Capabilities.ManifestSignaturePublicKeys == "" {
		return fmt.Errorf("capabilities.manifest_signature_public_keys is required when manifest_signature_mode is require")
	}
	for _, pin := range strings.Split(cfg.Capabilities.ManifestDigestPins, ",") {
		pin = strings.TrimSpace(pin)
		if pin == "" {
			continue
		}
		if _, _, ok := strings.Cut(pin, "="); !ok {
			return fmt.Errorf("capabilities.manifest_digest_pins entry %q must be path=sha256", pin)
		}
	}
	maxTTL, err := time.ParseDuration(cfg.Grant.MaxTTL)
	if err != nil {
		return fmt.Errorf("grant.max_ttl %q is invalid: %w", cfg.Grant.MaxTTL, err)
	}
	if maxTTL <= 0 {
		return fmt.Errorf("grant.max_ttl must be positive")
	}
	switch cfg.Approval.Kind {
	case "cli", "server", "allow", "deny":
	default:
		return fmt.Errorf("approval.kind %q is not supported", cfg.Approval.Kind)
	}
	for name, path := range map[string]string{
		"policy_store":              cfg.State.PolicyStore,
		"grant_store":               cfg.State.GrantStore,
		"delivery_store":            cfg.State.DeliveryStore,
		"session_store":             cfg.State.SessionStore,
		"airlock_store":             cfg.State.AirlockStore,
		"airlock_accumulator_store": cfg.State.AirlockAccumulatorStore,
		"id_store":                  cfg.State.IDStore,
	} {
		if path == "" {
			return fmt.Errorf("state.%s is required", name)
		}
	}
	for name, backend := range map[string]string{
		"network": cfg.Enforcement.Network,
		"file":    cfg.Enforcement.File,
		"process": cfg.Enforcement.Process,
	} {
		if backend != "observe" && backend != "noop" {
			return fmt.Errorf("enforcement.%s backend %q is not supported yet", name, backend)
		}
	}
	return nil
}
