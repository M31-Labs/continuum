package config

import "fmt"

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
