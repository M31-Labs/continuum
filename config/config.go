package config

type Config struct {
	Project      ProjectConfig      `json:"project"`
	Policy       PolicyConfig       `json:"policy"`
	Audit        AuditConfig        `json:"audit"`
	Subject      SubjectConfig      `json:"subject"`
	Capabilities CapabilitiesConfig `json:"capabilities"`
	Enforcement  EnforcementConfig  `json:"enforcement"`
	Approval     ApprovalConfig     `json:"approval"`
}

type ProjectConfig struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type PolicyConfig struct {
	Bundle string `json:"bundle"`
}

type AuditConfig struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

type SubjectConfig struct {
	DefaultKind string `json:"default_kind"`
	DefaultMode string `json:"default_mode"`
}

type CapabilitiesConfig struct {
	HorizonManifestDir string `json:"horizon_manifest_dir"`
}

type EnforcementConfig struct {
	Network string `json:"network"`
	File    string `json:"file"`
	Process string `json:"process"`
}

type ApprovalConfig struct {
	Kind string `json:"kind"`
}

func Default() Config {
	return Config{
		Project: ProjectConfig{Name: "continuum", Version: "0.1.0"},
		Policy:  PolicyConfig{Bundle: "policies/main.arb"},
		Audit:   AuditConfig{Kind: "jsonl", Path: ".continuum/audit.jsonl"},
		Subject: SubjectConfig{DefaultKind: "agent", DefaultMode: "ask"},
		Capabilities: CapabilitiesConfig{
			HorizonManifestDir: ".continuum/capabilities",
		},
		Enforcement: EnforcementConfig{
			Network: "observe",
			File:    "observe",
			Process: "observe",
		},
		Approval: ApprovalConfig{Kind: "cli"},
	}
}
