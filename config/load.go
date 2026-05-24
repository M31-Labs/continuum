package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg, err := LoadBytes(data)
	if err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}

func LoadBytes(data []byte) (Config, error) {
	cfg := Default()
	section := ""
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(stripComment(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return Config{}, fmt.Errorf("line %d: expected key = value", lineNo)
		}
		key = strings.TrimSpace(key)
		parsed, err := parseValue(strings.TrimSpace(value))
		if err != nil {
			return Config{}, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if err := assign(&cfg, section, key, parsed); err != nil {
			return Config{}, fmt.Errorf("line %d: %w", lineNo, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return Config{}, err
	}
	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func stripComment(line string) string {
	inString := false
	escaped := false
	for i, r := range line {
		if escaped {
			escaped = false
			continue
		}
		switch r {
		case '\\':
			escaped = true
		case '"':
			inString = !inString
		case '#':
			if !inString {
				return line[:i]
			}
		}
	}
	return line
}

func parseValue(raw string) (string, error) {
	if strings.HasPrefix(raw, "\"") {
		value, err := strconv.Unquote(raw)
		if err != nil {
			return "", err
		}
		return value, nil
	}
	return strings.TrimSpace(raw), nil
}

func assign(cfg *Config, section, key, value string) error {
	switch section {
	case "project":
		switch key {
		case "name":
			cfg.Project.Name = value
		case "version":
			cfg.Project.Version = value
		default:
			return unknown(section, key)
		}
	case "policy":
		if key != "bundle" {
			return unknown(section, key)
		}
		cfg.Policy.Bundle = value
	case "audit":
		switch key {
		case "kind":
			cfg.Audit.Kind = value
		case "path":
			cfg.Audit.Path = value
		default:
			return unknown(section, key)
		}
	case "subject":
		switch key {
		case "default_kind":
			cfg.Subject.DefaultKind = value
		case "default_mode":
			cfg.Subject.DefaultMode = value
		default:
			return unknown(section, key)
		}
	case "capabilities":
		if key != "horizon_manifest_dir" {
			return unknown(section, key)
		}
		cfg.Capabilities.HorizonManifestDir = value
	case "state":
		switch key {
		case "policy_store":
			cfg.State.PolicyStore = value
		case "grant_store":
			cfg.State.GrantStore = value
		case "delivery_store":
			cfg.State.DeliveryStore = value
		case "session_store":
			cfg.State.SessionStore = value
		case "airlock_store":
			cfg.State.AirlockStore = value
		case "airlock_accumulator_store":
			cfg.State.AirlockAccumulatorStore = value
		case "id_store":
			cfg.State.IDStore = value
		default:
			return unknown(section, key)
		}
	case "daemon":
		switch key {
		case "cors_origins":
			cfg.Daemon.CORSOrigins = value
		default:
			return unknown(section, key)
		}
	case "grant":
		switch key {
		case "max_ttl":
			cfg.Grant.MaxTTL = value
		default:
			return unknown(section, key)
		}
	case "enforcement":
		switch key {
		case "network":
			cfg.Enforcement.Network = value
		case "file":
			cfg.Enforcement.File = value
		case "process":
			cfg.Enforcement.Process = value
		default:
			return unknown(section, key)
		}
	case "approval":
		if key != "kind" {
			return unknown(section, key)
		}
		cfg.Approval.Kind = value
	default:
		return fmt.Errorf("unknown section %q", section)
	}
	return nil
}

func unknown(section, key string) error {
	if section == "" {
		return fmt.Errorf("unknown top-level key %q", key)
	}
	return fmt.Errorf("unknown key %q in section [%s]", key, section)
}
