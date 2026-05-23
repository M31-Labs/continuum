package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"m31labs.dev/continuum/airlock"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/config"
	"m31labs.dev/continuum/horizon"
	"m31labs.dev/continuum/policy"
	cruntime "m31labs.dev/continuum/runtime"
)

func runStatus(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "continuum.toml", "config path")
	policyStorePath := fs.String("policy-store", defaultPolicyStorePath, "policy store")
	grantStorePath := fs.String("grant-store", defaultGrantStorePath, "grant store")
	deliveryStorePath := fs.String("delivery-store", defaultDeliveryStorePath, "delivery queue store")
	airlockStorePath := fs.String("airlock-store", defaultAirlockStorePath, "airlock state store")
	sessionStorePath := fs.String("session-store", defaultSessionStorePath, "session store")
	auditPath := fs.String("audit", defaultAuditPath, "audit JSONL path")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError("Usage: continuum status [--config continuum.toml] [--json]")
	}
	snapshot, err := loadStatusSnapshot(*configPath, *policyStorePath, *grantStorePath, *deliveryStorePath, *airlockStorePath, *sessionStorePath, *auditPath)
	if err != nil {
		return err
	}
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(snapshot)
	}
	fmt.Fprintf(stdout, "continuum: pre-alpha project=%s\n", snapshot.Project)
	fmt.Fprintf(stdout, "policy: active=%s bundles=%d\n", snapshot.ActivePolicy, snapshot.PolicyBundles)
	fmt.Fprintf(stdout, "capabilities: total=%d sources=%d sinks=%d workers=%d privileged=%d\n",
		snapshot.Health.Capabilities, snapshot.Health.SourceCount, snapshot.Health.SinkCount, snapshot.Health.WorkerCount, snapshot.Health.PrivilegedCount)
	fmt.Fprintf(stdout, "state: active_grants=%d deliveries=%d pending_deliveries=%d failed_deliveries=%d airlocks=%d running_sessions=%d sessions=%d audit_events=%d\n", snapshot.ActiveGrants, snapshot.Deliveries, snapshot.PendingDeliveries, snapshot.FailedDeliveries, snapshot.AirlockSessions, snapshot.RunningSessions, snapshot.Sessions, snapshot.AuditEvents)
	fmt.Fprintf(stdout, "enforcement: file=%s network=%s process=%s\n", snapshot.Enforcement.File, snapshot.Enforcement.Network, snapshot.Enforcement.Process)
	return nil
}

type statusSnapshot struct {
	Project           string                   `json:"project"`
	ConfigPath        string                   `json:"config_path"`
	PolicyBundles     int                      `json:"policy_bundles"`
	ActivePolicy      string                   `json:"active_policy,omitempty"`
	ActiveGrants      int                      `json:"active_grants"`
	Deliveries        int                      `json:"deliveries"`
	PendingDeliveries int                      `json:"pending_deliveries"`
	FailedDeliveries  int                      `json:"failed_deliveries"`
	AirlockSessions   int                      `json:"airlock_sessions"`
	Sessions          int                      `json:"sessions"`
	RunningSessions   int                      `json:"running_sessions"`
	AuditEvents       int                      `json:"audit_events"`
	Health            cruntime.Health          `json:"health"`
	Enforcement       config.EnforcementConfig `json:"enforcement"`
}

func loadStatusSnapshot(configPath, policyStorePath, grantStorePath, deliveryStorePath, airlockStorePath, sessionStorePath, auditPath string) (statusSnapshot, error) {
	cfg, configUsed, err := loadStatusConfig(configPath)
	if err != nil {
		return statusSnapshot{}, err
	}
	cfg = config.Resolve(cfg, configUsed)
	cliCfg := cliConfig{ConfigPath: configUsed, Config: cfg}
	policyStorePath = resolvePolicyStorePath(policyStorePath, cliCfg)
	grantStorePath = resolveGrantStorePath(grantStorePath, cliCfg)
	deliveryStorePath = resolveDeliveryStorePath(deliveryStorePath, cliCfg)
	airlockStorePath = resolveAirlockStorePath(airlockStorePath, cliCfg)
	sessionStorePath = resolveSessionStorePath(sessionStorePath, cliCfg)
	auditPath = resolveAuditPath(auditPath, false, cliCfg)
	daemon := cruntime.NewDaemon(horizon.DirProvider{Dir: cfg.Capabilities.HorizonManifestDir})
	if err := daemon.Start(context.Background()); err != nil {
		return statusSnapshot{}, err
	}
	policies, err := policy.LoadStore(policyStorePath)
	if err != nil {
		return statusSnapshot{}, err
	}
	grants, err := capability.LoadGrantStore(grantStorePath)
	if err != nil {
		return statusSnapshot{}, err
	}
	deliveries, err := cruntime.LoadDeliveryStore(deliveryStorePath)
	if err != nil {
		return statusSnapshot{}, err
	}
	airlocks, err := airlock.LoadStore(airlockStorePath)
	if err != nil {
		return statusSnapshot{}, err
	}
	sessions, err := cruntime.LoadSessionStore(sessionStorePath)
	if err != nil {
		return statusSnapshot{}, err
	}
	auditEvents := 0
	if fileExists(auditPath) {
		events, err := audit.ReadJSONL(auditPath)
		if err != nil {
			return statusSnapshot{}, err
		}
		auditEvents = len(events)
	}
	activePolicy := ""
	if active, ok := policies.ActiveBundle(); ok {
		activePolicy = active.Name
	}
	return statusSnapshot{
		Project:           cfg.Project.Name,
		ConfigPath:        configUsed,
		PolicyBundles:     len(policies.Bundles),
		ActivePolicy:      activePolicy,
		ActiveGrants:      len(grants.Active(time.Now().UTC())),
		Deliveries:        len(deliveries.List()),
		PendingDeliveries: len(deliveries.ByStatus(cruntime.DeliveryPending)),
		FailedDeliveries:  len(deliveries.ByStatus(cruntime.DeliveryFailed)),
		AirlockSessions:   len(airlocks.List()),
		Sessions:          len(sessions.Sessions),
		RunningSessions:   len(sessions.Running()),
		AuditEvents:       auditEvents,
		Health:            daemon.Health(),
		Enforcement:       cfg.Enforcement,
	}, nil
}

func loadStatusConfig(path string) (config.Config, string, error) {
	if fileExists(path) {
		cfg, err := config.Load(path)
		return cfg, path, err
	}
	if path != "continuum.toml" {
		return config.Config{}, path, fmt.Errorf("config %s does not exist", path)
	}
	return config.Default(), "<default>", nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
