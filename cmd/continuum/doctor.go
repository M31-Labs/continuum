package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"m31labs.dev/continuum/airlock"
	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/config"
	"m31labs.dev/continuum/horizon"
	"m31labs.dev/continuum/policy"
	cruntime "m31labs.dev/continuum/runtime"
)

type doctorStatus string

const (
	doctorOK   doctorStatus = "ok"
	doctorWarn doctorStatus = "warn"
	doctorFail doctorStatus = "fail"
)

type doctorReport struct {
	OK         bool          `json:"ok"`
	ConfigPath string        `json:"config_path"`
	Project    string        `json:"project,omitempty"`
	Checks     []doctorCheck `json:"checks"`
	Warnings   int           `json:"warnings"`
	Failures   int           `json:"failures"`
}

type doctorCheck struct {
	Name    string       `json:"name"`
	Status  doctorStatus `json:"status"`
	Message string       `json:"message"`
	Path    string       `json:"path,omitempty"`
}

type doctorOptions struct {
	ConfigPath                  string
	PolicyPath                  string
	ManifestDir                 string
	PolicyStorePath             string
	GrantStorePath              string
	DeliveryStorePath           string
	AirlockStorePath            string
	AirlockAccumulatorStorePath string
	SessionStorePath            string
	IDStorePath                 string
	AuditPath                   string
}

func runDoctor(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	opts := doctorOptions{}
	fs.StringVar(&opts.ConfigPath, "config", "continuum.toml", "config path")
	fs.StringVar(&opts.PolicyPath, "policy", "", "policy bundle path override")
	fs.StringVar(&opts.ManifestDir, "manifest-dir", "", "Horizon manifest directory override")
	fs.StringVar(&opts.PolicyStorePath, "policy-store", defaultPolicyStorePath, "policy store")
	fs.StringVar(&opts.GrantStorePath, "grant-store", defaultGrantStorePath, "grant store")
	fs.StringVar(&opts.DeliveryStorePath, "delivery-store", defaultDeliveryStorePath, "delivery queue store")
	fs.StringVar(&opts.AirlockStorePath, "airlock-store", defaultAirlockStorePath, "airlock state store")
	fs.StringVar(&opts.AirlockAccumulatorStorePath, "airlock-accumulators", defaultAirlockAccumulatorStorePath, "airlock behavior accumulator store")
	fs.StringVar(&opts.SessionStorePath, "session-store", defaultSessionStorePath, "session store")
	fs.StringVar(&opts.IDStorePath, "id-store", defaultIDStorePath, "monotonic id store")
	fs.StringVar(&opts.AuditPath, "audit", defaultAuditPath, "audit JSONL path")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError("Usage: continuum doctor [--config continuum.toml] [--json]")
	}

	report := buildDoctorReport(opts)
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		printDoctorReport(stdout, report)
	}
	if !report.OK {
		return fmt.Errorf("doctor found %d failing check(s)", report.Failures)
	}
	return nil
}

func buildDoctorReport(opts doctorOptions) doctorReport {
	report := doctorReport{OK: true, ConfigPath: opts.ConfigPath}
	cfg, configUsed, err := loadStatusConfig(opts.ConfigPath)
	if err != nil {
		report.add(doctorFail, "config", err.Error(), opts.ConfigPath)
		return report
	}
	if configUsed == "<default>" {
		report.ConfigPath = configUsed
		report.add(doctorWarn, "config", "continuum.toml not found; using built-in defaults", opts.ConfigPath)
	} else {
		report.ConfigPath = configUsed
		report.add(doctorOK, "config", "loaded config", configUsed)
	}
	cfg = config.Resolve(cfg, configUsed)
	if opts.ManifestDir != "" {
		cfg.Capabilities.HorizonManifestDir = opts.ManifestDir
	}
	cliCfg := cliConfig{ConfigPath: configUsed, Config: cfg}
	report.Project = cfg.Project.Name
	report.add(doctorOK, "project", fmt.Sprintf("project=%s", cfg.Project.Name), "")
	report.add(doctorOK, "grant max ttl", fmt.Sprintf("max_ttl=%s", cfg.Grant.MaxTTL), "")

	policyStorePath := resolvePolicyStorePath(opts.PolicyStorePath, cliCfg)
	grantStorePath := resolveGrantStorePath(opts.GrantStorePath, cliCfg)
	deliveryStorePath := resolveDeliveryStorePath(opts.DeliveryStorePath, cliCfg)
	airlockStorePath := resolveAirlockStorePath(opts.AirlockStorePath, cliCfg)
	airlockAccumulatorStorePath := resolveAirlockAccumulatorStorePath(opts.AirlockAccumulatorStorePath, cliCfg)
	sessionStorePath := resolveSessionStorePath(opts.SessionStorePath, cliCfg)
	idStorePath := resolveIDStorePath(opts.IDStorePath, cliCfg)
	auditPath := resolveAuditPath(opts.AuditPath, opts.AuditPath != defaultAuditPath, cliCfg)

	policyPath, err := resolvePolicyPath(opts.PolicyPath, policyStorePath, cliCfg)
	if err != nil {
		report.add(doctorFail, "policy bundle", fmt.Sprintf("cannot resolve policy bundle: %v", err), "")
	} else {
		report.checkPolicy(policyPath, cfg.Capabilities.HorizonManifestDir)
	}
	report.checkCapabilities(cfg.Capabilities.HorizonManifestDir)

	seenParents := map[string]bool{}
	report.checkPolicyStore(policyStorePath, seenParents)
	report.checkGrantStore(grantStorePath, seenParents)
	report.checkDeliveryStore(deliveryStorePath, seenParents)
	report.checkAirlockStore(airlockStorePath, seenParents)
	report.checkAirlockAccumulatorStore(airlockAccumulatorStorePath, seenParents)
	report.checkSessionStore(sessionStorePath, seenParents)
	report.checkIDStore(idStorePath, seenParents)
	report.checkAuditLog(auditPath, seenParents)
	report.checkEnforcement(cfg.Enforcement)
	return report
}

func (r *doctorReport) checkPolicy(path, manifestDir string) {
	if path == "" {
		r.add(doctorFail, "policy bundle", "policy bundle path is required", "")
		return
	}
	if _, err := os.Stat(path); err != nil {
		r.add(doctorFail, "policy bundle", fmt.Sprintf("policy bundle is not readable: %v", err), path)
		return
	}
	bundle, err := arbiterx.CompileFile(path)
	if err != nil {
		r.add(doctorFail, "policy bundle", fmt.Sprintf("policy compile failed: %v", err), path)
		return
	}
	r.add(doctorOK, "policy bundle", fmt.Sprintf("compiled policy id=%s kind=%s", bundle.ID, bundle.Kind), path)
	inputs, err := arbiterx.ValidatePolicyInputs(bundle)
	if err != nil {
		r.add(doctorFail, "policy inputs", err.Error(), path)
		return
	}
	r.add(doctorOK, "policy inputs", fmt.Sprintf("validated fields=%d", len(inputs.Fields)), path)
	registry, err := loadCapabilityRegistry(context.Background(), manifestDir)
	if err != nil {
		r.add(doctorFail, "policy routes", fmt.Sprintf("capability load failed: %v", err), manifestDir)
		return
	}
	routes, err := cruntime.ValidateOutcomeRoutes(bundle, registry)
	if err != nil {
		r.add(doctorFail, "policy routes", err.Error(), path)
		return
	}
	r.add(doctorOK, "policy routes", fmt.Sprintf("validated routes=%d", len(routes.Routes)), path)
}

func (r *doctorReport) checkCapabilities(manifestDir string) {
	if manifestDir == "" {
		r.add(doctorWarn, "capabilities", "Horizon manifest directory is empty; only built-ins will be registered", "")
		return
	}
	if st, err := os.Stat(manifestDir); err != nil {
		if os.IsNotExist(err) {
			r.add(doctorWarn, "capabilities", "Horizon manifest directory does not exist; only built-ins will be registered", manifestDir)
		} else {
			r.add(doctorFail, "capabilities", fmt.Sprintf("cannot stat Horizon manifest directory: %v", err), manifestDir)
		}
		return
	} else if !st.IsDir() {
		r.add(doctorFail, "capabilities", "Horizon manifest path is not a directory", manifestDir)
		return
	}
	daemon := cruntime.NewDaemon(horizon.DirProvider{Dir: manifestDir})
	if err := daemon.Start(context.Background()); err != nil {
		r.add(doctorFail, "capabilities", fmt.Sprintf("capability load failed: %v", err), manifestDir)
		return
	}
	health := daemon.Health()
	r.add(doctorOK, "capabilities", fmt.Sprintf("registered=%d sources=%d sinks=%d workers=%d", health.Capabilities, health.SourceCount, health.SinkCount, health.WorkerCount), manifestDir)
}

func (r *doctorReport) checkPolicyStore(path string, seenParents map[string]bool) {
	r.checkPrivateStateFile("policy store", path, seenParents)
	store, err := policy.LoadStore(path)
	if err != nil {
		r.add(doctorFail, "policy store", fmt.Sprintf("cannot read policy store: %v", err), path)
		return
	}
	if active, ok := store.ActiveBundle(); ok {
		if _, err := os.Stat(active.Path); err != nil {
			r.add(doctorFail, "active policy", fmt.Sprintf("active policy bundle is not readable: %v", err), active.Path)
			return
		}
		r.add(doctorOK, "active policy", fmt.Sprintf("active=%s", active.Name), active.Path)
		return
	}
	r.add(doctorWarn, "active policy", "no active policy bundle is published yet", path)
}

func (r *doctorReport) checkGrantStore(path string, seenParents map[string]bool) {
	r.checkPrivateStateFile("grant store", path, seenParents)
	store, err := capability.LoadGrantStore(path)
	if err != nil {
		r.add(doctorFail, "grant store", fmt.Sprintf("cannot read grant store: %v", err), path)
		return
	}
	r.add(doctorOK, "grant store", fmt.Sprintf("grants=%d", len(store.Grants)), path)
}

func (r *doctorReport) checkDeliveryStore(path string, seenParents map[string]bool) {
	r.checkPrivateStateFile("delivery store", path, seenParents)
	store, err := cruntime.LoadDeliveryStore(path)
	if err != nil {
		r.add(doctorFail, "delivery store", fmt.Sprintf("cannot read delivery store: %v", err), path)
		return
	}
	r.add(doctorOK, "delivery store", fmt.Sprintf("deliveries=%d", len(store.List())), path)
}

func (r *doctorReport) checkAirlockStore(path string, seenParents map[string]bool) {
	r.checkPrivateStateFile("airlock store", path, seenParents)
	store, err := airlock.LoadStore(path)
	if err != nil {
		r.add(doctorFail, "airlock store", fmt.Sprintf("cannot read airlock store: %v", err), path)
		return
	}
	r.add(doctorOK, "airlock store", fmt.Sprintf("sessions=%d", len(store.List())), path)
}

func (r *doctorReport) checkAirlockAccumulatorStore(path string, seenParents map[string]bool) {
	r.checkPrivateStateFile("airlock accumulator store", path, seenParents)
	store, err := airlock.LoadAccumulatorStore(path)
	if err != nil {
		r.add(doctorFail, "airlock accumulator store", fmt.Sprintf("cannot read airlock accumulator store: %v", err), path)
		return
	}
	r.add(doctorOK, "airlock accumulator store", fmt.Sprintf("subjects=%d", len(store.List())), path)
}

func (r *doctorReport) checkSessionStore(path string, seenParents map[string]bool) {
	r.checkPrivateStateFile("session store", path, seenParents)
	store, err := cruntime.LoadSessionStore(path)
	if err != nil {
		r.add(doctorFail, "session store", fmt.Sprintf("cannot read session store: %v", err), path)
		return
	}
	r.add(doctorOK, "session store", fmt.Sprintf("sessions=%d running=%d", len(store.Sessions), len(store.Running())), path)
}

func (r *doctorReport) checkIDStore(path string, seenParents map[string]bool) {
	r.checkPrivateStateFile("id store", path, seenParents)
	store, err := cruntime.LoadIDStore(path)
	if err != nil {
		r.add(doctorFail, "id store", fmt.Sprintf("cannot read id store: %v", err), path)
		return
	}
	r.add(doctorOK, "id store", fmt.Sprintf("counters=%d", len(store.Counters)), path)
}

func (r *doctorReport) checkAuditLog(path string, seenParents map[string]bool) {
	exists := r.checkPrivateStateFile("audit log", path, seenParents)
	if !exists {
		return
	}
	events, err := audit.ReadJSONL(path)
	if err != nil {
		r.add(doctorFail, "audit log", fmt.Sprintf("cannot read audit log: %v", err), path)
		return
	}
	r.add(doctorOK, "audit log", fmt.Sprintf("events=%d", len(events)), path)
}

func (r *doctorReport) checkEnforcement(cfg config.EnforcementConfig) {
	r.add(doctorOK, "enforcement", fmt.Sprintf("file=%s network=%s process=%s", cfg.File, cfg.Network, cfg.Process), "")
	if cfg.File != "observe" || cfg.Network != "observe" || cfg.Process != "observe" {
		r.add(doctorWarn, "enforcement boundary", "non-observe backend configured; verify this is not claiming kernel enforcement", "")
	}
}

func (r *doctorReport) checkPrivateStateFile(name, path string, seenParents map[string]bool) bool {
	if path == "" {
		r.add(doctorFail, name, "path is required", "")
		return false
	}
	r.checkPrivateWritableParent(name+" parent", filepath.Dir(path), seenParents)
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			r.add(doctorWarn, name, "state file does not exist yet; it will be created on first write", path)
			return false
		}
		r.add(doctorFail, name, fmt.Sprintf("cannot stat path: %v", err), path)
		return false
	}
	if st.IsDir() {
		r.add(doctorFail, name, "path is a directory, expected a file", path)
		return false
	}
	mode := st.Mode().Perm()
	if mode&0077 != 0 {
		r.add(doctorFail, name, fmt.Sprintf("file permissions %04o expose group/other bits; expected private 0600-style state", mode), path)
		return true
	}
	r.add(doctorOK, name, fmt.Sprintf("private file permissions %04o", mode), path)
	return true
}

func (r *doctorReport) checkPrivateWritableParent(name, dir string, seen map[string]bool) {
	if dir == "" {
		return
	}
	dir = filepath.Clean(dir)
	if seen[dir] {
		return
	}
	seen[dir] = true
	st, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			r.add(doctorWarn, name, "directory does not exist yet; Continuum will create it with private permissions on write", dir)
		} else {
			r.add(doctorFail, name, fmt.Sprintf("cannot stat directory: %v", err), dir)
		}
		return
	}
	if !st.IsDir() {
		r.add(doctorFail, name, "parent path is not a directory", dir)
		return
	}
	mode := st.Mode().Perm()
	if mode&0200 == 0 {
		r.add(doctorFail, name, fmt.Sprintf("directory permissions %04o are not owner-writable", mode), dir)
		return
	}
	if mode&0077 != 0 {
		r.add(doctorWarn, name, fmt.Sprintf("directory permissions %04o are not private; state writes will tighten managed directories", mode), dir)
		return
	}
	r.add(doctorOK, name, fmt.Sprintf("private writable directory %04o", mode), dir)
}

func (r *doctorReport) add(status doctorStatus, name, message, path string) {
	r.Checks = append(r.Checks, doctorCheck{Name: name, Status: status, Message: message, Path: path})
	switch status {
	case doctorFail:
		r.OK = false
		r.Failures++
	case doctorWarn:
		r.Warnings++
	}
}

func printDoctorReport(w io.Writer, report doctorReport) {
	state := "ok"
	if !report.OK {
		state = "failed"
	}
	fmt.Fprintf(w, "continuum doctor: %s project=%s config=%s\n", state, report.Project, report.ConfigPath)
	for _, check := range report.Checks {
		if check.Path != "" {
			fmt.Fprintf(w, "%-4s %s: %s (%s)\n", string(check.Status), check.Name, check.Message, check.Path)
			continue
		}
		fmt.Fprintf(w, "%-4s %s: %s\n", string(check.Status), check.Name, check.Message)
	}
	fmt.Fprintf(w, "summary: checks=%d warnings=%d failures=%d\n", len(report.Checks), report.Warnings, report.Failures)
}
