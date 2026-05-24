package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	statepkg "m31labs.dev/continuum/state"
)

func runState(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError("Usage: continuum state export|backup|import")
	}
	switch args[0] {
	case "export":
		return runStateExport(args[1:], stdout, stderr, false)
	case "backup":
		return runStateExport(args[1:], stdout, stderr, true)
	case "import":
		return runStateImport(args[1:], stdout, stderr)
	default:
		return usageError("Usage: continuum state export|backup|import")
	}
}

func runStateExport(args []string, stdout, stderr io.Writer, backup bool) error {
	name := "state export"
	usage := "Usage: continuum state export --out continuum-state.json [--strict]"
	if backup {
		name = "state backup"
		usage = "Usage: continuum state backup [--out .continuum/backups/state-<timestamp>.json] [--strict]"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "continuum.toml", "config path")
	pathFlags := addStatePathFlags(fs)
	outPath := fs.String("out", "", "state archive output path")
	strict := fs.Bool("strict", false, "fail if any state file is missing")
	jsonOut := fs.Bool("json", false, "emit JSON report")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError(usage)
	}
	now := time.Now().UTC()
	if backup && *outPath == "" {
		*outPath = defaultStateBackupPath(now)
	}
	if *outPath == "" {
		return usageError(usage)
	}
	cfg, err := loadConfigOrDefault(*configPath)
	if err != nil {
		return err
	}
	archive, report, err := statepkg.ExportArchive(statepkg.ExportOptions{
		Paths:     resolveStatePaths(pathFlags, fs, cfg),
		CreatedAt: now,
		Strict:    *strict,
	})
	if err != nil {
		return err
	}
	if err := statepkg.WriteArchive(*outPath, archive); err != nil {
		return err
	}
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Path string `json:"path"`
			statepkg.ExportReport
		}{Path: *outPath, ExportReport: report})
	}
	verb := "exported"
	if backup {
		verb = "backed up"
	}
	fmt.Fprintf(stdout, "%s state items=%d bytes=%d missing=%d out=%s\n", verb, report.Items, report.Bytes, len(report.Missing), *outPath)
	return nil
}

func runStateImport(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("state import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "continuum.toml", "config path")
	pathFlags := addStatePathFlags(fs)
	inPath := fs.String("in", "", "state archive input path")
	force := fs.Bool("force", false, "overwrite existing state files after preserving pre-import copies")
	dryRun := fs.Bool("dry-run", false, "validate archive and report import targets without writing")
	jsonOut := fs.Bool("json", false, "emit JSON report")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *inPath == "" {
		return usageError("Usage: continuum state import --in continuum-state.json [--force] [--dry-run]")
	}
	cfg, err := loadConfigOrDefault(*configPath)
	if err != nil {
		return err
	}
	archive, err := statepkg.ReadArchive(*inPath)
	if err != nil {
		return err
	}
	report, err := statepkg.ImportArchive(archive, statepkg.ImportOptions{
		Paths:  resolveStatePaths(pathFlags, fs, cfg),
		Now:    time.Now().UTC(),
		Force:  *force,
		DryRun: *dryRun,
	})
	if err != nil {
		return err
	}
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	if *dryRun {
		fmt.Fprintf(stdout, "checked state archive items=%d would_import=%d in=%s\n", len(report.Items), report.WouldImport, *inPath)
		return nil
	}
	fmt.Fprintf(stdout, "imported state items=%d overwritten=%d in=%s\n", report.Imported, report.Overwritten, *inPath)
	return nil
}

type statePathFlags struct {
	policyStore             *string
	grantStore              *string
	deliveryStore           *string
	sessionStore            *string
	airlockStore            *string
	airlockAccumulatorStore *string
	idStore                 *string
	audit                   *string
}

func addStatePathFlags(fs *flag.FlagSet) statePathFlags {
	return statePathFlags{
		policyStore:             fs.String("policy-store", defaultPolicyStorePath, "policy store"),
		grantStore:              fs.String("grant-store", defaultGrantStorePath, "grant store"),
		deliveryStore:           fs.String("delivery-store", defaultDeliveryStorePath, "delivery queue store"),
		sessionStore:            fs.String("session-store", defaultSessionStorePath, "session store"),
		airlockStore:            fs.String("airlock-store", defaultAirlockStorePath, "airlock state store"),
		airlockAccumulatorStore: fs.String("airlock-accumulators", defaultAirlockAccumulatorStorePath, "airlock behavior accumulator store"),
		idStore:                 fs.String("id-store", defaultIDStorePath, "monotonic id store"),
		audit:                   fs.String("audit", defaultAuditPath, "audit JSONL path"),
	}
}

func resolveStatePaths(flags statePathFlags, fs *flag.FlagSet, cfg cliConfig) statepkg.Paths {
	return statepkg.Paths{
		PolicyStore:             resolvePolicyStorePath(*flags.policyStore, cfg),
		GrantStore:              resolveGrantStorePath(*flags.grantStore, cfg),
		DeliveryStore:           resolveDeliveryStorePath(*flags.deliveryStore, cfg),
		SessionStore:            resolveSessionStorePath(*flags.sessionStore, cfg),
		AirlockStore:            resolveAirlockStorePath(*flags.airlockStore, cfg),
		AirlockAccumulatorStore: resolveAirlockAccumulatorStorePath(*flags.airlockAccumulatorStore, cfg),
		IDStore:                 resolveIDStorePath(*flags.idStore, cfg),
		AuditLog:                resolveAuditPath(*flags.audit, flagSet(fs, "audit"), cfg),
	}
}

func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(flag *flag.Flag) {
		if flag.Name == name {
			set = true
		}
	})
	return set
}

func defaultStateBackupPath(now time.Time) string {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return ".continuum/backups/state-" + now.UTC().Format("20060102T150405Z") + ".json"
}
