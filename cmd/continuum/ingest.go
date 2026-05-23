package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
	cruntime "m31labs.dev/continuum/runtime"
)

func runIngest(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("ingest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "config path")
	policyPath := fs.String("policy", "", "policy path")
	policyStorePath := fs.String("policy-store", ".continuum/policies.json", "policy store")
	eventsPath := fs.String("events", "", "events JSON or JSONL path")
	auditPath := fs.String("audit", ".continuum/audit.jsonl", "audit JSONL path")
	grantPath := fs.String("grants", ".continuum/grants.json", "grant store")
	approvalFlag := fs.String("approval", "deny", "approval mode: deny, allow, cli")
	manifestDir := fs.String("manifest-dir", "", "Horizon capability manifest directory for Horizon event envelopes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *eventsPath == "" {
		return usageError("Usage: continuum ingest --events events.jsonl [--policy policy.arb] [--audit audit.jsonl]")
	}
	cfg, err := loadOptionalConfig(*configPath)
	if err != nil {
		return err
	}
	*policyStorePath = resolvePolicyStorePath(*policyStorePath, cfg)
	*grantPath = resolveGrantStorePath(*grantPath, cfg)
	resolvedPolicy, err := resolvePolicyPath(*policyPath, *policyStorePath, cfg)
	if err != nil {
		return err
	}
	*auditPath = resolveAuditPath(*auditPath, false, cfg)
	if *manifestDir == "" && cfg.ConfigPath != "<default>" {
		*manifestDir = cfg.Config.Capabilities.HorizonManifestDir
	}
	bundle, err := arbiterx.CompileFile(resolvedPolicy)
	if err != nil {
		return err
	}
	events, err := loadEventsWithHorizon(*eventsPath, *manifestDir)
	if err != nil {
		return err
	}
	sink, err := audit.NewJSONLSink(*auditPath)
	if err != nil {
		return err
	}
	defer sink.Close()
	engine := cruntime.NewEngine(bundle, sink)
	if grants, err := capability.LoadGrantStore(*grantPath); err == nil {
		engine.Grants = grants.Active(time.Now().UTC())
	} else if !os.IsNotExist(err) {
		return err
	}
	for _, evt := range events {
		record, _, err := engine.DecideEvent(context.Background(), evt)
		if err != nil {
			return err
		}
		printAuditLine(stdout, record)
		if err := handleAskHuman(context.Background(), approvalMode(*approvalFlag), stdout, record, evt, *grantPath); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "ingested=%d audit=%s policy=%s\n", len(events), *auditPath, resolvedPolicy)
	return nil
}

func runEventsThroughEngine(ctx context.Context, engine *cruntime.Engine, events []event.Event) ([]audit.Event, error) {
	records := make([]audit.Event, 0, len(events))
	for _, evt := range events {
		record, _, err := engine.DecideEvent(ctx, evt)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}
