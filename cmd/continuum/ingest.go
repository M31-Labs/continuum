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
	"m31labs.dev/continuum/horizon"
	cruntime "m31labs.dev/continuum/runtime"
)

func runIngest(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("ingest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "config path")
	daemonURL := fs.String("daemon", "", "daemon base URL for remote ingest")
	daemonToken := fs.String("daemon-token", os.Getenv("CONTINUUM_DAEMON_TOKEN"), "bearer token for daemon ingest")
	policyPath := fs.String("policy", "", "policy path")
	policyStorePath := fs.String("policy-store", ".continuum/policies.json", "policy store")
	eventsPath := fs.String("events", "", "events JSON or JSONL path")
	auditPath := fs.String("audit", ".continuum/audit.jsonl", "audit JSONL path")
	sessionPath := fs.String("sessions", defaultSessionStorePath, "session store for process lifecycle events")
	grantPath := fs.String("grants", ".continuum/grants.json", "grant store")
	deliveryPath := fs.String("delivery-store", defaultDeliveryStorePath, "delivery queue store")
	idStorePath := fs.String("id-store", defaultIDStorePath, "monotonic id store")
	approvalFlag := fs.String("approval", "deny", "approval mode: deny, allow, cli")
	manifestDir := fs.String("manifest-dir", "", "Horizon capability manifest directory for Horizon event envelopes")
	airlockPolicyPath := fs.String("airlock-policy", cruntime.DefaultAirlockPolicyPath, "airlock policy path")
	airlockStorePath := fs.String("airlock-store", defaultAirlockStorePath, "airlock state store")
	airlockAccumulatorStorePath := fs.String("airlock-accumulators", defaultAirlockAccumulatorStorePath, "airlock behavior accumulator store")
	noAirlock := fs.Bool("no-airlock", false, "skip airlock behavior accumulation")
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
	*sessionPath = resolveSessionStorePath(*sessionPath, cfg)
	*grantPath = resolveGrantStorePath(*grantPath, cfg)
	*deliveryPath = resolveDeliveryStorePath(*deliveryPath, cfg)
	*airlockStorePath = resolveAirlockStorePath(*airlockStorePath, cfg)
	*airlockAccumulatorStorePath = resolveAirlockAccumulatorStorePath(*airlockAccumulatorStorePath, cfg)
	*idStorePath = resolveIDStorePath(*idStorePath, cfg)
	maxGrantTTL, err := configuredMaxGrantTTL(cfg)
	if err != nil {
		return err
	}
	resolvedPolicy, err := resolvePolicyPath(*policyPath, *policyStorePath, cfg)
	if err != nil {
		return err
	}
	*auditPath = resolveAuditPath(*auditPath, false, cfg)
	if *manifestDir == "" && cfg.ConfigPath != "<default>" {
		*manifestDir = cfg.Config.Capabilities.HorizonManifestDir
	}
	loadOptions := horizon.LoadOptions{}
	if cfg.ConfigPath != "<default>" {
		loadOptions, err = horizonLoadOptionsFromConfig(cfg.Config)
		if err != nil {
			return err
		}
	}
	if *daemonURL != "" {
		data, err := os.ReadFile(*eventsPath)
		if err != nil {
			return err
		}
		result, err := cruntime.NewClient(*daemonURL).Ingest(context.Background(), data, cruntime.ClientIngestOptions{
			PolicyPath:              resolvedPolicy,
			PolicyStore:             *policyStorePath,
			SessionStore:            *sessionPath,
			GrantStore:              *grantPath,
			DeliveryStore:           *deliveryPath,
			IDStore:                 *idStorePath,
			AuditPath:               *auditPath,
			AuthToken:               *daemonToken,
			AirlockPolicy:           *airlockPolicyPath,
			AirlockStore:            *airlockStorePath,
			AirlockAccumulatorStore: *airlockAccumulatorStorePath,
			NoAirlock:               *noAirlock,
		})
		if err != nil {
			return err
		}
		for _, record := range result.Records {
			printAuditLine(stdout, record)
		}
		for _, result := range result.Airlocks {
			if result.Session == nil {
				continue
			}
			fmt.Fprintf(stdout, "ENTER_AIRLOCK subject=%s reason=%q state=%s audit=%s\n", result.Behavior.Subject, result.Session.Reason, result.Session.State, result.Record.ID)
		}
		fmt.Fprintf(stdout, "ingested=%d process_events=%d audit=%s policy=%s daemon=%s\n", result.Ingested, result.ProcessEvents, result.Audit, result.Policy, *daemonURL)
		return nil
	}
	bundle, err := arbiterx.CompileFile(resolvedPolicy)
	if err != nil {
		return err
	}
	events, err := loadEventsWithHorizonOptions(*eventsPath, *manifestDir, loadOptions)
	if err != nil {
		return err
	}
	sink, err := audit.NewJSONLSink(*auditPath)
	if err != nil {
		return err
	}
	defer sink.Close()
	engine := cruntime.NewEngine(bundle, sink)
	engine.NewID = cruntime.PersistentID(*idStorePath, "evt")
	queue, err := cruntime.LoadDeliveryStore(*deliveryPath)
	if err != nil {
		return err
	}
	engine.Queue = queue
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
		if err := handleAskHuman(context.Background(), approvalMode(*approvalFlag), stdout, sink, record, evt, *grantPath, *idStorePath, maxGrantTTL); err != nil {
			return err
		}
	}
	if err := sink.Close(); err != nil {
		return err
	}
	processEvents := 0
	if err := cruntime.UpdateSessionStore(*sessionPath, func(sessions *cruntime.SessionStore) error {
		var err error
		processEvents, err = sessions.TrackProcessEvents(events, func() time.Time { return time.Now().UTC() })
		return err
	}); err != nil {
		return err
	}
	if !*noAirlock {
		airlocks, err := cruntime.EvaluateAirlockForEvents(context.Background(), events, cruntime.AirlockOptions{
			PolicyPath:           *airlockPolicyPath,
			StorePath:            *airlockStorePath,
			AccumulatorStorePath: *airlockAccumulatorStorePath,
			AuditPath:            *auditPath,
			IDStore:              *idStorePath,
		})
		if err != nil {
			return err
		}
		for _, result := range airlocks {
			if result.Session == nil {
				continue
			}
			fmt.Fprintf(stdout, "ENTER_AIRLOCK subject=%s reason=%q state=%s audit=%s\n", result.Behavior.Subject, result.Session.Reason, result.Session.State, result.Record.ID)
		}
	}
	fmt.Fprintf(stdout, "ingested=%d process_events=%d audit=%s policy=%s deliveries=%s sessions=%s\n", len(events), processEvents, *auditPath, resolvedPolicy, *deliveryPath, *sessionPath)
	return nil
}
