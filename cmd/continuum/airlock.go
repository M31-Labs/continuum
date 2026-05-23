package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"m31labs.dev/continuum/airlock"
	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/event"
	cruntime "m31labs.dev/continuum/runtime"
	"m31labs.dev/continuum/subject"
)

func runAirlock(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError("Usage: continuum airlock status|enter|release|simulate|accumulate")
	}
	switch args[0] {
	case "status":
		fs := flag.NewFlagSet("airlock status", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "continuum.toml", "config path")
		storePath := fs.String("store", defaultAirlockStorePath, "airlock state store")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := loadConfigOrDefault(*configPath)
		if err != nil {
			return err
		}
		*storePath = resolveAirlockStorePath(*storePath, cfg)
		store, err := airlock.LoadStore(*storePath)
		if err != nil {
			return err
		}
		for _, session := range store.List() {
			fmt.Fprintf(stdout, "%s\t%s\t%s\n", session.ID, session.State, session.Reason)
		}
		return nil
	case "enter":
		fs := flag.NewFlagSet("airlock enter", flag.ContinueOnError)
		fs.SetOutput(stderr)
		pid := fs.Int("pid", 0, "pid")
		reason := fs.String("reason", "", "reason")
		configPath := fs.String("config", "continuum.toml", "config path")
		storePath := fs.String("store", defaultAirlockStorePath, "airlock state store")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *pid == 0 {
			return usageError("Usage: continuum airlock enter --pid 1234 --reason <reason>")
		}
		cfg, err := loadConfigOrDefault(*configPath)
		if err != nil {
			return err
		}
		*storePath = resolveAirlockStorePath(*storePath, cfg)
		store, err := airlock.LoadStore(*storePath)
		if err != nil {
			return err
		}
		id := fmt.Sprintf("airlock-%d", time.Now().UnixNano())
		session, err := store.Enter(id, subject.NewProcessTree("manual", *pid), *reason, time.Now().UTC())
		if err != nil {
			return err
		}
		if err := store.Save(*storePath); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "ENTER_AIRLOCK session=%s subject=%s state=%s reason=%q\n", session.ID, session.Subject.String(), session.State, session.Reason)
		return nil
	case "release":
		fs := flag.NewFlagSet("airlock release", flag.ContinueOnError)
		fs.SetOutput(stderr)
		reason := fs.String("reason", "manual release", "reason")
		configPath := fs.String("config", "continuum.toml", "config path")
		storePath := fs.String("store", defaultAirlockStorePath, "airlock state store")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return usageError("Usage: continuum airlock release [--reason reason] <session>")
		}
		cfg, err := loadConfigOrDefault(*configPath)
		if err != nil {
			return err
		}
		*storePath = resolveAirlockStorePath(*storePath, cfg)
		store, err := airlock.LoadStore(*storePath)
		if err != nil {
			return err
		}
		session, err := store.Release(fs.Arg(0), *reason, time.Now().UTC())
		if err != nil {
			return err
		}
		if err := store.Save(*storePath); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "RELEASE_AIRLOCK session=%s state=%s reason=%q\n", session.ID, session.State, session.Reason)
		return nil
	case "simulate":
		fs := flag.NewFlagSet("airlock simulate", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "continuum.toml", "config path")
		fixture := fs.String("fixture", "", "behavior fixture")
		policyPath := fs.String("policy", "examples/airlock/policies/main.arb", "airlock policy")
		auditPath := fs.String("audit", defaultAuditPath, "audit JSONL path")
		storePath := fs.String("store", defaultAirlockStorePath, "airlock state store")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *fixture == "" {
			return usageError("Usage: continuum airlock simulate --fixture testdata/events/worm_fanout.json")
		}
		cfg, err := loadConfigOrDefault(*configPath)
		if err != nil {
			return err
		}
		*storePath = resolveAirlockStorePath(*storePath, cfg)
		*auditPath = resolveAuditPath(*auditPath, false, cfg)
		behavior, err := airlock.LoadBehaviorFixture(*fixture)
		if err != nil {
			return err
		}
		bundle, err := arbiterx.CompileFile(*policyPath)
		if err != nil {
			return err
		}
		sink, err := audit.NewJSONLSink(*auditPath)
		if err != nil {
			return err
		}
		defer sink.Close()
		engine := cruntime.NewEngine(bundle, sink)
		input := event.Event{
			ID:      "evt_airlock_sim",
			Kind:    "behavior.summary",
			Subject: subject.NewProcessTree(behavior.Subject, 0),
			Fields: map[string]any{
				"exec_count":             behavior.ExecCount,
				"unique_network_targets": behavior.UniqueNetworkTargets,
				"touched_secret_paths":   behavior.TouchedSecretPaths,
				"rewritten_files":        behavior.RewrittenFiles,
				"entropy_increase_score": behavior.EntropyIncreaseScore,
			},
		}
		record, decision, err := engine.DecideFacts(context.Background(), input, []arbiterx.Fact{behavior.Fact()})
		if err != nil {
			return err
		}
		if decision.Selected == nil || decision.Selected.Name != arbiterx.OutcomeEnterAirlock {
			fmt.Fprintln(stdout, "NO_AIRLOCK")
			return nil
		}
		store, err := airlock.LoadStore(*storePath)
		if err != nil {
			return err
		}
		session, err := store.Enter("airlock-sim", subject.NewProcessTree(behavior.Subject, 0), decision.Selected.Reason(), time.Now().UTC())
		if err != nil {
			return err
		}
		if err := store.Save(*storePath); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "ENTER_AIRLOCK subject=%s\nreason=%q\nstate=%s\naudit=%s\n", behavior.Subject, session.Reason, session.State, record.ID)
		return nil
	case "accumulate":
		fs := flag.NewFlagSet("airlock accumulate", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "continuum.toml", "config path")
		eventsPath := fs.String("events", "", "events JSON, JSONL, or audit JSONL path")
		manifestDir := fs.String("manifest-dir", "", "Horizon capability manifest directory for Horizon event envelopes")
		subjectName := fs.String("subject", "", "airlock subject override")
		policyPath := fs.String("policy", "examples/airlock/policies/main.arb", "airlock policy")
		auditPath := fs.String("audit", defaultAuditPath, "audit JSONL path")
		storePath := fs.String("store", defaultAirlockStorePath, "airlock state store")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *eventsPath == "" {
			return usageError("Usage: continuum airlock accumulate --events audit.jsonl")
		}
		cfg, err := loadConfigOrDefault(*configPath)
		if err != nil {
			return err
		}
		*storePath = resolveAirlockStorePath(*storePath, cfg)
		*auditPath = resolveAuditPath(*auditPath, false, cfg)
		if *manifestDir == "" && cfg.ConfigPath != "<default>" {
			*manifestDir = cfg.Config.Capabilities.HorizonManifestDir
		}
		events, err := loadEventsWithHorizon(*eventsPath, *manifestDir)
		if err != nil {
			return err
		}
		acc := airlock.NewAccumulator(*subjectName)
		for _, evt := range events {
			acc.Observe(evt)
		}
		behavior := acc.Behavior()
		if behavior.Subject == "" {
			behavior.Subject = "unknown"
		}
		record, decision, err := decideAirlockBehavior(behavior, *policyPath, *auditPath)
		if err != nil {
			return err
		}
		if decision.Selected == nil || decision.Selected.Name != arbiterx.OutcomeEnterAirlock {
			fmt.Fprintf(stdout, "NO_AIRLOCK subject=%s exec_count=%d unique_network_targets=%d rewritten_files=%d audit=%s\n", behavior.Subject, behavior.ExecCount, behavior.UniqueNetworkTargets, behavior.RewrittenFiles, record.ID)
			return nil
		}
		store, err := airlock.LoadStore(*storePath)
		if err != nil {
			return err
		}
		session, err := store.Enter(fmt.Sprintf("airlock-%d", time.Now().UnixNano()), subject.NewProcessTree(behavior.Subject, 0), decision.Selected.Reason(), time.Now().UTC())
		if err != nil {
			return err
		}
		if err := store.Save(*storePath); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "ENTER_AIRLOCK subject=%s\nreason=%q\nstate=%s\naudit=%s\n", behavior.Subject, session.Reason, session.State, record.ID)
		return nil
	default:
		return usageError("Usage: continuum airlock status|enter|release|simulate|accumulate")
	}
}

func decideAirlockBehavior(behavior airlock.Behavior, policyPath, auditPath string) (audit.Event, arbiterx.Decision, error) {
	bundle, err := arbiterx.CompileFile(policyPath)
	if err != nil {
		return audit.Event{}, arbiterx.Decision{}, err
	}
	sink, err := audit.NewJSONLSink(auditPath)
	if err != nil {
		return audit.Event{}, arbiterx.Decision{}, err
	}
	defer sink.Close()
	engine := cruntime.NewEngine(bundle, sink)
	input := event.Event{
		ID:      fmt.Sprintf("evt_airlock_%d", time.Now().UnixNano()),
		Kind:    "behavior.summary",
		Subject: subject.NewProcessTree(behavior.Subject, 0),
		Fields: map[string]any{
			"exec_count":             behavior.ExecCount,
			"unique_network_targets": behavior.UniqueNetworkTargets,
			"touched_secret_paths":   behavior.TouchedSecretPaths,
			"rewritten_files":        behavior.RewrittenFiles,
			"entropy_increase_score": behavior.EntropyIncreaseScore,
		},
	}
	return engine.DecideFacts(context.Background(), input, []arbiterx.Fact{behavior.Fact()})
}
