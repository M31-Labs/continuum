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
		return usageError("Usage: continuum airlock status|enter|release|remediate|note|notes|simulate|accumulate")
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
		idStorePath := fs.String("id-store", defaultIDStorePath, "monotonic id store")
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
		*idStorePath = resolveIDStorePath(*idStorePath, cfg)
		id, err := cruntime.NextIDWithSeparator(*idStorePath, "airlock", "-")
		if err != nil {
			return err
		}
		var session airlock.Session
		if err := airlock.UpdateStore(*storePath, func(store *airlock.Store) error {
			var err error
			session, err = store.Enter(id, subject.NewProcessTree("manual", *pid), *reason, time.Now().UTC())
			return err
		}); err != nil {
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
		auditPath := fs.String("audit", defaultAuditPath, "audit JSONL path")
		idStorePath := fs.String("id-store", defaultIDStorePath, "monotonic id store")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return usageError("Usage: continuum airlock release [--reason reason] [--audit audit.jsonl] <session>")
		}
		cfg, err := loadConfigOrDefault(*configPath)
		if err != nil {
			return err
		}
		*storePath = resolveAirlockStorePath(*storePath, cfg)
		*auditPath = resolveAuditPath(*auditPath, flagSet(fs, "audit"), cfg)
		*idStorePath = resolveIDStorePath(*idStorePath, cfg)
		now := time.Now().UTC()
		auditID, err := cruntime.NextID(*idStorePath, "evt_airlock")
		if err != nil {
			return err
		}
		var session airlock.Session
		var previous airlock.Session
		if err := airlock.UpdateStore(*storePath, func(store *airlock.Store) error {
			var err error
			var ok bool
			previous, ok = store.Get(fs.Arg(0))
			if !ok {
				return fmt.Errorf("airlock session %q not found", fs.Arg(0))
			}
			session, err = store.Release(fs.Arg(0), *reason, now)
			if err != nil {
				return err
			}
			return writeAirlockTransitionAudit(context.Background(), *auditPath, auditID, "release", previous, session, *reason, now)
		}); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "RELEASE_AIRLOCK session=%s state=%s reason=%q audit=%s\n", session.ID, session.State, session.Reason, auditID)
		return nil
	case "remediate":
		fs := flag.NewFlagSet("airlock remediate", flag.ContinueOnError)
		fs.SetOutput(stderr)
		reason := fs.String("reason", "manual remediation", "reason")
		configPath := fs.String("config", "continuum.toml", "config path")
		storePath := fs.String("store", defaultAirlockStorePath, "airlock state store")
		auditPath := fs.String("audit", defaultAuditPath, "audit JSONL path")
		idStorePath := fs.String("id-store", defaultIDStorePath, "monotonic id store")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return usageError("Usage: continuum airlock remediate [--reason reason] [--audit audit.jsonl] <session>")
		}
		cfg, err := loadConfigOrDefault(*configPath)
		if err != nil {
			return err
		}
		*storePath = resolveAirlockStorePath(*storePath, cfg)
		*auditPath = resolveAuditPath(*auditPath, flagSet(fs, "audit"), cfg)
		*idStorePath = resolveIDStorePath(*idStorePath, cfg)
		now := time.Now().UTC()
		auditID, err := cruntime.NextID(*idStorePath, "evt_airlock")
		if err != nil {
			return err
		}
		var session airlock.Session
		var previous airlock.Session
		if err := airlock.UpdateStore(*storePath, func(store *airlock.Store) error {
			var err error
			var ok bool
			previous, ok = store.Get(fs.Arg(0))
			if !ok {
				return fmt.Errorf("airlock session %q not found", fs.Arg(0))
			}
			session, err = store.Remediate(fs.Arg(0), *reason, now)
			if err != nil {
				return err
			}
			return writeAirlockTransitionAudit(context.Background(), *auditPath, auditID, "remediate", previous, session, *reason, now)
		}); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "REMEDIATE_AIRLOCK session=%s state=%s reason=%q audit=%s\n", session.ID, session.State, session.Reason, auditID)
		return nil
	case "note":
		fs := flag.NewFlagSet("airlock note", flag.ContinueOnError)
		fs.SetOutput(stderr)
		operator := fs.String("operator", "operator", "operator label")
		text := fs.String("text", "", "note text")
		noteText := fs.String("note", "", "note text")
		configPath := fs.String("config", "continuum.toml", "config path")
		storePath := fs.String("store", defaultAirlockStorePath, "airlock state store")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *text == "" {
			*text = *noteText
		}
		if fs.NArg() != 1 || *text == "" {
			return usageError("Usage: continuum airlock note --text <note> [--operator name] <session>")
		}
		cfg, err := loadConfigOrDefault(*configPath)
		if err != nil {
			return err
		}
		*storePath = resolveAirlockStorePath(*storePath, cfg)
		var session airlock.Session
		var note airlock.Note
		if err := airlock.UpdateStore(*storePath, func(store *airlock.Store) error {
			var err error
			session, note, err = store.AddNote(fs.Arg(0), *operator, *text, time.Now().UTC())
			return err
		}); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "NOTE_AIRLOCK session=%s notes=%d operator=%q time=%s\n", session.ID, len(session.Notes), note.Operator, note.Time.Format(time.RFC3339))
		return nil
	case "notes":
		fs := flag.NewFlagSet("airlock notes", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "continuum.toml", "config path")
		storePath := fs.String("store", defaultAirlockStorePath, "airlock state store")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return usageError("Usage: continuum airlock notes <session>")
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
		session, ok := store.Get(fs.Arg(0))
		if !ok {
			return fmt.Errorf("airlock session %q not found", fs.Arg(0))
		}
		for _, note := range session.Notes {
			fmt.Fprintf(stdout, "%s\t%s\t%s\n", note.Time.Format(time.RFC3339), note.Operator, note.Text)
		}
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
		var session airlock.Session
		if err := airlock.UpdateStore(*storePath, func(store *airlock.Store) error {
			var err error
			session, err = store.Enter("airlock-sim", subject.NewProcessTree(behavior.Subject, 0), decision.Selected.Reason(), time.Now().UTC())
			return err
		}); err != nil {
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
		var session airlock.Session
		if err := airlock.UpdateStore(*storePath, func(store *airlock.Store) error {
			var err error
			session, err = store.Enter(fmt.Sprintf("airlock-%d", time.Now().UnixNano()), subject.NewProcessTree(behavior.Subject, 0), decision.Selected.Reason(), time.Now().UTC())
			return err
		}); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "ENTER_AIRLOCK subject=%s\nreason=%q\nstate=%s\naudit=%s\n", behavior.Subject, session.Reason, session.State, record.ID)
		return nil
	default:
		return usageError("Usage: continuum airlock status|enter|release|remediate|note|notes|simulate|accumulate")
	}
}

func writeAirlockTransitionAudit(ctx context.Context, path, id, action string, previous, current airlock.Session, reason string, now time.Time) error {
	sink, err := audit.NewJSONLSink(path)
	if err != nil {
		return err
	}
	defer sink.Close()
	return sink.Write(ctx, airlockTransitionAuditEvent(id, action, previous, current, reason, now))
}

func airlockTransitionAuditEvent(id, action string, previous, current airlock.Session, reason string, now time.Time) audit.Event {
	if id == "" {
		id = fmt.Sprintf("evt_airlock_%d", now.UnixNano())
	}
	if reason == "" {
		reason = current.Reason
	}
	rule := "AirlockRelease"
	decision := "release_airlock"
	kind := "airlock.release"
	if action == "remediate" {
		rule = "AirlockRemediation"
		decision = "remediate_airlock"
		kind = "airlock.remediate"
	}
	fields := map[string]any{
		"reason":          reason,
		"session":         current.ID,
		"from_state":      string(previous.State),
		"to_state":        string(current.State),
		"operator_action": action,
	}
	input := event.Event{
		ID:      id + "_input",
		Time:    now,
		Source:  "continuum.airlock",
		Subject: current.Subject,
		Kind:    kind,
		Fields:  fields,
	}
	return audit.Event{
		ID:          id,
		Time:        now,
		Clock:       &audit.ClockMetadata{Source: audit.ClockSourceAirlockCLI, RecordedAt: now, EventTimeSource: audit.EventTimeSourceRecordedClock},
		Subject:     current.Subject,
		InputEvent:  input,
		Policy:      "airlock.operator",
		Outcome:     arbiterx.NewOutcome(arbiterx.OutcomeAudit, rule, fields),
		Decision:    decision,
		Reason:      reason,
		Capability:  "continuum.airlock." + action,
		Enforcement: "observe",
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
