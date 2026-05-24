package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
	cruntime "m31labs.dev/continuum/runtime"
	"m31labs.dev/continuum/subject"
)

func runRun(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	agent := fs.String("agent", "", "agent name")
	repo := fs.String("repo", ".", "repo root")
	configPath := fs.String("config", "", "config path")
	policyPath := fs.String("policy", "", "policy path")
	policyStorePath := fs.String("policy-store", ".continuum/policies.json", "policy store")
	auditPath := fs.String("audit", ".continuum/audit.jsonl", "audit JSONL path")
	grantPath := fs.String("grants", ".continuum/grants.json", "grant store")
	deliveryPath := fs.String("delivery-store", defaultDeliveryStorePath, "delivery queue store")
	sessionPath := fs.String("sessions", ".continuum/sessions.json", "session store")
	approvalFlag := fs.String("approval", "deny", "approval mode: deny, allow, cli")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) > 0 && rest[0] == "--" {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return usageError("Usage: continuum run --agent <name> --repo <path> [--policy <file>] -- <command> [args...]")
	}
	if *agent == "" {
		return fmt.Errorf("--agent is required")
	}
	cfg, err := loadOptionalConfig(*configPath)
	if err != nil {
		return err
	}
	*policyStorePath = resolvePolicyStorePath(*policyStorePath, cfg)
	*grantPath = resolveGrantStorePath(*grantPath, cfg)
	*deliveryPath = resolveDeliveryStorePath(*deliveryPath, cfg)
	*sessionPath = resolveSessionStorePath(*sessionPath, cfg)
	maxGrantTTL, err := configuredMaxGrantTTL(cfg)
	if err != nil {
		return err
	}
	absRepo, err := filepath.Abs(*repo)
	if err != nil {
		return err
	}
	session := fmt.Sprintf("agent-session-%d", time.Now().UnixNano())
	resolvedPolicy, err := resolvePolicyPath(*policyPath, *policyStorePath, cfg)
	if err != nil {
		return err
	}
	*auditPath = resolveAuditPath(*auditPath, false, cfg)
	bundle, err := arbiterx.CompileFile(resolvedPolicy)
	if err != nil {
		return err
	}
	sink, err := audit.NewJSONLSink(*auditPath)
	if err != nil {
		return err
	}
	defer sink.Close()
	engine := cruntime.NewEngine(bundle, sink)
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

	fmt.Fprintf(stdout, "continuum: session=%s subject=agent:%s repo=%s enforcement=observe policy=%s\n", session, *agent, absRepo, resolvedPolicy)
	cmd := exec.Command(rest[0], rest[1:]...)
	cmd.Env = append(os.Environ(),
		"CONTINUUM_SESSION="+session,
		"CONTINUUM_AGENT="+*agent,
		"CONTINUUM_REPO="+absRepo,
		"CONTINUUM_POLICY="+resolvedPolicy,
	)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", strings.Join(rest, " "), err)
	}
	subj := subject.NewAgent(*agent, session, absRepo, strings.Join(rest, " "), cmd.Process.Pid)
	if cgroup, err := subject.CgroupForPID(cmd.Process.Pid); err == nil {
		subj.Cgroup = cgroup
	}
	started := time.Now().UTC()
	startSession := cruntime.Session{
		ID:              session,
		Subject:         subj,
		Command:         append([]string(nil), rest...),
		Policy:          resolvedPolicy,
		AuditPath:       *auditPath,
		State:           cruntime.SessionRunning,
		ProcessTree:     cruntime.NewProcessLifecycleTree(subj, rest, started),
		StartedAt:       started,
		LastHeartbeatAt: started,
	}
	if err := cruntime.UpdateSessionStore(*sessionPath, func(sessions *cruntime.SessionStore) error {
		sessions.Upsert(startSession)
		return nil
	}); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return err
	}
	for _, evt := range syntheticCommandEvents(subj, absRepo, rest) {
		if err := cruntime.UpdateSessionStore(*sessionPath, func(sessions *cruntime.SessionStore) error {
			_, _, err := sessions.TrackProcessEvent(evt, time.Now().UTC())
			return err
		}); err != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			return err
		}
		record, _, err := engine.DecideEvent(context.Background(), evt)
		if err != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			return err
		}
		printAuditLine(stdout, record)
		if err := handleAskHuman(context.Background(), approvalMode(*approvalFlag), stdout, sink, record, evt, *grantPath, maxGrantTTL); err != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			return err
		}
	}

	runErr := cmd.Wait()
	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	state := cruntime.SessionExited
	if runErr != nil {
		state = cruntime.SessionFailed
	}
	if err := cruntime.UpdateSessionStore(*sessionPath, func(sessions *cruntime.SessionStore) error {
		_, err := sessions.Finish(session, state, exitCode, time.Now().UTC())
		return err
	}); err != nil {
		return err
	}
	if runErr != nil {
		return fmt.Errorf("run %s: %w", strings.Join(rest, " "), runErr)
	}
	return nil
}

func syntheticCommandEvents(subj subject.Subject, repo string, argv []string) []event.Event {
	if len(argv) == 0 {
		return nil
	}
	events := []event.Event{
		{
			Kind:    event.KindProcessExec,
			Subject: subj,
			Fields: map[string]any{
				"pid":       subj.PID,
				"comm":      argv[0],
				"argv_text": strings.Join(argv, " "),
				"cwd":       repo,
			},
		},
	}
	if filepath.Base(argv[0]) == "cat" {
		for _, arg := range argv[1:] {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			events = append(events, event.NewFileAccess(subj, expandHome(arg), "read"))
		}
	}
	return events
}

func printAuditLine(w io.Writer, record audit.Event) {
	target := cruntime.DisplayTarget(record.InputEvent)
	fmt.Fprintf(w, "%s %s %s\nsubject=%s\nrule=%s\nreason=%q\naudit=%s\nenforcement=%s\n",
		strings.ToUpper(record.Decision),
		record.InputEvent.Kind,
		target,
		record.Subject.String(),
		record.Outcome.Rule,
		record.Reason,
		record.ID,
		record.Enforcement,
	)
}

func expandHome(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}
