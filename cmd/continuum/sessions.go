package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	cruntime "m31labs.dev/continuum/runtime"
)

func runSessions(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError("Usage: continuum sessions list|show|heartbeat|mark-stale|compact [--store .continuum/sessions.json]")
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("sessions list", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "continuum.toml", "config path")
		storePath := fs.String("store", defaultSessionStorePath, "session store")
		state := fs.String("state", "", "filter by state")
		jsonOut := fs.Bool("json", false, "emit JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := loadConfigOrDefault(*configPath)
		if err != nil {
			return err
		}
		*storePath = resolveSessionStorePath(*storePath, cfg)
		store, err := cruntime.LoadSessionStore(*storePath)
		if err != nil {
			return err
		}
		sessions := filterSessions(store.Sessions, cruntime.SessionState(*state))
		if *jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(sessions)
		}
		for _, session := range sessions {
			fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\t%s\n", session.ID, session.State, session.Subject.String(), strings.Join(session.Command, " "), formatSessionTime(session.StartedAt), formatSessionTime(session.LastHeartbeatAt))
		}
		return nil
	case "show":
		fs := flag.NewFlagSet("sessions show", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "continuum.toml", "config path")
		storePath := fs.String("store", defaultSessionStorePath, "session store")
		jsonOut := fs.Bool("json", false, "emit JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return usageError("Usage: continuum sessions show [--store .continuum/sessions.json] <session-id>")
		}
		cfg, err := loadConfigOrDefault(*configPath)
		if err != nil {
			return err
		}
		*storePath = resolveSessionStorePath(*storePath, cfg)
		store, err := cruntime.LoadSessionStore(*storePath)
		if err != nil {
			return err
		}
		session, ok := findSession(store.Sessions, fs.Arg(0))
		if !ok {
			return fmt.Errorf("session %q not found", fs.Arg(0))
		}
		if *jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(session)
		}
		processes, running := sessionProcessCounts(session)
		fmt.Fprintf(stdout, "id=%s state=%s subject=%s command=%q policy=%s audit=%s started=%s last_heartbeat=%s processes=%d running_processes=%d\n",
			session.ID, session.State, session.Subject.String(), strings.Join(session.Command, " "), session.Policy, session.AuditPath, formatSessionTime(session.StartedAt), formatSessionTime(session.LastHeartbeatAt), processes, running)
		return nil
	case "heartbeat":
		fs := flag.NewFlagSet("sessions heartbeat", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "continuum.toml", "config path")
		storePath := fs.String("store", defaultSessionStorePath, "session store")
		jsonOut := fs.Bool("json", false, "emit JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return usageError("Usage: continuum sessions heartbeat [--store .continuum/sessions.json] <session-id>")
		}
		cfg, err := loadConfigOrDefault(*configPath)
		if err != nil {
			return err
		}
		*storePath = resolveSessionStorePath(*storePath, cfg)
		now := time.Now().UTC()
		var session cruntime.Session
		if err := cruntime.UpdateSessionStore(*storePath, func(sessions *cruntime.SessionStore) error {
			var err error
			session, err = sessions.Heartbeat(fs.Arg(0), now)
			return err
		}); err != nil {
			return err
		}
		if *jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(session)
		}
		fmt.Fprintf(stdout, "heartbeat session=%s state=%s last_heartbeat=%s\n", session.ID, session.State, formatSessionTime(session.LastHeartbeatAt))
		return nil
	case "mark-stale":
		fs := flag.NewFlagSet("sessions mark-stale", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "continuum.toml", "config path")
		storePath := fs.String("store", defaultSessionStorePath, "session store")
		after := fs.Duration("after", 0, "mark running sessions stale after this heartbeat age")
		jsonOut := fs.Bool("json", false, "emit JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || *after <= 0 {
			return usageError("Usage: continuum sessions mark-stale --after 10m [--store .continuum/sessions.json]")
		}
		cfg, err := loadConfigOrDefault(*configPath)
		if err != nil {
			return err
		}
		*storePath = resolveSessionStorePath(*storePath, cfg)
		var stale []cruntime.Session
		if err := cruntime.UpdateSessionStore(*storePath, func(sessions *cruntime.SessionStore) error {
			stale = sessions.MarkStale(time.Now().UTC(), *after)
			return nil
		}); err != nil {
			return err
		}
		if *jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(stale)
		}
		fmt.Fprintf(stdout, "stale_sessions=%d after=%s\n", len(stale), after.String())
		return nil
	case "compact":
		fs := flag.NewFlagSet("sessions compact", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "continuum.toml", "config path")
		storePath := fs.String("store", defaultSessionStorePath, "session store")
		retain := fs.Int("retain", 0, "retain newest terminal sessions")
		olderThan := fs.Duration("older-than", 0, "remove terminal sessions older than this age")
		jsonOut := fs.Bool("json", false, "emit JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return usageError("Usage: continuum sessions compact [--store .continuum/sessions.json] --retain N [--older-than 720h]")
		}
		cfg, err := loadConfigOrDefault(*configPath)
		if err != nil {
			return err
		}
		*storePath = resolveSessionStorePath(*storePath, cfg)
		opts := cruntime.RetentionOptions{Retain: *retain, OlderThan: *olderThan, Now: time.Now().UTC()}
		var report cruntime.RetentionReport
		if err := cruntime.UpdateSessionStore(*storePath, func(sessions *cruntime.SessionStore) error {
			var err error
			report, err = sessions.Compact(opts)
			return err
		}); err != nil {
			return err
		}
		if *jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		}
		fmt.Fprintf(stdout, "compacted sessions before=%d after=%d removed=%d store=%s\n", report.Before, report.After, report.Removed, *storePath)
		return nil
	default:
		return usageError("Usage: continuum sessions list|show|heartbeat|mark-stale|compact [--store .continuum/sessions.json]")
	}
}

const timeFormat = "2006-01-02T15:04:05Z07:00"

func filterSessions(sessions []cruntime.Session, state cruntime.SessionState) []cruntime.Session {
	if state == "" {
		return sessions
	}
	out := make([]cruntime.Session, 0, len(sessions))
	for _, session := range sessions {
		if session.State == state {
			out = append(out, session)
		}
	}
	return out
}

func findSession(sessions []cruntime.Session, id string) (cruntime.Session, bool) {
	for _, session := range sessions {
		if session.ID == id {
			return session, true
		}
	}
	return cruntime.Session{}, false
}

func sessionProcessCounts(session cruntime.Session) (int, int) {
	if session.ProcessTree == nil {
		return 0, 0
	}
	return len(session.ProcessTree.Processes), len(session.ProcessTree.Running())
}

func formatSessionTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format(timeFormat)
}
