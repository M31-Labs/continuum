package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	cruntime "m31labs.dev/continuum/runtime"
)

func runSessions(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError("Usage: continuum sessions list|show [--store .continuum/sessions.json]")
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
			fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\n", session.ID, session.State, session.Subject.String(), strings.Join(session.Command, " "), session.StartedAt.Format(timeFormat))
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
		fmt.Fprintf(stdout, "id=%s state=%s subject=%s command=%q policy=%s audit=%s processes=%d running_processes=%d\n",
			session.ID, session.State, session.Subject.String(), strings.Join(session.Command, " "), session.Policy, session.AuditPath, processes, running)
		return nil
	default:
		return usageError("Usage: continuum sessions list|show [--store .continuum/sessions.json]")
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
