package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"m31labs.dev/continuum/audit"
)

func runAudit(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError("Usage: continuum audit list|show|verify [--path audit.jsonl] [id]")
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("audit list", flag.ContinueOnError)
		fs.SetOutput(stderr)
		path := fs.String("path", ".continuum/audit.jsonl", "audit JSONL path")
		decision := fs.String("decision", "", "filter by decision")
		subject := fs.String("subject", "", "filter by subject id or session")
		kind := fs.String("kind", "", "filter by input event kind")
		limit := fs.Int("limit", 0, "return the last N matching events")
		jsonOut := fs.Bool("json", false, "emit JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		events, err := audit.ReadJSONL(*path)
		if err != nil {
			return err
		}
		events = audit.Query(events, audit.Filter{Decision: *decision, Subject: *subject, Kind: *kind, Limit: *limit})
		if *jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(events)
		}
		for _, evt := range events {
			fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\t%s\n", evt.ID, evt.Decision, evt.InputEvent.Kind, evt.Outcome.Name, evt.Outcome.Rule, evt.Reason)
		}
		return nil
	case "show":
		fs := flag.NewFlagSet("audit show", flag.ContinueOnError)
		fs.SetOutput(stderr)
		path := fs.String("path", ".continuum/audit.jsonl", "audit JSONL path")
		jsonOut := fs.Bool("json", false, "emit JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return usageError("Usage: continuum audit show [--path audit.jsonl] <id>")
		}
		evt, err := audit.LoadAndFind(*path, fs.Arg(0))
		if err != nil {
			return err
		}
		if *jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(evt)
		}
		fmt.Fprintf(stdout, "id=%s decision=%s outcome=%s reason=%q capability=%s enforcement=%s\n",
			evt.ID, evt.Decision, evt.Outcome.Name, evt.Reason, evt.Capability, evt.Enforcement)
		return nil
	case "verify":
		fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
		fs.SetOutput(stderr)
		path := fs.String("path", ".continuum/audit.jsonl", "audit JSONL path")
		jsonOut := fs.Bool("json", false, "emit JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return usageError("Usage: continuum audit verify [--path audit.jsonl] [--json]")
		}
		report, err := audit.VerifyJSONL(*path)
		if err != nil {
			return err
		}
		if *jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(report); err != nil {
				return err
			}
		} else if report.OK {
			fmt.Fprintf(stdout, "audit chain ok events=%d last_hash=%s\n", report.Events, report.LastHash)
		} else {
			fmt.Fprintf(stdout, "audit chain failed line=%d event=%s error=%q\n", report.Line, report.EventID, report.Error)
		}
		if !report.OK {
			return fmt.Errorf("audit chain verification failed")
		}
		return nil
	default:
		return usageError("Usage: continuum audit list|show|verify [--path audit.jsonl] [id]")
	}
}
