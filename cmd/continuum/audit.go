package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"m31labs.dev/continuum/audit"
)

func runAudit(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError("Usage: continuum audit list|show|export|verify [--path audit.jsonl] [id]")
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
		offset := fs.Int("offset", 0, "return events starting at N after filtering")
		jsonOut := fs.Bool("json", false, "emit JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return usageError("Usage: continuum audit list [--path audit.jsonl] [--decision decision] [--subject subject] [--kind kind] [--limit n] [--offset n] [--json]")
		}
		if err := validatePagination(*limit, *offset); err != nil {
			return err
		}
		events, err := audit.ReadJSONL(*path)
		if err != nil {
			return err
		}
		events = audit.Query(events, audit.Filter{Decision: *decision, Subject: *subject, Kind: *kind, Limit: *limit, Offset: *offset})
		if *jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(events)
		}
		for _, evt := range events {
			fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\t%s\n", evt.ID, evt.Decision, evt.InputEvent.Kind, evt.Outcome.Name, evt.Outcome.Rule, evt.Reason)
		}
		return nil
	case "export":
		fs := flag.NewFlagSet("audit export", flag.ContinueOnError)
		fs.SetOutput(stderr)
		path := fs.String("path", ".continuum/audit.jsonl", "audit JSONL path")
		outPath := fs.String("out", "", "write exported JSONL to path instead of stdout")
		decision := fs.String("decision", "", "filter by decision")
		subject := fs.String("subject", "", "filter by subject id or session")
		kind := fs.String("kind", "", "filter by input event kind")
		limit := fs.Int("limit", 0, "return the last N matching events, or next N with --offset")
		offset := fs.Int("offset", 0, "return events starting at N after filtering")
		redactFields := fs.String("redact-fields", "", "comma-separated input/outcome field names to redact")
		redactRaw := fs.Bool("redact-raw", false, "drop raw input event payloads")
		redactSubject := fs.Bool("redact-subject", false, "drop subject identifiers and keep only subject kind")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return usageError("Usage: continuum audit export [--path audit.jsonl] [--out audit-redacted.jsonl] [--decision decision] [--subject subject] [--kind kind] [--limit n] [--offset n] [--redact-fields a,b] [--redact-raw] [--redact-subject]")
		}
		if err := validatePagination(*limit, *offset); err != nil {
			return err
		}
		events, err := audit.ReadJSONL(*path)
		if err != nil {
			return err
		}
		events = audit.Query(events, audit.Filter{Decision: *decision, Subject: *subject, Kind: *kind, Limit: *limit, Offset: *offset})
		opts := audit.RedactionOptions{
			FieldNames:    splitCommaList(*redactFields),
			RedactRaw:     *redactRaw,
			RedactSubject: *redactSubject,
		}
		if *outPath == "" {
			return audit.ExportJSONL(stdout, events, opts)
		}
		var buf bytes.Buffer
		if err := audit.ExportJSONL(&buf, events, opts); err != nil {
			return err
		}
		if err := writePrivateExportFile(*outPath, buf.Bytes()); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "exported audit events=%d out=%s redacted=%t\n", len(events), *outPath, opts.Active())
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
		return usageError("Usage: continuum audit list|show|export|verify [--path audit.jsonl] [id]")
	}
}

func validatePagination(limit, offset int) error {
	if limit < 0 {
		return fmt.Errorf("limit must be >= 0")
	}
	if offset < 0 {
		return fmt.Errorf("offset must be >= 0")
	}
	return nil
}

func splitCommaList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func writePrivateExportFile(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("export path is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create export dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("create temp export %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	closed := false
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(0600); err != nil {
		return fmt.Errorf("chmod temp export %s: %w", tmpPath, err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temp export %s: %w", tmpPath, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp export %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp export %s: %w", tmpPath, err)
	}
	closed = true
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace export %s: %w", path, err)
	}
	if err := syncExportDir(dir); err != nil {
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("chmod export %s: %w", path, err)
	}
	return nil
}

func syncExportDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open export dir %s: %w", dir, err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync export dir %s: %w", dir, err)
	}
	return nil
}
