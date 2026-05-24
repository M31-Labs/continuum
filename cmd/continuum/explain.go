package main

import (
	"encoding/json"
	"flag"
	"io"

	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/explain"
)

func runExplain(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", ".continuum/audit.jsonl", "audit JSONL path")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError("Usage: continuum explain [--path audit.jsonl] <event-id>")
	}
	evt, err := audit.LoadAndFind(*path, fs.Arg(0))
	if err != nil {
		return err
	}
	exp := explain.FromAudit(evt)
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(exp)
	}
	explain.Render(stdout, exp)
	return nil
}
