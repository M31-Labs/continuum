package main

import (
	"flag"
	"io"

	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/explain"
)

func runExplain(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("path", ".continuum/audit.jsonl", "audit JSONL path")
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
	explain.Render(stdout, explain.FromAudit(evt))
	return nil
}
