package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

type versionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
}

func runVersion(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError("Usage: continuum version [--json]")
	}
	info := versionInfo{Version: version, Commit: commit, BuildDate: buildDate}
	if *jsonOut {
		return json.NewEncoder(stdout).Encode(info)
	}
	fmt.Fprintf(stdout, "continuum version=%s commit=%s build_date=%s\n", info.Version, info.Commit, info.BuildDate)
	return nil
}
