package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"

	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/horizon"
	cruntime "m31labs.dev/continuum/runtime"
)

func runCapabilities(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("capabilities", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manifestDir := fs.String("manifest-dir", ".continuum/capabilities", "Horizon manifest directory")
	kind := fs.String("kind", "", "filter by source, sink, or worker")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	daemon := cruntime.NewDaemon(horizon.DirProvider{Dir: *manifestDir})
	if err := daemon.Start(context.Background()); err != nil {
		return err
	}
	caps := filterCapabilities(daemon.Registry.List(), capability.Kind(*kind))
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(caps)
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tKIND\tOWNER\tDANGER\tBACKEND")
	for _, cap := range caps {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", cap.Name, cap.Kind, cap.Owner, cap.Danger, cap.Backend)
	}
	return tw.Flush()
}

func filterCapabilities(caps []capability.Capability, kind capability.Kind) []capability.Capability {
	if kind == "" {
		return caps
	}
	out := make([]capability.Capability, 0, len(caps))
	for _, cap := range caps {
		if cap.Kind == kind {
			out = append(out, cap)
		}
	}
	return out
}
