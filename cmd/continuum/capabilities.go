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
	if len(args) > 0 && args[0] == "inspect" {
		return runCapabilitiesInspect(args[1:], stdout, stderr)
	}
	fs := flag.NewFlagSet("capabilities", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manifestDir := fs.String("manifest-dir", ".continuum/capabilities", "Horizon manifest directory")
	kind := fs.String("kind", "", "filter by source, sink, or worker")
	jsonOut := fs.Bool("json", false, "emit JSON")
	signatureMode := fs.String("signature-mode", "off", "manifest signature mode: off, warn, or require")
	var signatureKeys repeatStringFlag
	fs.Var(&signatureKeys, "signature-key", "trusted Ed25519 manifest public key path; may be repeated or comma-separated")
	if err := fs.Parse(args); err != nil {
		return err
	}
	loadOptions, err := horizonLoadOptionsFromValues(*signatureMode, signatureKeys.String())
	if err != nil {
		return err
	}
	daemon := cruntime.NewDaemon(horizon.DirProvider{Dir: *manifestDir, Options: loadOptions})
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
	if err := tw.Flush(); err != nil {
		return err
	}
	warnDangerousCapabilities(stdout, caps)
	return nil
}

func runCapabilitiesInspect(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("capabilities inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "emit JSON")
	signatureMode := fs.String("signature-mode", "off", "manifest signature mode: off, warn, or require")
	var signatureKeys repeatStringFlag
	fs.Var(&signatureKeys, "signature-key", "trusted Ed25519 manifest public key path; may be repeated or comma-separated")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError("Usage: continuum capabilities inspect [--json] [--signature-mode off|warn|require] [--signature-key key.pub] <path>")
	}
	loadOptions, err := horizonLoadOptionsFromValues(*signatureMode, signatureKeys.String())
	if err != nil {
		return err
	}
	inspection, err := horizon.InspectPathWithOptions(fs.Arg(0), loadOptions)
	if err != nil {
		return err
	}
	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(inspection)
	}
	fmt.Fprintf(stdout, "path=%s kind=%s needs_export=%v\n", inspection.Path, inspection.Kind, inspection.NeedsExport)
	if inspection.Message != "" {
		fmt.Fprintf(stdout, "message=%q\n", inspection.Message)
	}
	for _, artifact := range inspection.Artifacts {
		fmt.Fprintf(stdout, "artifact kind=%s path=%s sha256=%s size=%d\n", artifact.Kind, artifact.Path, artifact.SHA256, artifact.Size)
	}
	if inspection.Signature != nil {
		fmt.Fprintf(stdout, "signature mode=%s signed=%v verified=%v key_id=%s path=%s error=%q\n", inspection.Signature.Mode, inspection.Signature.Signed, inspection.Signature.Verified, inspection.Signature.KeyID, inspection.Signature.SignaturePath, inspection.Signature.Error)
	}
	for _, cap := range inspection.Capabilities {
		fmt.Fprintf(stdout, "capability name=%s kind=%s owner=%s danger=%s output=%s input=%s\n", cap.Name, cap.Kind, cap.Owner, cap.Danger, cap.Output, cap.Input)
	}
	return nil
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

func warnDangerousCapabilities(stdout io.Writer, caps []capability.Capability) {
	var dangerous []capability.Capability
	for _, cap := range caps {
		if cap.Danger == capability.DangerPrivileged || cap.Danger == capability.DangerDestructive {
			dangerous = append(dangerous, cap)
		}
	}
	if len(dangerous) == 0 {
		return
	}
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "WARNING: privileged/destructive capabilities are registered:")
	for _, cap := range dangerous {
		fmt.Fprintf(stdout, "- %s danger=%s backend=%s\n", cap.Name, cap.Danger, cap.Backend)
	}
}
