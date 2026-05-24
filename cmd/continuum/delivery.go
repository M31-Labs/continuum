package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	cruntime "m31labs.dev/continuum/runtime"
)

func runDelivery(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError("Usage: continuum delivery compact [--delivery-store .continuum/deliveries.json] --retain N [--older-than 720h]")
	}
	switch args[0] {
	case "compact":
		fs := flag.NewFlagSet("delivery compact", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "continuum.toml", "config path")
		storePath := fs.String("delivery-store", defaultDeliveryStorePath, "delivery queue store")
		retain := fs.Int("retain", 0, "retain newest terminal delivery records")
		olderThan := fs.Duration("older-than", 0, "remove terminal delivery records older than this age")
		jsonOut := fs.Bool("json", false, "emit JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return usageError("Usage: continuum delivery compact [--delivery-store .continuum/deliveries.json] --retain N [--older-than 720h]")
		}
		cfg, err := loadConfigOrDefault(*configPath)
		if err != nil {
			return err
		}
		*storePath = resolveDeliveryStorePath(*storePath, cfg)
		opts := cruntime.RetentionOptions{Retain: *retain, OlderThan: *olderThan, Now: time.Now().UTC()}
		var report cruntime.RetentionReport
		if err := cruntime.UpdateDeliveryStore(*storePath, func(store *cruntime.DeliveryStore) error {
			var err error
			report, err = store.Compact(opts)
			return err
		}); err != nil {
			return err
		}
		if *jsonOut {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		}
		fmt.Fprintf(stdout, "compacted deliveries before=%d after=%d removed=%d store=%s\n", report.Before, report.After, report.Removed, *storePath)
		return nil
	default:
		return usageError("Usage: continuum delivery compact [--delivery-store .continuum/deliveries.json] --retain N [--older-than 720h]")
	}
}
