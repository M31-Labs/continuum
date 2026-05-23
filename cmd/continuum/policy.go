package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"time"

	"m31labs.dev/continuum/policy"
)

func runPolicy(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError("Usage: continuum policy check <file.arb> | publish <file.arb> | activate <name> | list | show <name>")
	}
	switch args[0] {
	case "check":
		fs := flag.NewFlagSet("policy check", flag.ContinueOnError)
		fs.SetOutput(stderr)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return usageError("Usage: continuum policy check <file.arb>")
		}
		name := inferPolicyName(fs.Arg(0))
		bundle, err := policy.Load(name, fs.Arg(0))
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "policy ok name=%s id=%s kind=%s path=%s\n", bundle.Name, bundle.Program.ID, bundle.Program.Kind, fs.Arg(0))
		return nil
	case "publish":
		fs := flag.NewFlagSet("policy publish", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "continuum.toml", "config path")
		storePath := fs.String("store", defaultPolicyStorePath, "policy store path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return usageError("Usage: continuum policy publish [--config continuum.toml] [--store .continuum/policies.json] <file.arb>")
		}
		cfg, err := loadConfigOrDefault(*configPath)
		if err != nil {
			return err
		}
		*storePath = resolvePolicyStorePath(*storePath, cfg)
		name := inferPolicyName(fs.Arg(0))
		bundle, err := policy.Load(name, fs.Arg(0))
		if err != nil {
			return err
		}
		store, err := policy.LoadStore(*storePath)
		if err != nil {
			return err
		}
		if err := store.Publish(bundle, time.Now().UTC()); err != nil {
			return err
		}
		if err := store.Save(); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "published policy name=%s id=%s kind=%s path=%s store=%s\n", bundle.Name, bundle.Program.ID, bundle.Program.Kind, fs.Arg(0), *storePath)
		return nil
	case "activate":
		fs := flag.NewFlagSet("policy activate", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "continuum.toml", "config path")
		storePath := fs.String("store", defaultPolicyStorePath, "policy store path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return usageError("Usage: continuum policy activate [--config continuum.toml] [--store .continuum/policies.json] <name>")
		}
		cfg, err := loadConfigOrDefault(*configPath)
		if err != nil {
			return err
		}
		*storePath = resolvePolicyStorePath(*storePath, cfg)
		store, err := policy.LoadStore(*storePath)
		if err != nil {
			return err
		}
		if err := store.Activate(fs.Arg(0)); err != nil {
			return err
		}
		if err := store.Save(); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "activated policy name=%s store=%s\n", fs.Arg(0), *storePath)
		return nil
	case "list":
		fs := flag.NewFlagSet("policy list", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "continuum.toml", "config path")
		storePath := fs.String("store", defaultPolicyStorePath, "policy store path")
		jsonOut := fs.Bool("json", false, "write JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := loadConfigOrDefault(*configPath)
		if err != nil {
			return err
		}
		*storePath = resolvePolicyStorePath(*storePath, cfg)
		store, err := policy.LoadStore(*storePath)
		if err != nil {
			return err
		}
		bundles := sortedStoredBundles(store)
		if *jsonOut {
			return json.NewEncoder(stdout).Encode(struct {
				Active  string                `json:"active,omitempty"`
				Bundles []policy.StoredBundle `json:"bundles"`
			}{Active: store.Active, Bundles: bundles})
		}
		for _, bundle := range bundles {
			marker := " "
			if bundle.Name == store.Active {
				marker = "*"
			}
			fmt.Fprintf(stdout, "%s %s\t%s\t%s\t%s\n", marker, bundle.Name, bundle.ID, bundle.Kind, bundle.Path)
		}
		return nil
	case "show":
		fs := flag.NewFlagSet("policy show", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "continuum.toml", "config path")
		storePath := fs.String("store", defaultPolicyStorePath, "policy store path")
		jsonOut := fs.Bool("json", false, "write JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return usageError("Usage: continuum policy show [--config continuum.toml] [--store .continuum/policies.json] <name>")
		}
		cfg, err := loadConfigOrDefault(*configPath)
		if err != nil {
			return err
		}
		*storePath = resolvePolicyStorePath(*storePath, cfg)
		store, err := policy.LoadStore(*storePath)
		if err != nil {
			return err
		}
		bundle, ok := store.Bundles[fs.Arg(0)]
		if !ok {
			return fmt.Errorf("policy bundle %q is not published", fs.Arg(0))
		}
		if *jsonOut {
			return json.NewEncoder(stdout).Encode(bundle)
		}
		active := "false"
		if bundle.Name == store.Active {
			active = "true"
		}
		fmt.Fprintf(stdout, "name=%s id=%s kind=%s active=%s path=%s published=%s\n", bundle.Name, bundle.ID, bundle.Kind, active, bundle.Path, bundle.Published.Format(time.RFC3339))
		return nil
	default:
		return usageError("Usage: continuum policy check <file.arb> | publish <file.arb> | activate <name> | list | show <name>")
	}
}

func sortedStoredBundles(store *policy.Store) []policy.StoredBundle {
	if store == nil || len(store.Bundles) == 0 {
		return nil
	}
	names := make([]string, 0, len(store.Bundles))
	for name := range store.Bundles {
		names = append(names, name)
	}
	slices.Sort(names)
	bundles := make([]policy.StoredBundle, 0, len(names))
	for _, name := range names {
		bundles = append(bundles, store.Bundles[name])
	}
	return bundles
}

func inferPolicyName(path string) string {
	dir := filepath.Dir(path)
	if filepath.Base(dir) == "policies" {
		parent := filepath.Base(filepath.Dir(dir))
		if parent != "." && parent != string(filepath.Separator) && parent != "" {
			return parent
		}
	}
	return filepath.Base(dir)
}
