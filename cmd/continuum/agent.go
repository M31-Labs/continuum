package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"

	"m31labs.dev/continuum/config"
	"m31labs.dev/continuum/horizon"
	cruntime "m31labs.dev/continuum/runtime"
)

func runAgent(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError("Usage: continuum agent start --config continuum.toml")
	}
	switch args[0] {
	case "start":
		fs := flag.NewFlagSet("agent start", flag.ContinueOnError)
		fs.SetOutput(stderr)
		configPath := fs.String("config", "continuum.toml", "config path")
		listen := fs.String("listen", "", "serve health and capabilities over HTTP")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		cfg = config.Resolve(cfg, *configPath)
		daemon := cruntime.NewDaemon(horizon.DirProvider{Dir: cfg.Capabilities.HorizonManifestDir})
		if err := daemon.Start(nil); err != nil {
			return err
		}
		health := daemon.Health()
		fmt.Fprintf(stdout, "continuum-agent: started project=%s capabilities=%d enforcement=file:%s network:%s process:%s\n",
			cfg.Project.Name, health.Capabilities, cfg.Enforcement.File, cfg.Enforcement.Network, cfg.Enforcement.Process)
		if *listen != "" {
			fmt.Fprintf(stdout, "continuum-agent: listening %s\n", *listen)
			return http.ListenAndServe(*listen, cruntime.NewHTTPHandlerWithState(daemon, cruntime.StatePaths{
				Sessions: cfg.State.SessionStore,
				Grants:   cfg.State.GrantStore,
				Airlock:  cfg.State.AirlockStore,
				Audit:    cfg.Audit.Path,
			}))
		}
		return nil
	default:
		return usageError("Usage: continuum agent start --config continuum.toml")
	}
}
