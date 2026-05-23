package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"

	"m31labs.dev/continuum/config"
	"m31labs.dev/continuum/horizon"
	cruntime "m31labs.dev/continuum/runtime"
)

func main() {
	configPath := flag.String("config", "continuum.toml", "config path")
	listen := flag.String("listen", "", "serve health and capabilities over HTTP")
	flag.Parse()
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "continuum-agent:", err)
		os.Exit(1)
	}
	cfg = config.Resolve(cfg, *configPath)
	daemon := cruntime.NewDaemon(horizon.DirProvider{Dir: cfg.Capabilities.HorizonManifestDir})
	if err := daemon.Start(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "continuum-agent:", err)
		os.Exit(1)
	}
	health := daemon.Health()
	fmt.Printf("continuum-agent: started project=%s capabilities=%d enforcement=file:%s network:%s process:%s\n",
		cfg.Project.Name, health.Capabilities, cfg.Enforcement.File, cfg.Enforcement.Network, cfg.Enforcement.Process)
	if *listen != "" {
		fmt.Printf("continuum-agent: listening %s\n", *listen)
		handler := cruntime.NewHTTPHandlerWithState(daemon, cruntime.StatePaths{
			Sessions: cfg.State.SessionStore,
			Grants:   cfg.State.GrantStore,
			Airlock:  cfg.State.AirlockStore,
			Audit:    cfg.Audit.Path,
		})
		if err := http.ListenAndServe(*listen, handler); err != nil {
			fmt.Fprintln(os.Stderr, "continuum-agent:", err)
			os.Exit(1)
		}
	}
}
