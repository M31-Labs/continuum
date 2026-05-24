package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

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
		authToken := fs.String("auth-token", os.Getenv("CONTINUUM_DAEMON_TOKEN"), "bearer token for mutating daemon endpoints")
		authReads := fs.Bool("auth-reads", false, "require daemon auth for read endpoints too")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		cfg = config.Resolve(cfg, *configPath)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		daemon := cruntime.NewDaemon(horizon.DirProvider{Dir: cfg.Capabilities.HorizonManifestDir})
		if err := daemon.Start(ctx); err != nil {
			return err
		}
		health := daemon.Health()
		fmt.Fprintf(stdout, "continuum-agent: started project=%s capabilities=%d enforcement=file:%s network:%s process:%s\n",
			cfg.Project.Name, health.Capabilities, cfg.Enforcement.File, cfg.Enforcement.Network, cfg.Enforcement.Process)
		if *listen != "" {
			listenAddr := cruntime.NormalizeListenAddress(*listen)
			fmt.Fprintf(stdout, "continuum-agent: listening %s\n", listenAddr)
			handler := cruntime.NewHTTPHandlerWithStateAndOptions(daemon, cruntime.StatePaths{
				PolicyStore:  cfg.State.PolicyStore,
				PolicyBundle: cfg.Policy.Bundle,
				Sessions:     cfg.State.SessionStore,
				Grants:       cfg.State.GrantStore,
				Deliveries:   cfg.State.DeliveryStore,
				Airlock:      cfg.State.AirlockStore,
				Audit:        cfg.Audit.Path,
			}, cruntime.HTTPOptions{
				AuthToken:           *authToken,
				RequireAuthForReads: *authReads,
			})
			return cruntime.ServeHTTP(ctx, cruntime.NewHTTPServer(listenAddr, handler, cruntime.HTTPServerOptions{}), 10*time.Second)
		}
		return nil
	default:
		return usageError("Usage: continuum agent start --config continuum.toml")
	}
}
