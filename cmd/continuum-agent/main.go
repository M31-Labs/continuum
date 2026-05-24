package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"m31labs.dev/continuum/config"
	"m31labs.dev/continuum/horizon"
	cruntime "m31labs.dev/continuum/runtime"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	configPath := flag.String("config", "continuum.toml", "config path")
	listen := flag.String("listen", "", "serve health and capabilities over HTTP")
	authToken := flag.String("auth-token", os.Getenv("CONTINUUM_DAEMON_TOKEN"), "bearer token for mutating daemon endpoints")
	authReads := flag.Bool("auth-reads", false, "require daemon auth for read endpoints too")
	flag.Parse()
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "continuum-agent:", err)
		os.Exit(1)
	}
	cfg = config.Resolve(cfg, *configPath)
	daemon := cruntime.NewDaemon(horizon.DirProvider{Dir: cfg.Capabilities.HorizonManifestDir})
	if err := daemon.Start(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "continuum-agent:", err)
		os.Exit(1)
	}
	health := daemon.Health()
	fmt.Printf("continuum-agent: started project=%s capabilities=%d enforcement=file:%s network:%s process:%s\n",
		cfg.Project.Name, health.Capabilities, cfg.Enforcement.File, cfg.Enforcement.Network, cfg.Enforcement.Process)
	if *listen != "" {
		listenAddr := cruntime.NormalizeListenAddress(*listen)
		fmt.Printf("continuum-agent: listening %s\n", listenAddr)
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
		if err := cruntime.ServeHTTP(ctx, cruntime.NewHTTPServer(listenAddr, handler, cruntime.HTTPServerOptions{}), 10*time.Second); err != nil {
			fmt.Fprintln(os.Stderr, "continuum-agent:", err)
			os.Exit(1)
		}
	}
}
