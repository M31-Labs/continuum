package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
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
	unixSocket := flag.String("unix-socket", "", "serve daemon HTTP over a local Unix socket")
	authToken := flag.String("auth-token", os.Getenv("CONTINUUM_DAEMON_TOKEN"), "bearer token for mutating daemon endpoints")
	authReads := flag.Bool("auth-reads", false, "require daemon auth for read endpoints too")
	corsOrigins := flag.String("cors-origins", "", "comma-separated CORS origin allowlist")
	flag.Parse()
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "continuum-agent:", err)
		os.Exit(1)
	}
	cfg = config.Resolve(cfg, *configPath)
	allowedOrigins := splitCSV(cfg.Daemon.CORSOrigins)
	if *corsOrigins != "" {
		allowedOrigins = splitCSV(*corsOrigins)
	}
	daemon := cruntime.NewDaemon(horizon.DirProvider{Dir: cfg.Capabilities.HorizonManifestDir})
	if err := daemon.Start(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "continuum-agent:", err)
		os.Exit(1)
	}
	paths := daemonStatePaths(cfg)
	if err := cruntime.CheckReadiness(daemon, paths).Err(); err != nil {
		fmt.Fprintln(os.Stderr, "continuum-agent:", err)
		os.Exit(1)
	}
	health := daemon.Health()
	fmt.Printf("continuum-agent: started project=%s capabilities=%d enforcement=file:%s network:%s process:%s\n",
		cfg.Project.Name, health.Capabilities, cfg.Enforcement.File, cfg.Enforcement.Network, cfg.Enforcement.Process)
	if *listen != "" || *unixSocket != "" {
		handler := cruntime.NewHTTPHandlerWithStateAndOptions(daemon, paths, cruntime.HTTPOptions{
			AuthToken:           *authToken,
			RequireAuthForReads: *authReads,
			AllowedOrigins:      allowedOrigins,
		})
		if *unixSocket != "" {
			fmt.Printf("continuum-agent: listening unix=%s\n", *unixSocket)
			if err := cruntime.ServeUnix(ctx, *unixSocket, handler, 10*time.Second); err != nil {
				fmt.Fprintln(os.Stderr, "continuum-agent:", err)
				os.Exit(1)
			}
			return
		}
		listenAddr := cruntime.NormalizeListenAddress(*listen)
		fmt.Printf("continuum-agent: listening %s\n", listenAddr)
		if err := cruntime.ServeHTTP(ctx, cruntime.NewHTTPServer(listenAddr, handler, cruntime.HTTPServerOptions{}), 10*time.Second); err != nil {
			fmt.Fprintln(os.Stderr, "continuum-agent:", err)
			os.Exit(1)
		}
	}
}

func daemonStatePaths(cfg config.Config) cruntime.StatePaths {
	return cruntime.StatePaths{
		PolicyStore:         cfg.State.PolicyStore,
		PolicyBundle:        cfg.Policy.Bundle,
		Sessions:            cfg.State.SessionStore,
		Grants:              cfg.State.GrantStore,
		Deliveries:          cfg.State.DeliveryStore,
		IDStore:             cfg.State.IDStore,
		Airlock:             cfg.State.AirlockStore,
		AirlockAccumulators: cfg.State.AirlockAccumulatorStore,
		Audit:               cfg.Audit.Path,
	}
}

func splitCSV(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}
