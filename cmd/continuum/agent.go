package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"m31labs.dev/continuum/config"
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
		unixSocket := fs.String("unix-socket", "", "serve daemon HTTP over a local Unix socket")
		authToken := fs.String("auth-token", os.Getenv("CONTINUUM_DAEMON_TOKEN"), "bearer token for mutating daemon endpoints")
		authReads := fs.Bool("auth-reads", false, "require daemon auth for read endpoints too")
		corsOrigins := fs.String("cors-origins", "", "comma-separated CORS origin allowlist")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		cfg = config.Resolve(cfg, *configPath)
		allowedOrigins := splitCSV(cfg.Daemon.CORSOrigins)
		if *corsOrigins != "" {
			allowedOrigins = splitCSV(*corsOrigins)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		provider, err := horizonProviderFromConfig(cfg)
		if err != nil {
			return err
		}
		daemon := cruntime.NewDaemon(provider)
		if err := daemon.Start(ctx); err != nil {
			return err
		}
		paths := daemonStatePaths(cfg)
		prunedGrants, err := pruneExpiredGrantStore(paths.Grants, paths.Deliveries, time.Now().UTC())
		if err != nil {
			return err
		}
		if prunedGrants > 0 {
			fmt.Fprintf(stdout, "continuum-agent: pruned expired_grants=%d\n", prunedGrants)
		}
		if err := cruntime.CheckReadiness(daemon, paths).Err(); err != nil {
			return err
		}
		health := daemon.Health()
		fmt.Fprintf(stdout, "continuum-agent: started project=%s capabilities=%d enforcement=file:%s network:%s process:%s\n",
			cfg.Project.Name, health.Capabilities, cfg.Enforcement.File, cfg.Enforcement.Network, cfg.Enforcement.Process)
		if *listen != "" || *unixSocket != "" {
			handler := cruntime.NewHTTPHandlerWithStateAndOptions(daemon, paths, cruntime.HTTPOptions{
				AuthToken:           *authToken,
				RequireAuthForReads: *authReads,
				AllowedOrigins:      allowedOrigins,
			})
			if *unixSocket != "" {
				fmt.Fprintf(stdout, "continuum-agent: listening unix=%s\n", *unixSocket)
				return cruntime.ServeUnix(ctx, *unixSocket, handler, 10*time.Second)
			}
			listenAddr := cruntime.NormalizeListenAddress(*listen)
			fmt.Fprintf(stdout, "continuum-agent: listening %s\n", listenAddr)
			return cruntime.ServeHTTP(ctx, cruntime.NewHTTPServer(listenAddr, handler, cruntime.HTTPServerOptions{}), 10*time.Second)
		}
		return nil
	default:
		return usageError("Usage: continuum agent start --config continuum.toml")
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
