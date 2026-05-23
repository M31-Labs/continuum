package main

import (
	"flag"
	"fmt"
	"io"
	"time"

	"m31labs.dev/continuum/capability"
)

func runGrant(args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "list":
			return runGrantList(args[1:], stdout, stderr)
		case "revoke":
			return runGrantRevoke(args[1:], stdout, stderr)
		case "prune":
			return runGrantPrune(args[1:], stdout, stderr)
		}
	}
	fs := flag.NewFlagSet("grant", flag.ContinueOnError)
	fs.SetOutput(stderr)
	session := fs.String("session", "", "session id")
	capName := fs.String("capability", "", "capability name")
	host := fs.String("host", "", "network host")
	port := fs.Int("port", 0, "network port")
	path := fs.String("path", "", "file path")
	pathPrefix := fs.String("path-prefix", "", "file path prefix")
	op := fs.String("op", "", "file operation")
	comm := fs.String("comm", "", "process command")
	argvText := fs.String("argv", "", "process argv text")
	argvPrefix := fs.String("argv-prefix", "", "process argv prefix")
	ttl := fs.Duration("ttl", 20*time.Minute, "grant TTL")
	reason := fs.String("reason", "", "reason")
	configPath := fs.String("config", "continuum.toml", "config path")
	storePath := fs.String("store", defaultGrantStorePath, "grant store")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *session == "" || *capName == "" {
		return usageError("Usage: continuum grant --session <id> --capability <name> [--host host --port port | --path path --op write | --comm go] --ttl 20m --reason <text>\n       continuum grant list|revoke|prune")
	}
	now := time.Now().UTC()
	scope := grantScope(*host, *port, *path, *pathPrefix, *op, *comm, *argvText, *argvPrefix)
	if err := validateGrantScope(*capName, scope); err != nil {
		return err
	}
	cfg, err := loadConfigOrDefault(*configPath)
	if err != nil {
		return err
	}
	*storePath = resolveGrantStorePath(*storePath, cfg)
	grant := capability.Grant{
		ID:         fmt.Sprintf("grant_%d", now.UnixNano()),
		Session:    *session,
		Capability: *capName,
		Scope:      scope,
		Reason:     *reason,
		CreatedAt:  now,
		ExpiresAt:  now.Add(*ttl),
	}
	store, err := capability.LoadGrantStore(*storePath)
	if err != nil {
		return err
	}
	if err := store.Add(grant); err != nil {
		return err
	}
	if err := store.Save(*storePath); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "grant id=%s session=%s capability=%s expires=%s reason=%q store=%s\n", grant.ID, grant.Session, grant.Capability, grant.ExpiresAt.Format(time.RFC3339), grant.Reason, *storePath)
	return nil
}

func grantScope(host string, port int, path, pathPrefix, op, comm, argvText, argvPrefix string) map[string]any {
	scope := map[string]any{}
	if host != "" {
		scope["host"] = host
	}
	if port != 0 {
		scope["port"] = port
	}
	if path != "" {
		scope["path"] = path
	}
	if pathPrefix != "" {
		scope["path_prefix"] = pathPrefix
	}
	if op != "" {
		scope["op"] = op
	}
	if comm != "" {
		scope["comm"] = comm
	}
	if argvText != "" {
		scope["argv_text"] = argvText
	}
	if argvPrefix != "" {
		scope["argv_prefix"] = argvPrefix
	}
	return scope
}

func validateGrantScope(capName string, scope map[string]any) error {
	switch capName {
	case "network.connect", "kernel.network.connect.grant":
		if _, ok := scope["host"]; !ok {
			return usageError("network grants require --host")
		}
	case "file.access", "file.read", "file.write", "file.open":
		if _, ok := scope["path"]; ok {
			return nil
		}
		if _, ok := scope["path_prefix"]; ok {
			return nil
		}
		return usageError("file grants require --path or --path-prefix")
	case "process.exec":
		if _, ok := scope["comm"]; ok {
			return nil
		}
		if _, ok := scope["argv_text"]; ok {
			return nil
		}
		if _, ok := scope["argv_prefix"]; ok {
			return nil
		}
		return usageError("process grants require --comm, --argv, or --argv-prefix")
	}
	return nil
}

func runGrantList(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("grant list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "continuum.toml", "config path")
	storePath := fs.String("store", defaultGrantStorePath, "grant store")
	all := fs.Bool("all", false, "include inactive grants")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfigOrDefault(*configPath)
	if err != nil {
		return err
	}
	*storePath = resolveGrantStorePath(*storePath, cfg)
	store, err := capability.LoadGrantStore(*storePath)
	if err != nil {
		return err
	}
	grants := store.Active(time.Now().UTC())
	if *all {
		grants = store.Grants
	}
	for _, grant := range grants {
		state := "active"
		if !grant.RevokedAt.IsZero() {
			state = "revoked"
		} else if grant.Expired(time.Now().UTC()) {
			state = "expired"
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\n", grant.ID, grant.Session, grant.Capability, state, grant.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}

func runGrantRevoke(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("grant revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "continuum.toml", "config path")
	storePath := fs.String("store", defaultGrantStorePath, "grant store")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError("Usage: continuum grant revoke [--store .continuum/grants.json] <grant-id>")
	}
	cfg, err := loadConfigOrDefault(*configPath)
	if err != nil {
		return err
	}
	*storePath = resolveGrantStorePath(*storePath, cfg)
	store, err := capability.LoadGrantStore(*storePath)
	if err != nil {
		return err
	}
	grant, err := store.Revoke(fs.Arg(0), time.Now().UTC())
	if err != nil {
		return err
	}
	if err := store.Save(*storePath); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "revoked grant id=%s session=%s capability=%s\n", grant.ID, grant.Session, grant.Capability)
	return nil
}

func runGrantPrune(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("grant prune", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "continuum.toml", "config path")
	storePath := fs.String("store", defaultGrantStorePath, "grant store")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfigOrDefault(*configPath)
	if err != nil {
		return err
	}
	*storePath = resolveGrantStorePath(*storePath, cfg)
	store, err := capability.LoadGrantStore(*storePath)
	if err != nil {
		return err
	}
	removed := store.PruneExpired(time.Now().UTC())
	if err := store.Save(*storePath); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "pruned grants removed=%d\n", removed)
	return nil
}
