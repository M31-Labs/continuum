package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"m31labs.dev/continuum/capability"
	cruntime "m31labs.dev/continuum/runtime"
)

func runGrant(args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "list":
			return runGrantList(args[1:], stdout, stderr)
		case "renew":
			return runGrantRenew(args[1:], stdout, stderr)
		case "revoke":
			return runGrantRevoke(args[1:], stdout, stderr)
		case "retry-revocations":
			return runGrantRetryRevocations(args[1:], stdout, stderr)
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
		return usageError("Usage: continuum grant --session <id> --capability <name> [--host host --port port | --path path --op write | --comm go] --ttl 20m --reason <text>\n       continuum grant list|renew|revoke|retry-revocations|prune")
	}
	reasonText := strings.TrimSpace(*reason)
	if reasonText == "" {
		return usageError("grant --reason is required")
	}
	if *ttl <= 0 {
		return usageError("grant --ttl must be positive")
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
	maxTTL, err := configuredMaxGrantTTL(cfg)
	if err != nil {
		return err
	}
	if *ttl > maxTTL {
		return usageError(fmt.Sprintf("grant --ttl %s exceeds configured maximum %s", ttl.String(), maxTTL.String()))
	}
	*storePath = resolveGrantStorePath(*storePath, cfg)
	grant := capability.Grant{
		ID:         fmt.Sprintf("grant_%d", now.UnixNano()),
		Session:    *session,
		Capability: *capName,
		Scope:      scope,
		Reason:     reasonText,
		CreatedAt:  now,
		ExpiresAt:  now.Add(*ttl),
	}
	if err := capability.UpdateGrantStore(*storePath, func(store *capability.GrantStore) error {
		return store.Add(grant)
	}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "grant id=%s session=%s capability=%s expires=%s reason=%q store=%s\n", grant.ID, grant.Session, grant.Capability, grant.ExpiresAt.Format(time.RFC3339), grant.Reason, *storePath)
	return nil
}

func configuredMaxGrantTTL(cfg cliConfig) (time.Duration, error) {
	maxTTL, err := time.ParseDuration(cfg.Config.Grant.MaxTTL)
	if err != nil {
		return 0, fmt.Errorf("grant.max_ttl %q is invalid: %w", cfg.Config.Grant.MaxTTL, err)
	}
	if maxTTL <= 0 {
		return 0, fmt.Errorf("grant.max_ttl must be positive")
	}
	return maxTTL, nil
}

func grantScope(host string, port int, path, pathPrefix, op, comm, argvText, argvPrefix string) map[string]any {
	scope := map[string]any{}
	addGrantString(scope, "host", host)
	if port != 0 {
		scope["port"] = port
	}
	addGrantString(scope, "path", path)
	addGrantString(scope, "path_prefix", pathPrefix)
	addGrantString(scope, "op", op)
	addGrantString(scope, "comm", comm)
	addGrantString(scope, "argv_text", argvText)
	addGrantString(scope, "argv_prefix", argvPrefix)
	return scope
}

func addGrantString(scope map[string]any, key, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		scope[key] = value
	}
}

func validateGrantScope(capName string, scope map[string]any) error {
	switch capName {
	case "network.connect", "kernel.network.connect.grant":
		return validateNetworkGrantScope(scope)
	case "file.access", "file.read", "file.write", "file.open":
		return validateFileGrantScope(scope)
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

func validateNetworkGrantScope(scope map[string]any) error {
	host, ok := grantString(scope, "host")
	if !ok {
		return usageError("network grants require --host")
	}
	if strings.ContainsAny(host, " \t\r\n/\\") {
		return usageError("network grant --host must be a hostname or IP address without spaces, slashes, or ports")
	}
	if _, err := netip.ParseAddr(host); err != nil && !validGrantHostname(host) {
		return usageError("network grant --host must be a valid hostname or IP address")
	}
	if port, ok := grantInt(scope, "port"); ok && (port < 1 || port > 65535) {
		return usageError("network grant --port must be between 1 and 65535")
	}
	return nil
}

func validGrantHostname(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i, r := range label {
			isAlpha := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
			isDigit := r >= '0' && r <= '9'
			isHyphen := r == '-'
			if !isAlpha && !isDigit && !isHyphen {
				return false
			}
			if isHyphen && (i == 0 || i == len(label)-1) {
				return false
			}
		}
	}
	return true
}

func validateFileGrantScope(scope map[string]any) error {
	path, hasPath := grantString(scope, "path")
	pathPrefix, hasPathPrefix := grantString(scope, "path_prefix")
	switch {
	case hasPath && hasPathPrefix:
		return usageError("file grants accept either --path or --path-prefix, not both")
	case hasPath:
		return validateGrantPath("--path", path)
	case hasPathPrefix:
		return validateGrantPath("--path-prefix", pathPrefix)
	default:
		return usageError("file grants require --path or --path-prefix")
	}
}

func validateGrantPath(label, value string) error {
	if strings.ContainsRune(value, '\x00') {
		return usageError(label + " cannot contain NUL bytes")
	}
	clean := filepath.Clean(value)
	if clean == "." || clean == "" {
		return usageError(label + " must identify a concrete path")
	}
	if clean == string(filepath.Separator) {
		return usageError(label + " cannot grant the filesystem root")
	}
	return nil
}

func grantString(scope map[string]any, key string) (string, bool) {
	value, ok := scope[key].(string)
	if !ok {
		return "", false
	}
	value = strings.TrimSpace(value)
	return value, value != ""
}

func grantInt(scope map[string]any, key string) (int, bool) {
	value, ok := scope[key]
	if !ok {
		return 0, false
	}
	switch v := value.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	default:
		return 0, false
	}
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

func runGrantRenew(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("grant renew", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "continuum.toml", "config path")
	storePath := fs.String("store", defaultGrantStorePath, "grant store")
	ttl := fs.Duration("ttl", 20*time.Minute, "renewal TTL")
	reason := fs.String("reason", "", "renewal reason")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError("Usage: continuum grant renew [--store .continuum/grants.json] --ttl 20m --reason <text> <grant-id>")
	}
	reasonText := strings.TrimSpace(*reason)
	if reasonText == "" {
		return usageError("grant renew --reason is required")
	}
	if *ttl <= 0 {
		return usageError("grant renew --ttl must be positive")
	}
	cfg, err := loadConfigOrDefault(*configPath)
	if err != nil {
		return err
	}
	maxTTL, err := configuredMaxGrantTTL(cfg)
	if err != nil {
		return err
	}
	if *ttl > maxTTL {
		return usageError(fmt.Sprintf("grant renew --ttl %s exceeds configured maximum %s", ttl.String(), maxTTL.String()))
	}
	*storePath = resolveGrantStorePath(*storePath, cfg)
	var grant capability.Grant
	if err := capability.UpdateGrantStore(*storePath, func(store *capability.GrantStore) error {
		var err error
		grant, err = store.Renew(fs.Arg(0), *ttl, reasonText, time.Now().UTC())
		return err
	}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "renewed grant id=%s session=%s capability=%s expires=%s reason=%q renewals=%d store=%s\n", grant.ID, grant.Session, grant.Capability, grant.ExpiresAt.Format(time.RFC3339), reasonText, len(grant.Renewals), *storePath)
	return nil
}

func runGrantRevoke(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("grant revoke", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "continuum.toml", "config path")
	storePath := fs.String("store", defaultGrantStorePath, "grant store")
	deliveryPath := fs.String("delivery-store", defaultDeliveryStorePath, "delivery queue store")
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
	*deliveryPath = resolveDeliveryStorePath(*deliveryPath, cfg)
	var grant capability.Grant
	if err := capability.UpdateGrantStore(*storePath, func(store *capability.GrantStore) error {
		var err error
		grant, err = store.Revoke(fs.Arg(0), time.Now().UTC())
		return err
	}); err != nil {
		return err
	}
	delivery, err := cruntime.EnqueueGrantRevocation(*deliveryPath, grant, "grant revoked", grant.RevokedAt)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "revoked grant id=%s session=%s capability=%s delivery=%s\n", grant.ID, grant.Session, grant.Capability, delivery.ID)
	return nil
}

func runGrantRetryRevocations(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("grant retry-revocations", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "continuum.toml", "config path")
	deliveryPath := fs.String("delivery-store", defaultDeliveryStorePath, "delivery queue store")
	failedOnly := fs.Bool("failed-only", false, "retry only failed revocation deliveries")
	dryRun := fs.Bool("dry-run", false, "count retryable revocation deliveries without mutating state")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError("Usage: continuum grant retry-revocations [--delivery-store .continuum/deliveries.json] [--failed-only] [--dry-run]")
	}
	cfg, err := loadConfigOrDefault(*configPath)
	if err != nil {
		return err
	}
	*deliveryPath = resolveDeliveryStorePath(*deliveryPath, cfg)
	report, err := cruntime.RetryGrantRevocationDeliveries(context.Background(), *deliveryPath, cruntime.GrantRevocationRetryOptions{
		FailedOnly: *failedOnly,
		DryRun:     *dryRun,
	}, cruntime.ObserveGrantRevocationDelivery)
	fmt.Fprintf(stdout, "retried revocations matched=%d attempted=%d delivered=%d failed=%d dry_run=%t store=%s\n", report.Matched, report.Attempted, report.Delivered, report.Failed, *dryRun, *deliveryPath)
	return err
}

func runGrantPrune(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("grant prune", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "continuum.toml", "config path")
	storePath := fs.String("store", defaultGrantStorePath, "grant store")
	deliveryPath := fs.String("delivery-store", defaultDeliveryStorePath, "delivery queue store")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfigOrDefault(*configPath)
	if err != nil {
		return err
	}
	*storePath = resolveGrantStorePath(*storePath, cfg)
	*deliveryPath = resolveDeliveryStorePath(*deliveryPath, cfg)
	removed, err := pruneExpiredGrantStore(*storePath, *deliveryPath, time.Now().UTC())
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "pruned grants removed=%d\n", removed)
	return nil
}

func pruneExpiredGrantStore(storePath, deliveryPath string, now time.Time) (int, error) {
	if storePath == "" {
		return 0, fmt.Errorf("grant store path is required")
	}
	if !fileExists(storePath) {
		return 0, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var expired []capability.Grant
	var removed int
	if err := capability.UpdateGrantStore(storePath, func(store *capability.GrantStore) error {
		expired = store.Expired(now)
		if len(expired) == 0 {
			return nil
		}
		for _, grant := range expired {
			if _, err := cruntime.EnqueueGrantRevocation(deliveryPath, grant, "grant expired", now); err != nil {
				return err
			}
		}
		removed = store.PruneExpired(now)
		return nil
	}); err != nil {
		return 0, err
	}
	return removed, nil
}
