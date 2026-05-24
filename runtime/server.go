package runtime

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"m31labs.dev/continuum/airlock"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
)

type StatePaths struct {
	PolicyStore         string
	PolicyBundle        string
	Sessions            string
	Grants              string
	Deliveries          string
	IDStore             string
	Airlock             string
	AirlockAccumulators string
	AirlockPolicy       string
	Audit               string
}

type HTTPOptions struct {
	AuthToken               string
	RequireAuthForReads     bool
	MaxBodyBytes            int64
	AllowedOrigins          []string
	AllowPathQueryOverrides bool
}

func NewHTTPHandler(daemon *Daemon) http.Handler {
	return NewHTTPHandlerWithState(daemon, StatePaths{})
}

func NewHTTPHandlerWithState(daemon *Daemon, paths StatePaths) http.Handler {
	return NewHTTPHandlerWithStateAndOptions(daemon, paths, HTTPOptions{})
}

func NewHTTPHandlerWithStateAndOptions(daemon *Daemon, paths StatePaths, opts HTTPOptions) http.Handler {
	paths = paths.withDefaults()
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 32 << 20
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if !authorizeHTTP(w, r, opts, false) {
			return
		}
		writeJSON(w, daemon.Health())
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if !authorizeHTTP(w, r, opts, false) {
			return
		}
		status := CheckReadiness(daemon, paths)
		if !status.Ready {
			writeJSONStatus(w, http.StatusServiceUnavailable, status)
			return
		}
		writeJSON(w, status)
	})
	mux.HandleFunc("/capabilities", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if !authorizeHTTP(w, r, opts, false) {
			return
		}
		if daemon == nil || daemon.Registry == nil {
			writeError(w, http.StatusServiceUnavailable, "daemon not initialized")
			return
		}
		writeJSON(w, daemon.Registry.List())
	})
	mux.HandleFunc("/sessions", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if !authorizeHTTP(w, r, opts, false) {
			return
		}
		path, ok := queryPath(w, r, opts, "path", paths.Sessions)
		if !ok {
			return
		}
		store, err := LoadSessionStore(path)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, store.Sessions)
	})
	mux.HandleFunc("/grants", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if !authorizeHTTP(w, r, opts, false) {
			return
		}
		path, ok := queryPath(w, r, opts, "path", paths.Grants)
		if !ok {
			return
		}
		store, err := capability.LoadGrantStore(path)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if truthy(r.URL.Query().Get("all")) {
			writeJSON(w, store.Grants)
			return
		}
		writeJSON(w, store.Active(time.Now().UTC()))
	})
	mux.HandleFunc("/airlocks", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if !authorizeHTTP(w, r, opts, false) {
			return
		}
		path, ok := queryPath(w, r, opts, "path", paths.Airlock)
		if !ok {
			return
		}
		store, err := airlock.LoadStore(path)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, store.List())
	})
	mux.HandleFunc("/deliveries", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if !authorizeHTTP(w, r, opts, false) {
			return
		}
		path, ok := queryPathAny(w, r, opts, []string{"path", "delivery-store", "delivery_store"}, paths.Deliveries)
		if !ok {
			return
		}
		store, err := LoadDeliveryStore(path)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		items := store.List()
		if status := r.URL.Query().Get("status"); status != "" {
			items = store.ByStatus(DeliveryStatus(status))
		}
		writeJSON(w, items)
	})
	mux.HandleFunc("/audit", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if !authorizeHTTP(w, r, opts, false) {
			return
		}
		path, ok := queryPath(w, r, opts, "path", paths.Audit)
		if !ok {
			return
		}
		events, err := audit.ReadJSONL(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeJSON(w, []audit.Event{})
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if limit := queryLimit(r); limit > 0 && len(events) > limit {
			events = events[len(events)-limit:]
		}
		writeJSON(w, events)
	})
	mux.HandleFunc("/ingest", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		if !authorizeHTTP(w, r, opts, true) {
			return
		}
		if !acceptsIngestContentType(r.Header.Get("content-type")) {
			writeError(w, http.StatusUnsupportedMediaType, "unsupported content type")
			return
		}
		if daemon == nil || daemon.Registry == nil {
			writeError(w, http.StatusServiceUnavailable, "daemon not initialized")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, opts.MaxBodyBytes))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		events, err := DecodeEvents(body, daemon.Registry)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		policyPath, ok := queryPathAny(w, r, opts, []string{"policy", "policy_path"}, paths.PolicyBundle)
		if !ok {
			return
		}
		policyStore, ok := queryPathAny(w, r, opts, []string{"policy-store", "policy_store"}, paths.PolicyStore)
		if !ok {
			return
		}
		sessionStore, ok := queryPathAny(w, r, opts, []string{"sessions", "session-store", "session_store"}, paths.Sessions)
		if !ok {
			return
		}
		grantStore, ok := queryPathAny(w, r, opts, []string{"grants", "grant-store", "grant_store"}, paths.Grants)
		if !ok {
			return
		}
		deliveryStore, ok := queryPathAny(w, r, opts, []string{"delivery-store", "delivery_store"}, paths.Deliveries)
		if !ok {
			return
		}
		idStore, ok := queryPathAny(w, r, opts, []string{"id-store", "id_store"}, paths.IDStore)
		if !ok {
			return
		}
		auditPath, ok := queryPathAny(w, r, opts, []string{"audit", "audit_path"}, paths.Audit)
		if !ok {
			return
		}
		airlockPolicy, ok := queryPathAny(w, r, opts, []string{"airlock-policy", "airlock_policy"}, paths.AirlockPolicy)
		if !ok {
			return
		}
		airlockStore, ok := queryPathAny(w, r, opts, []string{"airlock-store", "airlock_store"}, paths.Airlock)
		if !ok {
			return
		}
		airlockAccumulators, ok := queryPathAny(w, r, opts, []string{"airlock-accumulators", "airlock_accumulators", "airlock-accumulator-store", "airlock_accumulator_store"}, paths.AirlockAccumulators)
		if !ok {
			return
		}
		result, err := IngestEvents(r.Context(), events, IngestOptions{
			PolicyPath:    policyPath,
			PolicyStore:   policyStore,
			SessionStore:  sessionStore,
			GrantStore:    grantStore,
			DeliveryStore: deliveryStore,
			IDStore:       idStore,
			AuditPath:     auditPath,
			Registry:      daemon.Registry,
			EnableAirlock: !truthy(r.URL.Query().Get("no_airlock")),
			Airlock: AirlockOptions{
				PolicyPath:           airlockPolicy,
				StorePath:            airlockStore,
				AccumulatorStorePath: airlockAccumulators,
				AuditPath:            auditPath,
			},
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, result)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !applyCORS(w, r, opts) {
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func acceptsIngestContentType(value string) bool {
	if value == "" {
		return true
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
	switch mediaType {
	case "application/json", "application/x-ndjson", "application/jsonl", "text/plain":
		return true
	default:
		return false
	}
}

func authorizeHTTP(w http.ResponseWriter, r *http.Request, opts HTTPOptions, mutating bool) bool {
	if opts.AuthToken == "" || (!mutating && !opts.RequireAuthForReads) {
		return true
	}
	if subtle.ConstantTimeCompare([]byte(requestAuthToken(r)), []byte(opts.AuthToken)) == 1 {
		return true
	}
	writeError(w, http.StatusUnauthorized, "unauthorized")
	return false
}

func requestAuthToken(r *http.Request) string {
	if token := r.Header.Get("X-Continuum-Token"); token != "" {
		return token
	}
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return strings.TrimSpace(header[len("bearer "):])
	}
	return ""
}

func applyCORS(w http.ResponseWriter, r *http.Request, opts HTTPOptions) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	if !originAllowed(origin, opts.AllowedOrigins) {
		writeError(w, http.StatusForbidden, "cors origin denied")
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Continuum-Token")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return false
	}
	return true
}

func originAllowed(origin string, allowed []string) bool {
	for _, candidate := range allowed {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == origin {
			return true
		}
	}
	return false
}

func (p StatePaths) withDefaults() StatePaths {
	if p.PolicyStore == "" {
		p.PolicyStore = ".continuum/policies.json"
	}
	if p.PolicyBundle == "" {
		p.PolicyBundle = DefaultPolicyPath
	}
	if p.Sessions == "" {
		p.Sessions = ".continuum/sessions.json"
	}
	if p.Grants == "" {
		p.Grants = ".continuum/grants.json"
	}
	if p.Deliveries == "" {
		p.Deliveries = ".continuum/deliveries.json"
	}
	if p.IDStore == "" {
		p.IDStore = ".continuum/ids.json"
	}
	if p.Airlock == "" {
		p.Airlock = ".continuum/airlock.json"
	}
	if p.AirlockAccumulators == "" {
		p.AirlockAccumulators = ".continuum/airlock-accumulators.json"
	}
	if p.AirlockPolicy == "" {
		p.AirlockPolicy = DefaultAirlockPolicyPath
	}
	if p.Audit == "" {
		p.Audit = ".continuum/audit.jsonl"
	}
	return p
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	return false
}

func queryPath(w http.ResponseWriter, r *http.Request, opts HTTPOptions, key, fallback string) (string, bool) {
	if value := r.URL.Query().Get(key); value != "" {
		if !opts.AllowPathQueryOverrides {
			writeError(w, http.StatusForbidden, "path query overrides disabled")
			return "", false
		}
		return value, true
	}
	return fallback, true
}

func queryPathAny(w http.ResponseWriter, r *http.Request, opts HTTPOptions, keys []string, fallback string) (string, bool) {
	for _, key := range keys {
		if value := r.URL.Query().Get(key); value != "" {
			if !opts.AllowPathQueryOverrides {
				writeError(w, http.StatusForbidden, "path query overrides disabled")
				return "", false
			}
			return value, true
		}
	}
	return fallback, true
}

func queryLimit(r *http.Request) int {
	value := r.URL.Query().Get("limit")
	if value == "" {
		return 0
	}
	limit, err := strconv.Atoi(value)
	if err != nil || limit < 0 {
		return 0
	}
	return limit
}

func truthy(value string) bool {
	switch value {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	writeJSONStatus(w, http.StatusOK, value)
}

func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("content-type", "application/json")
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
