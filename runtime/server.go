package runtime

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"m31labs.dev/continuum/airlock"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
)

type StatePaths struct {
	PolicyStore   string
	PolicyBundle  string
	Sessions      string
	Grants        string
	Deliveries    string
	Airlock       string
	AirlockPolicy string
	Audit         string
}

func NewHTTPHandler(daemon *Daemon) http.Handler {
	return NewHTTPHandlerWithState(daemon, StatePaths{})
}

func NewHTTPHandlerWithState(daemon *Daemon, paths StatePaths) http.Handler {
	paths = paths.withDefaults()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if !requireGET(w, r) {
			return
		}
		writeJSON(w, daemon.Health())
	})
	mux.HandleFunc("/capabilities", func(w http.ResponseWriter, r *http.Request) {
		if !requireGET(w, r) {
			return
		}
		if daemon == nil || daemon.Registry == nil {
			writeError(w, http.StatusServiceUnavailable, "daemon not initialized")
			return
		}
		writeJSON(w, daemon.Registry.List())
	})
	mux.HandleFunc("/sessions", func(w http.ResponseWriter, r *http.Request) {
		if !requireGET(w, r) {
			return
		}
		store, err := LoadSessionStore(queryPath(r, "path", paths.Sessions))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, store.Sessions)
	})
	mux.HandleFunc("/grants", func(w http.ResponseWriter, r *http.Request) {
		if !requireGET(w, r) {
			return
		}
		store, err := capability.LoadGrantStore(queryPath(r, "path", paths.Grants))
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
		if !requireGET(w, r) {
			return
		}
		store, err := airlock.LoadStore(queryPath(r, "path", paths.Airlock))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, store.List())
	})
	mux.HandleFunc("/deliveries", func(w http.ResponseWriter, r *http.Request) {
		if !requireGET(w, r) {
			return
		}
		store, err := LoadDeliveryStore(queryPathAny(r, []string{"path", "delivery-store", "delivery_store"}, paths.Deliveries))
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
		if !requireGET(w, r) {
			return
		}
		events, err := audit.ReadJSONL(queryPath(r, "path", paths.Audit))
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
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if daemon == nil || daemon.Registry == nil {
			writeError(w, http.StatusServiceUnavailable, "daemon not initialized")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32<<20))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		events, err := DecodeEvents(body, daemon.Registry)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		result, err := IngestEvents(r.Context(), events, IngestOptions{
			PolicyPath:    queryPathAny(r, []string{"policy", "policy_path"}, paths.PolicyBundle),
			PolicyStore:   queryPathAny(r, []string{"policy-store", "policy_store"}, paths.PolicyStore),
			SessionStore:  queryPathAny(r, []string{"sessions", "session-store", "session_store"}, paths.Sessions),
			GrantStore:    queryPathAny(r, []string{"grants", "grant-store", "grant_store"}, paths.Grants),
			DeliveryStore: queryPathAny(r, []string{"delivery-store", "delivery_store"}, paths.Deliveries),
			AuditPath:     queryPathAny(r, []string{"audit", "audit_path"}, paths.Audit),
			Registry:      daemon.Registry,
			EnableAirlock: !truthy(r.URL.Query().Get("no_airlock")),
			Airlock: AirlockOptions{
				PolicyPath: queryPathAny(r, []string{"airlock-policy", "airlock_policy"}, paths.AirlockPolicy),
				StorePath:  queryPathAny(r, []string{"airlock-store", "airlock_store"}, paths.Airlock),
				AuditPath:  queryPathAny(r, []string{"audit", "audit_path"}, paths.Audit),
			},
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, result)
	})
	return mux
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
	if p.Airlock == "" {
		p.Airlock = ".continuum/airlock.json"
	}
	if p.AirlockPolicy == "" {
		p.AirlockPolicy = DefaultAirlockPolicyPath
	}
	if p.Audit == "" {
		p.Audit = ".continuum/audit.jsonl"
	}
	return p
}

func requireGET(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet {
		return true
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
	return false
}

func queryPath(r *http.Request, key, fallback string) string {
	if value := r.URL.Query().Get(key); value != "" {
		return value
	}
	return fallback
}

func queryPathAny(r *http.Request, keys []string, fallback string) string {
	for _, key := range keys {
		if value := r.URL.Query().Get(key); value != "" {
			return value
		}
	}
	return fallback
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
	w.Header().Set("content-type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
