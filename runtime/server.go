package runtime

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"time"

	"m31labs.dev/continuum/airlock"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
)

type StatePaths struct {
	Sessions string
	Grants   string
	Airlock  string
	Audit    string
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
	return mux
}

func (p StatePaths) withDefaults() StatePaths {
	if p.Sessions == "" {
		p.Sessions = ".continuum/sessions.json"
	}
	if p.Grants == "" {
		p.Grants = ".continuum/grants.json"
	}
	if p.Airlock == "" {
		p.Airlock = ".continuum/airlock.json"
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
