package runtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"m31labs.dev/continuum/airlock"
	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/subject"
)

func TestHTTPHandlerServesHealthAndCapabilities(t *testing.T) {
	daemon := NewDaemon(nil)
	if err := daemon.Start(nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	handler := NewHTTPHandler(daemon)
	for _, path := range []string{"/healthz", "/capabilities"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("%s status = %d body=%s", path, res.Code, res.Body.String())
		}
		if !strings.Contains(res.Header().Get("content-type"), "application/json") {
			t.Fatalf("%s content-type = %s", path, res.Header().Get("content-type"))
		}
	}
}

func TestHTTPHandlerServesStateStores(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	sessionPath := filepath.Join(dir, "sessions.json")
	grantPath := filepath.Join(dir, "grants.json")
	airlockPath := filepath.Join(dir, "airlock.json")
	auditPath := filepath.Join(dir, "audit.jsonl")

	sessions := &SessionStore{}
	sessions.Upsert(Session{ID: "s1", State: SessionRunning, StartedAt: now})
	if err := sessions.Save(sessionPath); err != nil {
		t.Fatalf("save sessions: %v", err)
	}
	grants := &capability.GrantStore{}
	if err := grants.Add(capability.Grant{ID: "g1", Session: "s1", Capability: "network.connect", Scope: map[string]any{"host": "github.com"}, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("add grant: %v", err)
	}
	if err := grants.Save(grantPath); err != nil {
		t.Fatalf("save grants: %v", err)
	}
	airlocks := airlock.NewStore()
	if _, err := airlocks.Enter("a1", subject.NewProcessTree("demo", 123), "test", now); err != nil {
		t.Fatalf("enter airlock: %v", err)
	}
	if err := airlocks.Save(airlockPath); err != nil {
		t.Fatalf("save airlocks: %v", err)
	}
	sink, err := audit.NewJSONLSink(auditPath)
	if err != nil {
		t.Fatalf("audit sink: %v", err)
	}
	if err := sink.Write(context.Background(), audit.Event{ID: "evt_1", Time: now, InputEvent: event.Event{Kind: event.KindProcessExec}, Outcome: arbiterx.NewOutcome(arbiterx.OutcomeAllow, "Allow", map[string]any{"reason": "ok"})}); err != nil {
		t.Fatalf("write audit: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close audit: %v", err)
	}

	daemon := NewDaemon(nil)
	if err := daemon.Start(nil); err != nil {
		t.Fatalf("Start: %v", err)
	}
	handler := NewHTTPHandlerWithState(daemon, StatePaths{
		Sessions: sessionPath,
		Grants:   grantPath,
		Airlock:  airlockPath,
		Audit:    auditPath,
	})
	for _, path := range []string{"/sessions", "/grants", "/airlocks", "/audit"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("%s status = %d body=%s", path, res.Code, res.Body.String())
		}
		if !strings.Contains(res.Body.String(), `"s1"`) && !strings.Contains(res.Body.String(), `"g1"`) && !strings.Contains(res.Body.String(), `"a1"`) && !strings.Contains(res.Body.String(), `"evt_1"`) {
			t.Fatalf("%s body missing stored state: %s", path, res.Body.String())
		}
	}
}
