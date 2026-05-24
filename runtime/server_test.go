package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"m31labs.dev/continuum/airlock"
	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/horizon"
	"m31labs.dev/continuum/subject"
)

func TestHTTPHandlerServesHealthAndCapabilities(t *testing.T) {
	daemon := NewDaemon(nil)
	if err := daemon.Start(context.Background()); err != nil {
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

func TestHTTPHandlerServesReadiness(t *testing.T) {
	daemon := NewDaemon(nil)
	if err := daemon.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	handler := NewHTTPHandlerWithState(daemon, StatePaths{
		PolicyBundle: filepath.Join("..", "examples", "agent-workdir", "policies", "main.arb"),
	})
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("ready status = %d body=%s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"ready": true`) || !strings.Contains(res.Body.String(), `"registry"`) {
		t.Fatalf("ready body = %s", res.Body.String())
	}
}

func TestHTTPHandlerReadinessReportsPolicyFailure(t *testing.T) {
	daemon := NewDaemon(nil)
	if err := daemon.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	handler := NewHTTPHandlerWithState(daemon, StatePaths{PolicyBundle: filepath.Join(t.TempDir(), "missing.arb")})
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready status = %d body=%s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"ready": false`) || !strings.Contains(res.Body.String(), `"policy"`) {
		t.Fatalf("ready body = %s", res.Body.String())
	}
}

func TestHTTPHandlerReturnsStructuredMethodErrors(t *testing.T) {
	daemon := NewDaemon(nil)
	if err := daemon.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	handler := NewHTTPHandler(daemon)
	for _, tc := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/healthz"},
		{method: http.MethodPost, path: "/readyz"},
		{method: http.MethodPost, path: "/capabilities"},
		{method: http.MethodPost, path: "/sessions"},
		{method: http.MethodPost, path: "/grants"},
		{method: http.MethodPost, path: "/airlocks"},
		{method: http.MethodPost, path: "/deliveries"},
		{method: http.MethodPost, path: "/audit"},
		{method: http.MethodGet, path: "/ingest"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s status = %d body=%s", tc.method, tc.path, res.Code, res.Body.String())
		}
		if !strings.Contains(res.Header().Get("content-type"), "application/json") || !strings.Contains(res.Body.String(), `"error"`) {
			t.Fatalf("%s %s did not return structured error: content-type=%s body=%s", tc.method, tc.path, res.Header().Get("content-type"), res.Body.String())
		}
	}
}

func TestHTTPHandlerCORSSafeDefaultAndAllowlist(t *testing.T) {
	daemon := NewDaemon(nil)
	if err := daemon.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	handler := NewHTTPHandlerWithState(daemon, StatePaths{})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("origin", "https://console.example")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("default CORS status = %d body=%s", res.Code, res.Body.String())
	}
	handler = NewHTTPHandlerWithStateAndOptions(daemon, StatePaths{}, HTTPOptions{AllowedOrigins: []string{"https://console.example"}})
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("origin", "https://console.example")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK || res.Header().Get("Access-Control-Allow-Origin") != "https://console.example" {
		t.Fatalf("allowlist status = %d origin=%q body=%s", res.Code, res.Header().Get("Access-Control-Allow-Origin"), res.Body.String())
	}
}

func TestHTTPHandlerIngestsContinuumEvent(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	deliveryPath := filepath.Join(dir, "deliveries.json")
	daemon := NewDaemon(nil)
	if err := daemon.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	handler := NewHTTPHandlerWithState(daemon, StatePaths{
		PolicyBundle:        filepath.Join("..", "examples", "agent-workdir", "policies", "main.arb"),
		AirlockPolicy:       filepath.Join("..", "examples", "airlock", "policies", "main.arb"),
		Audit:               auditPath,
		Deliveries:          deliveryPath,
		Airlock:             filepath.Join(dir, "airlock.json"),
		AirlockAccumulators: filepath.Join(dir, "airlock-accumulators.json"),
	})
	body := `{
  "id": "evt_secret",
  "kind": "file.open",
  "subject": {
    "kind": "agent",
    "session": "agent-42",
    "agent_name": "claude",
    "repo_root": "/repo"
  },
  "fields": {
    "path": "/home/draco/.ssh/id_ed25519",
    "op": "read"
  }
}`
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/ingest", strings.NewReader(body)))
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"ingested": 1`) || !strings.Contains(res.Body.String(), `"decision": "deny"`) {
		t.Fatalf("response = %s", res.Body.String())
	}
	events, err := audit.ReadJSONL(auditPath)
	if err != nil {
		t.Fatalf("ReadJSONL: %v", err)
	}
	if len(events) != 1 || events[0].Decision != "deny" || len(events[0].Delivery) != 1 {
		t.Fatalf("audit events = %+v", events)
	}
	deliveries, err := LoadDeliveryStore(deliveryPath)
	if err != nil {
		t.Fatalf("LoadDeliveryStore: %v", err)
	}
	if got := deliveries.ByStatus(DeliveryDelivered); len(got) != 1 {
		t.Fatalf("delivered queue items = %+v", got)
	}
}

func TestHTTPHandlerRequiresAuthForMutatingEndpoints(t *testing.T) {
	dir := t.TempDir()
	daemon := NewDaemon(nil)
	if err := daemon.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	handler := NewHTTPHandlerWithStateAndOptions(daemon, StatePaths{
		PolicyBundle:        filepath.Join("..", "examples", "agent-workdir", "policies", "main.arb"),
		AirlockPolicy:       filepath.Join("..", "examples", "airlock", "policies", "main.arb"),
		Audit:               filepath.Join(dir, "audit.jsonl"),
		Airlock:             filepath.Join(dir, "airlock.json"),
		AirlockAccumulators: filepath.Join(dir, "airlock-accumulators.json"),
	}, HTTPOptions{AuthToken: "secret"})
	body := `{"kind":"process.exec","subject":{"session":"agent-42","agent_name":"claude","repo_root":"/repo"},"fields":{"comm":"go","argv_text":"go test ./...","cwd":"/repo"}}`
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/ingest", strings.NewReader(body)))
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d body=%s", res.Code, res.Body.String())
	}
	req := httptest.NewRequest(http.MethodPost, "/ingest", strings.NewReader(body))
	req.Header.Set("authorization", "Bearer secret")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("authenticated status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestHTTPHandlerRejectsUnsupportedIngestContentType(t *testing.T) {
	daemon := NewDaemon(nil)
	if err := daemon.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	handler := NewHTTPHandlerWithState(daemon, StatePaths{})
	req := httptest.NewRequest(http.MethodPost, "/ingest", strings.NewReader("{}"))
	req.Header.Set("content-type", "application/octet-stream")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestHTTPHandlerCanRequireAuthForReadEndpoints(t *testing.T) {
	daemon := NewDaemon(nil)
	if err := daemon.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	handler := NewHTTPHandlerWithStateAndOptions(daemon, StatePaths{}, HTTPOptions{
		AuthToken:           "secret",
		RequireAuthForReads: true,
	})
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d body=%s", res.Code, res.Body.String())
	}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Continuum-Token", "secret")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("authenticated status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestHTTPHandlerIngestsHorizonEnvelope(t *testing.T) {
	dir := t.TempDir()
	daemon := NewDaemon(horizon.DirProvider{Dir: filepath.Join("..", "testdata", "horizon-manifests")})
	if err := daemon.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	handler := NewHTTPHandlerWithState(daemon, StatePaths{
		PolicyBundle:        filepath.Join("..", "examples", "agent-workdir", "policies", "main.arb"),
		AirlockPolicy:       filepath.Join("..", "examples", "airlock", "policies", "main.arb"),
		Audit:               filepath.Join(dir, "audit.jsonl"),
		Sessions:            filepath.Join(dir, "sessions.json"),
		Airlock:             filepath.Join(dir, "airlock.json"),
		AirlockAccumulators: filepath.Join(dir, "airlock-accumulators.json"),
	})
	body := `{
  "id": "hzn_exec",
  "capability": "kernel.process.exec.observe",
  "subject": {
    "kind": "agent",
    "session": "agent-42",
    "agent_name": "claude",
    "repo_root": "/repo"
  },
  "fields": {
    "pid": 321,
    "comm": "go",
    "argv_text": "go test ./...",
    "cwd": "/repo"
  }
}`
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/ingest", strings.NewReader(body)))
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"decision": "allow"`) || !strings.Contains(res.Body.String(), `kernel.process.exec.observe`) {
		t.Fatalf("response = %s", res.Body.String())
	}
	sessions, err := LoadSessionStore(filepath.Join(dir, "sessions.json"))
	if err != nil {
		t.Fatalf("LoadSessionStore: %v", err)
	}
	if len(sessions.Sessions) != 1 || sessions.Sessions[0].ProcessTree == nil || sessions.Sessions[0].ProcessTree.RootPID != 321 {
		t.Fatalf("sessions = %+v", sessions.Sessions)
	}
}

func TestHTTPHandlerIngestTriggersAirlock(t *testing.T) {
	dir := t.TempDir()
	daemon := NewDaemon(nil)
	if err := daemon.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	handler := NewHTTPHandlerWithState(daemon, StatePaths{
		PolicyBundle:        filepath.Join("..", "examples", "agent-workdir", "policies", "main.arb"),
		AirlockPolicy:       filepath.Join("..", "examples", "airlock", "policies", "main.arb"),
		Audit:               filepath.Join(dir, "audit.jsonl"),
		Airlock:             filepath.Join(dir, "airlock.json"),
		AirlockAccumulators: filepath.Join(dir, "airlock-accumulators.json"),
	})
	subj := subject.NewAgent("claude", "agent-42", "/repo", "", 123)
	var events []event.Event
	for i := 0; i < 21; i++ {
		events = append(events, event.NewProcessExec(subj, map[string]any{"comm": "sh", "argv_text": "sh -c true", "cwd": "/repo"}))
	}
	for i := 0; i < 51; i++ {
		events = append(events, event.NewNetworkConnect(subj, "host-"+strconv.Itoa(i)+".example", "10.0.0."+strconv.Itoa(i), 443))
	}
	body, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/ingest", strings.NewReader(string(body))))
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"airlocks"`) || !strings.Contains(res.Body.String(), `"state": "airlocked"`) {
		t.Fatalf("response = %s", res.Body.String())
	}
	store, err := airlock.LoadStore(filepath.Join(dir, "airlock.json"))
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if len(store.List()) != 1 {
		t.Fatalf("airlocks = %+v", store.List())
	}
}

func TestHTTPHandlerServesStateStores(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	sessionPath := filepath.Join(dir, "sessions.json")
	grantPath := filepath.Join(dir, "grants.json")
	airlockPath := filepath.Join(dir, "airlock.json")
	deliveryPath := filepath.Join(dir, "deliveries.json")
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
	deliveries, err := LoadDeliveryStore(deliveryPath)
	if err != nil {
		t.Fatalf("load deliveries: %v", err)
	}
	if _, err := deliveries.Enqueue(DeliveryItem{AuditID: "evt_1", Capability: "observe.audit", Status: DeliveryPending, CreatedAt: now}); err != nil {
		t.Fatalf("enqueue delivery: %v", err)
	}
	if err := deliveries.Save(); err != nil {
		t.Fatalf("save deliveries: %v", err)
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
	if err := daemon.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	handler := NewHTTPHandlerWithState(daemon, StatePaths{
		Sessions:   sessionPath,
		Grants:     grantPath,
		Deliveries: deliveryPath,
		Airlock:    airlockPath,
		Audit:      auditPath,
	})
	for _, path := range []string{"/sessions", "/grants", "/deliveries", "/airlocks", "/audit"} {
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
