package runtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientIngestPostsBatch(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/ingest" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.URL.Query().Get("delivery-store"); got != "/tmp/deliveries.json" {
			t.Fatalf("delivery-store query = %q", got)
		}
		if got := r.URL.Query().Get("session-store"); got != "/tmp/sessions.json" {
			t.Fatalf("session-store query = %q", got)
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"ingested":1,"policy":"p","audit":"a","records":[]}`))
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	result, err := NewClient(server.URL).Ingest(context.Background(), []byte(`{"kind":"process.exec"}`), ClientIngestOptions{
		DeliveryStore: "/tmp/deliveries.json",
		SessionStore:  "/tmp/sessions.json",
	})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if result.Ingested != 1 {
		t.Fatalf("result = %+v", result)
	}
}

func TestClientIngestReportsDaemonErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad event", http.StatusBadRequest)
	}))
	defer server.Close()
	_, err := NewClient(server.URL).Ingest(context.Background(), []byte(`{}`), ClientIngestOptions{})
	if err == nil || !strings.Contains(err.Error(), "bad event") {
		t.Fatalf("err = %v", err)
	}
}
