package runtime

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNormalizeListenAddressPrefersLocalhost(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{in: ":8787", want: "127.0.0.1:8787"},
		{in: "8787", want: "127.0.0.1:8787"},
		{in: "127.0.0.1:8788", want: "127.0.0.1:8788"},
		{in: "0.0.0.0:8789", want: "0.0.0.0:8789"},
		{in: "", want: ""},
	} {
		if got := NormalizeListenAddress(tc.in); got != tc.want {
			t.Fatalf("NormalizeListenAddress(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNewHTTPServerDefaultsTimeouts(t *testing.T) {
	server := NewHTTPServer(":8787", http.NewServeMux(), HTTPServerOptions{})
	if server.Addr != "127.0.0.1:8787" {
		t.Fatalf("addr = %q", server.Addr)
	}
	for name, got := range map[string]time.Duration{
		"read_header": server.ReadHeaderTimeout,
		"read":        server.ReadTimeout,
		"write":       server.WriteTimeout,
		"idle":        server.IdleTimeout,
	} {
		if got <= 0 {
			t.Fatalf("%s timeout = %s", name, got)
		}
	}
	if server.MaxHeaderBytes <= 0 {
		t.Fatalf("MaxHeaderBytes = %d", server.MaxHeaderBytes)
	}
}

func TestServeHTTPStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	server := NewHTTPServer("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), HTTPServerOptions{})
	done := make(chan error, 1)
	go func() {
		done <- ServeHTTP(ctx, server, time.Second)
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeHTTP shutdown err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestServeUnixCreatesPrivateSocketAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	socketPath := filepath.Join(t.TempDir(), "continuum.sock")
	done := make(chan error, 1)
	go func() {
		done <- ServeUnix(ctx, socketPath, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}), time.Second)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		info, err := os.Stat(socketPath)
		if err == nil {
			if got := info.Mode().Perm(); got != 0600 {
				t.Fatalf("socket mode = %v", got)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("socket was not created: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeUnix: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("unix server did not stop")
	}
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("socket was not removed: %v", err)
	}
}
