package runtime

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type HTTPServerOptions struct {
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
}

func NewHTTPServer(addr string, handler http.Handler, opts HTTPServerOptions) *http.Server {
	if opts.ReadHeaderTimeout == 0 {
		opts.ReadHeaderTimeout = 5 * time.Second
	}
	if opts.ReadTimeout == 0 {
		opts.ReadTimeout = 30 * time.Second
	}
	if opts.WriteTimeout == 0 {
		opts.WriteTimeout = 30 * time.Second
	}
	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = 60 * time.Second
	}
	if opts.MaxHeaderBytes == 0 {
		opts.MaxHeaderBytes = 1 << 20
	}
	return &http.Server{
		Addr:              NormalizeListenAddress(addr),
		Handler:           handler,
		ReadHeaderTimeout: opts.ReadHeaderTimeout,
		ReadTimeout:       opts.ReadTimeout,
		WriteTimeout:      opts.WriteTimeout,
		IdleTimeout:       opts.IdleTimeout,
		MaxHeaderBytes:    opts.MaxHeaderBytes,
	}
}

func ListenAndServe(addr string, handler http.Handler) error {
	return NewHTTPServer(addr, handler, HTTPServerOptions{}).ListenAndServe()
}

func ServeHTTP(ctx context.Context, server *http.Server, shutdownTimeout time.Duration) error {
	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return err
	}
	return ServeHTTPOnListener(ctx, server, ln, shutdownTimeout)
}

func ServeUnix(ctx context.Context, socketPath string, handler http.Handler, shutdownTimeout time.Duration) error {
	if socketPath == "" {
		return errors.New("unix socket path is required")
	}
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer os.Remove(socketPath)
	if err := os.Chmod(socketPath, 0600); err != nil {
		_ = ln.Close()
		return err
	}
	return ServeHTTPOnListener(ctx, NewHTTPServer("", handler, HTTPServerOptions{}), ln, shutdownTimeout)
}

func ServeHTTPOnListener(ctx context.Context, server *http.Server, ln net.Listener, shutdownTimeout time.Duration) error {
	if shutdownTimeout == 0 {
		shutdownTimeout = 10 * time.Second
	}
	errc := make(chan error, 1)
	go func() {
		errc <- server.Serve(ln)
	}()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		err := <-errc
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func NormalizeListenAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	if strings.Count(addr, ":") == 0 {
		return net.JoinHostPort("127.0.0.1", addr)
	}
	return addr
}
