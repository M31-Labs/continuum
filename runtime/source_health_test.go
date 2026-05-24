package runtime

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
)

func TestDaemonInitializesSourceHealthForRegisteredSources(t *testing.T) {
	daemon := NewDaemon(staticCapabilityProvider{caps: []capability.Capability{sourceCapability("kernel.process.exec.observe")}})
	if err := daemon.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	health := daemon.Health()
	if !health.OK {
		t.Fatalf("health not ok: %+v", health)
	}
	if health.SourceCount != 1 || len(health.SourceHealth) != 1 {
		t.Fatalf("source health count mismatch: %+v", health)
	}
	source := health.SourceHealth[0]
	if source.Name != "kernel.process.exec.observe" || source.Status != SourceStatusRegistered {
		t.Fatalf("source health = %+v", source)
	}
	if source.UpdatedAt.IsZero() {
		t.Fatalf("source health missing update time: %+v", source)
	}
}

func TestDaemonRunSourceUpdatesLifecycleHealth(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	daemon := NewDaemon(staticCapabilityProvider{caps: []capability.Capability{sourceCapability("kernel.process.exec.observe")}})
	if err := daemon.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	src := blockingSource{name: "kernel.process.exec.observe", started: make(chan struct{})}
	errc := make(chan error, 1)
	go func() {
		errc <- daemon.RunSource(ctx, src, func(context.Context, event.Event) error {
			return nil
		})
	}()
	<-src.started
	running := sourceHealthByName(t, daemon.SourceHealth(), "kernel.process.exec.observe")
	if running.Status != SourceStatusRunning || running.Events != 1 || running.StartedAt == nil || running.LastEventAt == nil {
		t.Fatalf("running source health = %+v", running)
	}
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("RunSource error = %v, want context canceled", err)
	}
	stopped := sourceHealthByName(t, daemon.SourceHealth(), "kernel.process.exec.observe")
	if stopped.Status != SourceStatusStopped || stopped.StoppedAt == nil || stopped.LastError != "" {
		t.Fatalf("stopped source health = %+v", stopped)
	}
}

func TestDaemonHealthReportsSourceFailure(t *testing.T) {
	daemon := NewDaemon(staticCapabilityProvider{caps: []capability.Capability{sourceCapability("kernel.file.open.observe")}})
	if err := daemon.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	errBoom := errors.New("source transport closed")
	err := daemon.RunSource(context.Background(), failingSource{name: "kernel.file.open.observe", err: errBoom}, func(context.Context, event.Event) error {
		return nil
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("RunSource error = %v, want %v", err, errBoom)
	}
	health := daemon.Health()
	if health.OK || health.SourceFailed != 1 || len(health.Issues) != 1 {
		t.Fatalf("failed source health = %+v", health)
	}
	source := sourceHealthByName(t, health.SourceHealth, "kernel.file.open.observe")
	if source.Status != SourceStatusFailed || source.LastError != "source transport closed" {
		t.Fatalf("failed source = %+v", source)
	}
}

func sourceCapability(name string) capability.Capability {
	return capability.Capability{
		Name:   name,
		Kind:   capability.KindSource,
		Owner:  "test",
		Output: "TestEvent",
		Danger: capability.DangerObserve,
	}
}

func sourceHealthByName(t *testing.T, sources []SourceHealth, name string) SourceHealth {
	t.Helper()
	for _, source := range sources {
		if source.Name == name {
			return source
		}
	}
	t.Fatalf("source %s not found in %+v", name, sources)
	return SourceHealth{}
}

type staticCapabilityProvider struct {
	caps []capability.Capability
	err  error
}

func (p staticCapabilityProvider) LoadCapabilities(context.Context) ([]capability.Capability, error) {
	if p.err != nil {
		return nil, p.err
	}
	return append([]capability.Capability(nil), p.caps...), nil
}

type blockingSource struct {
	name    string
	started chan struct{}
}

func (s blockingSource) Name() string { return s.name }

func (s blockingSource) Start(ctx context.Context, emit capability.EmitFunc) error {
	if err := emit(ctx, event.Event{ID: "evt_source", Kind: event.KindProcessExec}); err != nil {
		return err
	}
	close(s.started)
	<-ctx.Done()
	return ctx.Err()
}

type failingSource struct {
	name string
	err  error
}

func (s failingSource) Name() string { return s.name }

func (s failingSource) Start(context.Context, capability.EmitFunc) error {
	if s.err == nil {
		return fmt.Errorf("source failed")
	}
	return s.err
}
