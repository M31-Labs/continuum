package runtime

import (
	"context"
	"errors"
	"testing"
	"time"

	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
)

func TestRunSourceIngestsGenericContinuumEvents(t *testing.T) {
	src := fakeSource{events: []event.Event{{ID: "evt_1", Kind: event.KindProcessExec}}}
	var got []event.Event
	err := RunSource(context.Background(), src, func(_ context.Context, evt event.Event) error {
		got = append(got, evt)
		return nil
	})
	if err != nil {
		t.Fatalf("RunSource: %v", err)
	}
	if len(got) != 1 || got[0].ID != "evt_1" {
		t.Fatalf("got events = %+v", got)
	}
}

func TestRunSourceAppliesBoundedBackpressure(t *testing.T) {
	beforeThird := make(chan struct{})
	afterThird := make(chan struct{})
	handlerBlocked := make(chan struct{})
	releaseHandler := make(chan struct{})
	health := NewSourceHealthStore()
	src := backpressureSource{beforeThird: beforeThird, afterThird: afterThird}
	var got []event.Event
	done := make(chan error, 1)
	go func() {
		done <- RunSourceWithOptions(context.Background(), src, func(_ context.Context, evt event.Event) error {
			got = append(got, evt)
			if evt.ID == "evt_1" {
				close(handlerBlocked)
				<-releaseHandler
			}
			return nil
		}, SourceLoopOptions{BufferSize: 1, Health: health})
	}()

	waitForSignal(t, handlerBlocked, "handler to block")
	waitForSignal(t, beforeThird, "source to attempt third event")
	select {
	case <-afterThird:
		t.Fatal("source emitted past full queue before handler drained")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseHandler)
	if err := <-done; err != nil {
		t.Fatalf("RunSourceWithOptions: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("handled events = %+v", got)
	}
	source := sourceHealthByName(t, health.List(), "fake")
	if source.QueueCapacity != 1 || source.BackpressureEvents == 0 {
		t.Fatalf("source health did not record bounded backpressure: %+v", source)
	}
}

func TestRunSourceReturnsHandlerError(t *testing.T) {
	health := NewSourceHealthStore()
	errHandler := errors.New("handler failed")
	err := RunSourceWithOptions(context.Background(), fakeSource{events: []event.Event{{ID: "evt_1", Kind: event.KindProcessExec}}}, func(context.Context, event.Event) error {
		return errHandler
	}, SourceLoopOptions{BufferSize: 1, Health: health})
	if !errors.Is(err, errHandler) {
		t.Fatalf("RunSourceWithOptions error = %v, want %v", err, errHandler)
	}
	source := sourceHealthByName(t, health.List(), "fake")
	if source.Status != SourceStatusFailed || source.LastError != "handler failed" {
		t.Fatalf("source health = %+v", source)
	}
}

type fakeSource struct {
	events []event.Event
}

func (f fakeSource) Name() string { return "fake" }

func (f fakeSource) Start(ctx context.Context, emit capability.EmitFunc) error {
	for _, evt := range f.events {
		if err := emit(ctx, evt); err != nil {
			return err
		}
	}
	return nil
}

type backpressureSource struct {
	beforeThird chan struct{}
	afterThird  chan struct{}
}

func (s backpressureSource) Name() string { return "fake" }

func (s backpressureSource) Start(ctx context.Context, emit capability.EmitFunc) error {
	ids := []string{"evt_1", "evt_2", "evt_3"}
	for i := 1; i <= 3; i++ {
		if i == 3 {
			close(s.beforeThird)
		}
		if err := emit(ctx, event.Event{ID: ids[i-1], Kind: event.KindProcessExec}); err != nil {
			return err
		}
		if i == 3 {
			close(s.afterThird)
		}
	}
	return nil
}

func waitForSignal(t *testing.T, ch <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", label)
	}
}
