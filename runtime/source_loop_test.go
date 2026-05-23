package runtime

import (
	"context"
	"testing"

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
