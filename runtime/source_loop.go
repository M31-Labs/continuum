package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
)

type EventHandler func(context.Context, event.Event) error

// RunSource is Continuum's generic event ingestion loop. Source implementations
// may be backed by Horizon, OS fixtures, tests, or future adapters, but the
// runtime only depends on the narrow capability.Source interface.
func RunSource(ctx context.Context, src capability.Source, handler EventHandler) error {
	return RunSourceWithHealth(ctx, src, handler, nil)
}

func RunSourceWithHealth(ctx context.Context, src capability.Source, handler EventHandler, health *SourceHealthStore) error {
	if src == nil {
		return fmt.Errorf("source is required")
	}
	if handler == nil {
		return fmt.Errorf("event handler is required")
	}
	name := strings.TrimSpace(src.Name())
	if name == "" {
		return fmt.Errorf("source name is required")
	}
	if health != nil {
		health.MarkStarting(name)
		health.MarkRunning(name)
	}
	err := src.Start(ctx, func(ctx context.Context, evt event.Event) error {
		if health != nil {
			health.RecordEvent(name)
		}
		return handler(ctx, evt)
	})
	if err != nil {
		if health != nil {
			if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
				health.MarkStopped(name)
			} else {
				health.MarkFailed(name, err)
			}
		}
		return err
	}
	if health != nil {
		health.MarkStopped(name)
	}
	return nil
}
