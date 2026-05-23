package runtime

import (
	"context"

	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
)

type EventHandler func(context.Context, event.Event) error

// RunSource is Continuum's generic event ingestion loop. Source implementations
// may be backed by Horizon, OS fixtures, tests, or future adapters, but the
// runtime only depends on the narrow capability.Source interface.
func RunSource(ctx context.Context, src capability.Source, handler EventHandler) error {
	return src.Start(ctx, func(ctx context.Context, evt event.Event) error {
		return handler(ctx, evt)
	})
}
