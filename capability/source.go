package capability

import (
	"context"

	"m31labs.dev/continuum/event"
)

type EmitFunc func(context.Context, event.Event) error

type Source interface {
	Name() string
	Start(context.Context, EmitFunc) error
}
