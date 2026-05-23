package runtime

import (
	"context"
	"fmt"
	"os"

	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
)

type FixtureSource struct {
	NameValue string
	Path      string
	Events    []event.Event
	Registry  *capability.Registry
}

func NewFixtureSource(path string, registry *capability.Registry) FixtureSource {
	return FixtureSource{NameValue: "fixture", Path: path, Registry: registry}
}

func (s FixtureSource) Name() string {
	if s.NameValue != "" {
		return s.NameValue
	}
	return "fixture"
}

func (s FixtureSource) Start(ctx context.Context, emit capability.EmitFunc) error {
	if emit == nil {
		return fmt.Errorf("emit function is required")
	}
	events := append([]event.Event(nil), s.Events...)
	if s.Path != "" {
		data, err := os.ReadFile(s.Path)
		if err != nil {
			return fmt.Errorf("read fixture source %s: %w", s.Path, err)
		}
		decoded, err := DecodeEvents(data, s.Registry)
		if err != nil {
			return err
		}
		events = append(events, decoded...)
	}
	for _, evt := range events {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := emit(ctx, evt); err != nil {
			return err
		}
	}
	return nil
}
