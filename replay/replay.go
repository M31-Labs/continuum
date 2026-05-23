package replay

import (
	"context"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/event"
)

type Result struct {
	Event    event.Event       `json:"event"`
	Decision arbiterx.Decision `json:"decision"`
}

func Events(ctx context.Context, bundle *arbiterx.Bundle, events []event.Event) ([]Result, error) {
	results := make([]Result, 0, len(events))
	for _, evt := range events {
		decision, err := arbiterx.Evaluate(ctx, bundle, event.Normalize(evt))
		if err != nil {
			return nil, err
		}
		results = append(results, Result{Event: evt, Decision: decision})
	}
	return results, nil
}
