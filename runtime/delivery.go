package runtime

import (
	"context"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
)

func DeliveryFor(evt event.Event, outcome arbiterx.Outcome) capability.Delivery {
	return capability.Delivery{
		Subject: evt.Subject,
		Event:   evt,
		Outcome: outcome,
	}
}

func Deliver(ctx context.Context, sink capability.Sink, delivery capability.Delivery) error {
	return sink.Deliver(ctx, delivery)
}
