package capability

import (
	"context"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/subject"
)

type Delivery struct {
	Subject subject.Subject  `json:"subject"`
	Event   event.Event      `json:"event"`
	Outcome arbiterx.Outcome `json:"outcome"`
}

type Sink interface {
	Name() string
	Deliver(context.Context, Delivery) error
}
