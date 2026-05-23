package audit

import (
	"context"
	"time"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/subject"
)

type Sink interface {
	Write(context.Context, Event) error
}

type NopSink struct{}

func (NopSink) Write(context.Context, Event) error { return nil }

type Event struct {
	ID          string            `json:"id"`
	Time        time.Time         `json:"time"`
	Subject     subject.Subject   `json:"subject"`
	InputEvent  event.Event       `json:"input_event"`
	Policy      string            `json:"policy,omitempty"`
	Outcome     arbiterx.Outcome  `json:"outcome"`
	Decision    string            `json:"decision"`
	Reason      string            `json:"reason,omitempty"`
	Arbitraces  []arbiterx.Step   `json:"arbitraces,omitempty"`
	Capability  string            `json:"capability,omitempty"`
	Enforcement string            `json:"enforcement,omitempty"`
	Delivery    []DeliveryAttempt `json:"delivery,omitempty"`
}

type DeliveryAttempt struct {
	Time        time.Time `json:"time"`
	Capability  string    `json:"capability"`
	Enforcement string    `json:"enforcement,omitempty"`
	Status      string    `json:"status"`
	Error       string    `json:"error,omitempty"`
}
