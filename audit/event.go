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

const (
	ClockSourceRuntimeEngine     = "runtime.engine.now"
	ClockSourceApprovalFlow      = "approval.flow.now"
	ClockSourceAirlockCLI        = "airlock.cli.now"
	EventTimeSourceInputEvent    = "input_event"
	EventTimeSourceRecordedClock = "recorded_clock"
)

type Event struct {
	ID          string            `json:"id"`
	Time        time.Time         `json:"time"`
	Clock       *ClockMetadata    `json:"clock,omitempty"`
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
	ChainPrev   string            `json:"chain_prev,omitempty"`
	ChainHash   string            `json:"chain_hash,omitempty"`
}

type ClockMetadata struct {
	Source          string    `json:"source"`
	RecordedAt      time.Time `json:"recorded_at"`
	EventTimeSource string    `json:"event_time_source"`
}

type DeliveryAttempt struct {
	DeliveryID  string    `json:"delivery_id,omitempty"`
	Time        time.Time `json:"time"`
	Capability  string    `json:"capability"`
	Enforcement string    `json:"enforcement,omitempty"`
	Status      string    `json:"status"`
	Error       string    `json:"error,omitempty"`
}
