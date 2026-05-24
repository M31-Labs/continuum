package runtime

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/enforcement"
	"m31labs.dev/continuum/event"
)

type Engine struct {
	Bundle      *arbiterx.Bundle
	Audit       audit.Sink
	Registry    *capability.Registry
	Network     enforcement.NetworkBackend
	Process     enforcement.ProcessBackend
	File        enforcement.FileBackend
	Grants      []capability.Grant
	Queue       *DeliveryStore
	Enforcement string
	Now         func() time.Time
	NewID       IDFunc
}

func NewEngine(bundle *arbiterx.Bundle, sink audit.Sink) *Engine {
	reg := capability.NewRegistry()
	for _, cap := range capability.BuiltIns() {
		_ = reg.Register(cap)
	}
	return &Engine{
		Bundle:      bundle,
		Audit:       sink,
		Registry:    reg,
		Network:     enforcement.ObserveBackend{},
		Process:     enforcement.ObserveBackend{},
		File:        enforcement.ObserveBackend{},
		Enforcement: "observe",
		Now:         func() time.Time { return time.Now().UTC() },
	}
}

func (e *Engine) DecideEvent(ctx context.Context, evt event.Event) (audit.Event, arbiterx.Decision, error) {
	facts := event.Normalize(evt)
	now := e.now()
	for _, grant := range e.Grants {
		if grant.Active(now) {
			facts = append(facts, grant.Fact(evt.Subject))
		}
	}
	return e.DecideFacts(ctx, evt, facts)
}

func (e *Engine) DecideFacts(ctx context.Context, evt event.Event, facts []arbiterx.Fact) (audit.Event, arbiterx.Decision, error) {
	if e == nil {
		return audit.Event{}, arbiterx.Decision{}, fmt.Errorf("nil engine")
	}
	decision, err := arbiterx.Evaluate(ctx, e.Bundle, facts)
	if err != nil {
		return audit.Event{}, decision, err
	}
	record, err := e.auditEvent(evt, decision)
	if err != nil {
		return audit.Event{}, decision, err
	}
	var deliveryErr error
	if decision.Selected != nil {
		queueItem, err := e.enqueueDelivery(record, evt, *decision.Selected)
		if err != nil {
			return record, decision, err
		}
		attempt := audit.DeliveryAttempt{
			DeliveryID:  queueItem.ID,
			Time:        e.now(),
			Capability:  record.Capability,
			Enforcement: e.enforcementName(),
			Status:      "delivered",
		}
		if err := e.apply(ctx, evt, *decision.Selected); err != nil {
			attempt.Status = "failed"
			attempt.Error = err.Error()
			deliveryErr = err
		}
		record.Delivery = append(record.Delivery, attempt)
		if queueItem.ID != "" {
			if err := e.recordDeliveryAttempt(queueItem.ID, attempt); err != nil {
				return record, decision, err
			}
		}
	}
	if e.Audit != nil {
		if err := e.Audit.Write(ctx, record); err != nil {
			return record, decision, err
		}
	}
	return record, decision, deliveryErr
}

func (e *Engine) enqueueDelivery(record audit.Event, evt event.Event, outcome arbiterx.Outcome) (DeliveryItem, error) {
	if e == nil || e.Queue == nil {
		return DeliveryItem{}, nil
	}
	item := DeliveryItem{
		AuditID:     record.ID,
		EventID:     evt.ID,
		Capability:  record.Capability,
		Enforcement: e.enforcementName(),
		Delivery:    DeliveryFor(evt, outcome),
		Status:      DeliveryPending,
		CreatedAt:   e.now(),
		UpdatedAt:   e.now(),
	}
	if e.Queue.Path != "" {
		var enqueued DeliveryItem
		err := UpdateDeliveryStore(e.Queue.Path, func(queue *DeliveryStore) error {
			var err error
			enqueued, err = queue.Enqueue(item)
			if err == nil {
				e.Queue = queue
			}
			return err
		})
		return enqueued, err
	}
	item, err := e.Queue.Enqueue(item)
	if err != nil {
		return DeliveryItem{}, err
	}
	if err := e.Queue.Save(); err != nil {
		return DeliveryItem{}, err
	}
	return item, nil
}

func (e *Engine) recordDeliveryAttempt(id string, attempt audit.DeliveryAttempt) error {
	if e == nil || e.Queue == nil {
		return nil
	}
	if e.Queue.Path != "" {
		return UpdateDeliveryStore(e.Queue.Path, func(queue *DeliveryStore) error {
			if _, err := queue.RecordAttempt(id, attempt); err != nil {
				return err
			}
			e.Queue = queue
			return nil
		})
	}
	if _, err := e.Queue.RecordAttempt(id, attempt); err != nil {
		return err
	}
	return e.Queue.Save()
}

func (e *Engine) auditEvent(evt event.Event, decision arbiterx.Decision) (audit.Event, error) {
	now := e.now()
	eventTimeSource := audit.EventTimeSourceInputEvent
	if evt.Time.IsZero() {
		evt.Time = now
		eventTimeSource = audit.EventTimeSourceRecordedClock
	}
	id := evt.ID
	if id == "" {
		if e.NewID != nil {
			var err error
			id, err = e.NewID()
			if err != nil {
				return audit.Event{}, err
			}
		} else {
			id = fmt.Sprintf("evt_%d", now.UnixNano())
		}
	}

	outcome := arbiterx.NewOutcome(arbiterx.OutcomeAudit, "NoDecision", map[string]any{
		"reason": "no outcome selected",
	})
	if decision.Selected != nil {
		outcome = *decision.Selected
	}
	policyID := ""
	if e.Bundle != nil {
		policyID = e.Bundle.ID
	}
	return audit.Event{
		ID:          id,
		Time:        now,
		Clock:       &audit.ClockMetadata{Source: audit.ClockSourceRuntimeEngine, RecordedAt: now, EventTimeSource: eventTimeSource},
		Subject:     evt.Subject,
		InputEvent:  evt,
		Policy:      policyID,
		Outcome:     outcome,
		Decision:    outcome.Decision(),
		Reason:      outcome.Reason(),
		Arbitraces:  decision.Arbitrace,
		Capability:  e.RouteCapability(evt, outcome),
		Enforcement: e.enforcementName(),
	}, nil
}

func (e *Engine) now() time.Time {
	if e != nil && e.Now != nil {
		return e.Now()
	}
	return time.Now().UTC()
}

func (e *Engine) enforcementName() string {
	if e == nil || e.Enforcement == "" {
		return "observe"
	}
	return e.Enforcement
}

func (e *Engine) apply(ctx context.Context, evt event.Event, outcome arbiterx.Outcome) error {
	switch outcome.Name {
	case arbiterx.OutcomeGrantNetwork:
		if e.Network == nil {
			return nil
		}
		return e.Network.Grant(ctx, enforcement.NetworkGrant{
			Session: evt.Subject.Session,
			Host:    stringOutcome(outcome, "host"),
			Port:    intOutcome(outcome, "port"),
			Reason:  outcome.Reason(),
		})
	case arbiterx.OutcomeDeny:
		switch evt.Kind {
		case event.KindNetworkConnect:
			if e.Network == nil {
				return nil
			}
			return e.Network.Deny(ctx, enforcement.NetworkDeny{
				Session: evt.Subject.Session,
				Host:    stringField(evt.Fields, "host"),
				IP:      stringField(evt.Fields, "ip"),
				Port:    intField(evt.Fields, "port"),
				Reason:  outcome.Reason(),
			})
		case event.KindFileAccess, event.KindFileOpen:
			if e.File == nil {
				return nil
			}
			return e.File.DenyPath(ctx, enforcement.FileDeny{
				Session: evt.Subject.Session,
				Path:    stringField(evt.Fields, "path"),
				Op:      stringField(evt.Fields, "op"),
				Reason:  outcome.Reason(),
			})
		}
	case arbiterx.OutcomeKillProcess:
		if e.Process == nil {
			return nil
		}
		return e.Process.Kill(ctx, enforcement.ProcessKill{
			PID:    intOutcome(outcome, "pid"),
			Reason: outcome.Reason(),
		})
	}
	return nil
}

func (e *Engine) RouteCapability(evt event.Event, outcome arbiterx.Outcome) string {
	for _, candidate := range RouteCandidates(evt, outcome) {
		if e == nil || e.Registry == nil {
			return candidate
		}
		if _, ok := e.Registry.Get(candidate); ok {
			return candidate
		}
	}
	return "observe.audit"
}

func RouteCapability(evt event.Event, outcome arbiterx.Outcome) string {
	candidates := RouteCandidates(evt, outcome)
	if len(candidates) == 0 {
		return "observe.audit"
	}
	return candidates[0]
}

func RouteCandidates(evt event.Event, outcome arbiterx.Outcome) []string {
	switch outcome.Name {
	case arbiterx.OutcomeAllow:
		return []string{"kernel." + evt.Kind + ".allow", "observe.audit"}
	case arbiterx.OutcomeDeny:
		switch evt.Kind {
		case event.KindFileAccess, event.KindFileOpen:
			return []string{"kernel.file.open.deny", "continuum.outcome.deny", "observe.audit"}
		case event.KindNetworkConnect:
			return []string{"kernel.network.connect.deny", "continuum.outcome.deny", "observe.audit"}
		case event.KindProcessExec:
			return []string{"kernel.process.exec.deny", "continuum.outcome.deny", "observe.audit"}
		default:
			return []string{"continuum.outcome.deny", "observe.audit"}
		}
	case arbiterx.OutcomeAskHuman:
		return []string{"approval.cli.ask"}
	case arbiterx.OutcomeGrantNetwork:
		return []string{"kernel.network.connect.grant"}
	case arbiterx.OutcomeKillProcess:
		return []string{"kernel.process.kill"}
	case arbiterx.OutcomeEnterAirlock:
		return []string{"continuum.airlock.enter"}
	default:
		return []string{"observe.audit"}
	}
}

func RouteCandidatesForOutcomeName(name string) []string {
	switch name {
	case arbiterx.OutcomeAllow:
		return []string{"kernel.process.exec.allow", "observe.audit"}
	case arbiterx.OutcomeDeny:
		return []string{"continuum.outcome.deny", "kernel.file.open.deny", "kernel.network.connect.deny", "kernel.process.exec.deny", "observe.audit"}
	case arbiterx.OutcomeAskHuman:
		return []string{"approval.cli.ask"}
	case arbiterx.OutcomeGrantNetwork:
		return []string{"kernel.network.connect.grant"}
	case arbiterx.OutcomeKillProcess:
		return []string{"kernel.process.kill"}
	case arbiterx.OutcomeEnterAirlock:
		return []string{"continuum.airlock.enter"}
	case arbiterx.OutcomeAudit:
		return []string{"observe.audit"}
	default:
		return nil
	}
}

func stringField(fields map[string]any, key string) string {
	value, _ := fields[key].(string)
	return value
}

func intField(fields map[string]any, key string) int {
	switch v := fields[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

func stringOutcome(outcome arbiterx.Outcome, key string) string {
	value, _ := outcome.Fields[key].(string)
	return value
}

func intOutcome(outcome arbiterx.Outcome, key string) int {
	return intField(outcome.Fields, key)
}

func DisplayTarget(evt event.Event) string {
	switch evt.Kind {
	case event.KindFileAccess, event.KindFileOpen:
		return stringField(evt.Fields, "path")
	case event.KindNetworkConnect:
		host := stringField(evt.Fields, "host")
		if host == "" {
			host = stringField(evt.Fields, "ip")
		}
		port := intField(evt.Fields, "port")
		if port != 0 {
			return fmt.Sprintf("%s:%d", host, port)
		}
		return host
	case event.KindProcessExec:
		comm := stringField(evt.Fields, "comm")
		if comm != "" {
			return filepath.Base(comm)
		}
		return stringField(evt.Fields, "argv_text")
	default:
		return evt.Kind
	}
}
