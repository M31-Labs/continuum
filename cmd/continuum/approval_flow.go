package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"m31labs.dev/continuum/approval"
	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/subject"
)

type approvalMode string

const (
	approvalDeny  approvalMode = "deny"
	approvalAllow approvalMode = "allow"
	approvalCLI   approvalMode = "cli"
)

func handleAskHuman(ctx context.Context, mode approvalMode, stdout io.Writer, sink audit.Sink, record audit.Event, evt event.Event, grantStorePath string, maxGrantTTL time.Duration) error {
	if record.Outcome.Name != arbiterx.OutcomeAskHuman {
		return nil
	}
	req := approval.Request{
		Session:   evt.Subject.Session,
		Requester: subject.IdentityFromSubject(evt.Subject),
		Question:  stringFromOutcome(record.Outcome, "question"),
		Risk:      stringFromOutcome(record.Outcome, "risk"),
	}
	var resp approval.Response
	var err error
	switch mode {
	case approvalAllow:
		resp = approval.Response{Approved: true, Reason: "auto-approved"}
	case approvalCLI:
		resp, err = approval.CLI{In: os.Stdin, Out: stdout}.Ask(ctx, req)
	default:
		resp = approval.Response{Approved: false, Reason: "auto-denied"}
	}
	if err != nil {
		return err
	}
	if !resp.Approved {
		denial := approvalDenialAuditEvent(record, evt, req, resp, time.Now().UTC())
		if sink != nil {
			if err := sink.Write(ctx, denial); err != nil {
				return err
			}
		}
		fmt.Fprintf(stdout, "approval=denied session=%s requester=%s reason=%q audit=%s\n", req.Session, requesterLabel(req), denial.Reason, denial.ID)
		return nil
	}
	reason := approvalReason(resp.Reason, record.Outcome, req)
	grant := approvalGrant(evt, record.Outcome, req.Requester, reason, time.Now().UTC(), maxGrantTTL)
	if err := capability.UpdateGrantStore(grantStorePath, func(store *capability.GrantStore) error {
		return store.Add(grant)
	}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "approval=granted grant=%s session=%s capability=%s\n", grant.ID, grant.Session, grant.Capability)
	return nil
}

func approvalDenialAuditEvent(record audit.Event, evt event.Event, req approval.Request, resp approval.Response, now time.Time) audit.Event {
	reason := strings.TrimSpace(resp.Reason)
	if reason == "" {
		reason = "approval denied"
		if req.Question != "" {
			reason += ": " + req.Question
		}
	}
	fields := map[string]any{
		"reason":            reason,
		"approval_event_id": record.ID,
		"question":          req.Question,
		"risk":              req.Risk,
	}
	if req.Requester != nil {
		fields["requester"] = req.Requester
	}
	return audit.Event{
		ID:          approvalDenialAuditID(record.ID, now),
		Time:        now,
		Clock:       &audit.ClockMetadata{Source: audit.ClockSourceApprovalFlow, RecordedAt: now, EventTimeSource: audit.EventTimeSourceRecordedClock},
		Subject:     evt.Subject,
		InputEvent:  evt,
		Policy:      record.Policy,
		Outcome:     arbiterx.NewOutcome(arbiterx.OutcomeDeny, "ApprovalDenied", fields),
		Decision:    "deny",
		Reason:      reason,
		Arbitraces:  record.Arbitraces,
		Capability:  record.Capability,
		Enforcement: record.Enforcement,
	}
}

func approvalDenialAuditID(parentID string, now time.Time) string {
	if parentID != "" {
		return parentID + "_approval_denied"
	}
	return fmt.Sprintf("approval_denied_%d", now.UnixNano())
}

func requesterLabel(req approval.Request) string {
	if req.Requester != nil && req.Requester.Subject != "" {
		return req.Requester.Subject
	}
	if req.Session != "" {
		return "session:" + req.Session
	}
	return "unknown"
}

func approvalReason(responseReason string, outcome arbiterx.Outcome, req approval.Request) string {
	if reason := strings.TrimSpace(responseReason); reason != "" {
		return reason
	}
	if reason := strings.TrimSpace(outcome.Reason()); reason != "" {
		return reason
	}
	if req.Question != "" {
		return "approved: " + req.Question
	}
	return "approved governed request"
}

func approvalGrant(evt event.Event, outcome arbiterx.Outcome, requester *subject.Identity, reason string, now time.Time, maxGrantTTL time.Duration) capability.Grant {
	if reason == "" {
		reason = outcome.Reason()
	}
	ttl := 20 * time.Minute
	if maxGrantTTL > 0 && ttl > maxGrantTTL {
		ttl = maxGrantTTL
	}
	return capability.Grant{
		ID:         fmt.Sprintf("grant_%d", now.UnixNano()),
		Session:    evt.Subject.Session,
		Capability: approvalCapability(evt),
		Scope:      approvalScope(evt),
		Requester:  requester,
		Reason:     reason,
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
	}
}

func approvalCapability(evt event.Event) string {
	switch evt.Kind {
	case event.KindFileAccess, event.KindFileOpen:
		return "file." + approvalStringField(evt.Fields, "op")
	case event.KindNetworkConnect:
		return "network.connect"
	case event.KindProcessExec:
		return "process.exec"
	default:
		return evt.Kind
	}
}

func approvalStringField(fields map[string]any, key string) string {
	value, _ := fields[key].(string)
	return value
}

func approvalScope(evt event.Event) map[string]any {
	scope := map[string]any{"kind": evt.Kind}
	for key, value := range evt.Fields {
		scope[key] = value
	}
	return scope
}

func stringFromOutcome(outcome arbiterx.Outcome, key string) string {
	value, _ := outcome.Fields[key].(string)
	return value
}
