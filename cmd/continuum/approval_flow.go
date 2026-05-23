package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"m31labs.dev/continuum/approval"
	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
)

type approvalMode string

const (
	approvalDeny  approvalMode = "deny"
	approvalAllow approvalMode = "allow"
	approvalCLI   approvalMode = "cli"
)

func handleAskHuman(ctx context.Context, mode approvalMode, stdout io.Writer, record audit.Event, evt event.Event, grantStorePath string) error {
	if record.Outcome.Name != arbiterx.OutcomeAskHuman {
		return nil
	}
	req := approval.Request{
		Session:  evt.Subject.Session,
		Question: stringFromOutcome(record.Outcome, "question"),
		Risk:     stringFromOutcome(record.Outcome, "risk"),
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
		fmt.Fprintf(stdout, "approval=denied session=%s reason=%q\n", req.Session, resp.Reason)
		return nil
	}
	grant := approvalGrant(evt, record.Outcome, resp.Reason, time.Now().UTC())
	store, err := capability.LoadGrantStore(grantStorePath)
	if err != nil {
		return err
	}
	if err := store.Add(grant); err != nil {
		return err
	}
	if err := store.Save(grantStorePath); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "approval=granted grant=%s session=%s capability=%s\n", grant.ID, grant.Session, grant.Capability)
	return nil
}

func approvalGrant(evt event.Event, outcome arbiterx.Outcome, reason string, now time.Time) capability.Grant {
	if reason == "" {
		reason = outcome.Reason()
	}
	return capability.Grant{
		ID:         fmt.Sprintf("grant_%d", now.UnixNano()),
		Session:    evt.Subject.Session,
		Capability: approvalCapability(evt),
		Scope:      approvalScope(evt),
		Reason:     reason,
		CreatedAt:  now,
		ExpiresAt:  now.Add(20 * time.Minute),
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
