package enforcement

import (
	"context"

	"m31labs.dev/continuum/capability"
)

type ObserveBackend struct{}

func (ObserveBackend) Name() string { return "observe" }

func (ObserveBackend) Capabilities() []capability.Capability {
	return []capability.Capability{{Name: "observe.audit", Kind: capability.KindSink, Owner: "continuum", Input: "Decision", Danger: capability.DangerObserve, Backend: "observe", Description: "record decisions without enforcement"}}
}

func (ObserveBackend) Grant(context.Context, NetworkGrant) error { return nil }
func (ObserveBackend) Deny(context.Context, NetworkDeny) error   { return nil }
func (ObserveBackend) Kill(context.Context, ProcessKill) error   { return nil }
func (ObserveBackend) DenyPath(context.Context, FileDeny) error  { return nil }
