package enforcement

import (
	"context"

	"m31labs.dev/continuum/capability"
)

type NoopBackend struct{}

func (NoopBackend) Name() string { return "noop" }

func (NoopBackend) Capabilities() []capability.Capability {
	return []capability.Capability{
		{Name: "noop.enforcement", Kind: capability.KindWorker, Owner: "continuum", Input: "Outcome", Output: "NoopResult", Danger: capability.DangerObserve, Backend: "noop", Description: "accepts actions and does nothing"},
	}
}

func (NoopBackend) Grant(context.Context, NetworkGrant) error { return nil }
func (NoopBackend) Deny(context.Context, NetworkDeny) error   { return nil }
func (NoopBackend) Kill(context.Context, ProcessKill) error   { return nil }
func (NoopBackend) DenyPath(context.Context, FileDeny) error  { return nil }
