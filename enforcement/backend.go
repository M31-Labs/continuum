package enforcement

import (
	"context"

	"m31labs.dev/continuum/capability"
)

type Backend interface {
	Name() string
	Capabilities() []capability.Capability
}

type NetworkBackend interface {
	Backend
	Grant(context.Context, NetworkGrant) error
	Deny(context.Context, NetworkDeny) error
}

type ProcessBackend interface {
	Backend
	Kill(context.Context, ProcessKill) error
}

type FileBackend interface {
	Backend
	DenyPath(context.Context, FileDeny) error
}
