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

type CgroupBackend interface {
	Backend
	Attach(context.Context, CgroupAttach) error
	Freeze(context.Context, CgroupFreeze) error
	Thaw(context.Context, CgroupThaw) error
}

type NetworkNamespaceBackend interface {
	Backend
	Isolate(context.Context, NamespaceIsolation) error
	ReleaseIsolation(context.Context, NamespaceRelease) error
}
