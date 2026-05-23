package horizon

import (
	"context"

	"m31labs.dev/continuum/capability"
)

// Provider exposes Horizon-produced capability declarations to Continuum.
//
// Horizon owns probes, generated BPF artifacts, bindings, and transport details.
// Continuum consumes only the declared capability surface and machine events
// once they have crossed into Continuum's event model.
type Provider interface {
	LoadCapabilities(context.Context) ([]capability.Capability, error)
}

type DirProvider struct {
	Dir string
}

func (p DirProvider) LoadCapabilities(context.Context) ([]capability.Capability, error) {
	return LoadDir(p.Dir)
}
