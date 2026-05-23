package runtime

import (
	"context"
	"fmt"

	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/horizon"
)

type Daemon struct {
	Registry *capability.Registry
	Provider horizon.Provider
}

func NewDaemon(provider horizon.Provider) *Daemon {
	return &Daemon{Registry: capability.NewRegistry(), Provider: provider}
}

func (d *Daemon) Start(ctx context.Context) error {
	if d == nil {
		return fmt.Errorf("nil daemon")
	}
	for _, cap := range capability.BuiltIns() {
		if _, exists := d.Registry.Get(cap.Name); exists {
			continue
		}
		if err := d.Registry.Register(cap); err != nil {
			return err
		}
	}
	if d.Provider == nil {
		return nil
	}
	caps, err := d.Provider.LoadCapabilities(ctx)
	if err != nil {
		return err
	}
	for _, cap := range caps {
		if err := d.Registry.Register(cap); err != nil {
			return err
		}
	}
	return nil
}
