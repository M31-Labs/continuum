package runtime

import (
	"context"
	"fmt"

	"m31labs.dev/continuum/airlock"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/horizon"
)

type Daemon struct {
	Registry     *capability.Registry
	Provider     horizon.Provider
	sourceHealth *SourceHealthStore
}

func NewDaemon(provider horizon.Provider) *Daemon {
	return &Daemon{Registry: capability.NewRegistry(), Provider: provider, sourceHealth: NewSourceHealthStore()}
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
	for _, cap := range airlock.DecoyCapabilities() {
		if _, exists := d.Registry.Get(cap.Name); exists {
			continue
		}
		if err := d.Registry.Register(cap); err != nil {
			return err
		}
	}
	if d.Provider == nil {
		d.refreshSourceHealth()
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
	d.refreshSourceHealth()
	return nil
}

func (d *Daemon) RunSource(ctx context.Context, src capability.Source, handler EventHandler) error {
	if d == nil {
		return fmt.Errorf("nil daemon")
	}
	return RunSourceWithHealth(ctx, src, handler, d.ensureSourceHealth())
}

func (d *Daemon) SourceHealth() []SourceHealth {
	if d == nil || d.sourceHealth == nil {
		return nil
	}
	return d.sourceHealth.List()
}

func (d *Daemon) refreshSourceHealth() {
	if d == nil || d.Registry == nil {
		return
	}
	d.ensureSourceHealth().RegisterCapabilities(d.Registry.List())
}

func (d *Daemon) ensureSourceHealth() *SourceHealthStore {
	if d.sourceHealth == nil {
		d.sourceHealth = NewSourceHealthStore()
	}
	return d.sourceHealth
}
