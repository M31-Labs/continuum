package main

import (
	"context"

	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/horizon"
	cruntime "m31labs.dev/continuum/runtime"
)

func loadCapabilityRegistry(ctx context.Context, manifestDir string) (*capability.Registry, error) {
	daemon := cruntime.NewDaemon(horizon.DirProvider{Dir: manifestDir})
	if err := daemon.Start(ctx); err != nil {
		return nil, err
	}
	return daemon.Registry, nil
}
