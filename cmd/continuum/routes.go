package main

import (
	"context"

	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/horizon"
	cruntime "m31labs.dev/continuum/runtime"
)

func loadCapabilityRegistryWithProvider(ctx context.Context, provider horizon.Provider) (*capability.Registry, error) {
	daemon := cruntime.NewDaemon(provider)
	if err := daemon.Start(ctx); err != nil {
		return nil, err
	}
	return daemon.Registry, nil
}
