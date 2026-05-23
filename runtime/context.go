package runtime

import (
	"context"

	"m31labs.dev/continuum/config"
)

type Context struct {
	context.Context
	Config config.Config
}

func NewContext(parent context.Context, cfg config.Config) Context {
	if parent == nil {
		parent = context.Background()
	}
	return Context{Context: parent, Config: cfg}
}
