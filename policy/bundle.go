package policy

import (
	"fmt"

	"m31labs.dev/continuum/arbiterx"
)

type Bundle struct {
	Name    string           `json:"name"`
	Path    string           `json:"path"`
	Program *arbiterx.Bundle `json:"program"`
}

func Load(name, path string) (Bundle, error) {
	program, err := arbiterx.CompileFile(path)
	if err != nil {
		return Bundle{}, err
	}
	if name == "" {
		name = program.Kind
	}
	return Bundle{Name: name, Path: path, Program: program}, nil
}

func (b Bundle) Validate() error {
	if b.Name == "" {
		return fmt.Errorf("policy bundle name is required")
	}
	if b.Program == nil {
		return fmt.Errorf("policy bundle %q has no compiled program", b.Name)
	}
	return nil
}
