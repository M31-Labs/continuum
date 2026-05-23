package capability

import (
	"fmt"
	"slices"
	"strings"
)

type Registry struct {
	items map[string]Capability
}

func NewRegistry() *Registry {
	return &Registry{items: map[string]Capability{}}
}

func (r *Registry) Register(cap Capability) error {
	if r == nil {
		return fmt.Errorf("nil registry")
	}
	if err := Validate(cap); err != nil {
		return err
	}
	if _, exists := r.items[cap.Name]; exists {
		return fmt.Errorf("capability %q already registered", cap.Name)
	}
	r.items[cap.Name] = cap
	return nil
}

func (r *Registry) Get(name string) (Capability, bool) {
	if r == nil {
		return Capability{}, false
	}
	cap, ok := r.items[name]
	return cap, ok
}

func (r *Registry) List() []Capability {
	if r == nil {
		return nil
	}
	out := make([]Capability, 0, len(r.items))
	for _, cap := range r.items {
		out = append(out, cap)
	}
	slices.SortFunc(out, func(a, b Capability) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

func (r *Registry) ByKind(kind Kind) []Capability {
	var out []Capability
	for _, cap := range r.List() {
		if cap.Kind == kind {
			out = append(out, cap)
		}
	}
	return out
}

func Validate(cap Capability) error {
	if strings.TrimSpace(cap.Name) == "" {
		return fmt.Errorf("capability name is required")
	}
	switch cap.Kind {
	case KindSource, KindSink, KindWorker:
	default:
		return fmt.Errorf("capability %s: invalid kind %q", cap.Name, cap.Kind)
	}
	switch cap.Danger {
	case DangerObserve, DangerSoftControl, DangerEnforcement, DangerDestructive, DangerPrivileged:
	default:
		return fmt.Errorf("capability %s: invalid danger %q", cap.Name, cap.Danger)
	}
	return nil
}
