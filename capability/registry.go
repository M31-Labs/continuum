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
	case KindSource:
		if strings.TrimSpace(cap.Output) == "" {
			return fmt.Errorf("capability %s: source output is required", cap.Name)
		}
	case KindSink:
		if strings.TrimSpace(cap.Input) == "" {
			return fmt.Errorf("capability %s: sink input is required", cap.Name)
		}
	case KindWorker:
		if strings.TrimSpace(cap.Input) == "" {
			return fmt.Errorf("capability %s: worker input is required", cap.Name)
		}
	default:
		return fmt.Errorf("capability %s: invalid kind %q", cap.Name, cap.Kind)
	}
	switch cap.Danger {
	case DangerObserve, DangerSoftControl, DangerEnforcement, DangerDestructive, DangerPrivileged:
	default:
		return fmt.Errorf("capability %s: invalid danger %q", cap.Name, cap.Danger)
	}
	if err := validateBackendDanger(cap); err != nil {
		return err
	}
	if cap.Danger == DangerDestructive || cap.Danger == DangerPrivileged {
		if strings.TrimSpace(cap.Owner) == "" {
			return fmt.Errorf("capability %s: %s capability requires an explicit owner", cap.Name, cap.Danger)
		}
		if len(cap.Requires) == 0 {
			return fmt.Errorf("capability %s: %s capability requires an explicit requirement", cap.Name, cap.Danger)
		}
	}
	return nil
}

func validateBackendDanger(cap Capability) error {
	switch cap.Backend {
	case "", "observe", "file", "network", "process":
		return nil
	case "noop":
		if cap.Danger != DangerObserve {
			return fmt.Errorf("capability %s: noop backend only supports observe danger", cap.Name)
		}
	case "cli":
		if cap.Danger != DangerObserve && cap.Danger != DangerSoftControl {
			return fmt.Errorf("capability %s: cli backend cannot host %s danger", cap.Name, cap.Danger)
		}
	}
	return nil
}
