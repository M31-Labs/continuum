package policy

import "fmt"

type ActiveSet struct {
	bundles map[string]Bundle
	active  string
}

func NewActiveSet() *ActiveSet {
	return &ActiveSet{bundles: map[string]Bundle{}}
}

func (s *ActiveSet) Publish(bundle Bundle) error {
	if err := bundle.Validate(); err != nil {
		return err
	}
	s.bundles[bundle.Name] = bundle
	return nil
}

func (s *ActiveSet) Activate(name string) error {
	if _, ok := s.bundles[name]; !ok {
		return fmt.Errorf("policy bundle %q is not published", name)
	}
	s.active = name
	return nil
}

func (s *ActiveSet) Active() (Bundle, bool) {
	if s == nil || s.active == "" {
		return Bundle{}, false
	}
	bundle, ok := s.bundles[s.active]
	return bundle, ok
}
