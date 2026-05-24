package policy

import (
	"fmt"
	"time"

	"m31labs.dev/continuum/internal/statefile"
)

type Store struct {
	Path    string                  `json:"-"`
	Active  string                  `json:"active,omitempty"`
	Bundles map[string]StoredBundle `json:"bundles,omitempty"`
}

type StoredBundle struct {
	Name      string    `json:"name"`
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Path      string    `json:"path"`
	Published time.Time `json:"published"`
}

func LoadStore(path string) (*Store, error) {
	store := &Store{Path: path, Bundles: map[string]StoredBundle{}}
	if _, err := statefile.ReadJSON(path, store); err != nil {
		return nil, fmt.Errorf("load policy store %s: %w", path, err)
	}
	store.Path = path
	if store.Bundles == nil {
		store.Bundles = map[string]StoredBundle{}
	}
	return store, nil
}

func (s *Store) Save() error {
	if s == nil {
		return fmt.Errorf("nil policy store")
	}
	return statefile.WriteJSON(s.Path, s)
}

func UpdateStore(path string, mutate func(*Store) error) error {
	if mutate == nil {
		return fmt.Errorf("policy store mutation callback is required")
	}
	return statefile.WithLock(path, func() error {
		store, err := LoadStore(path)
		if err != nil {
			return err
		}
		if err := mutate(store); err != nil {
			return err
		}
		return statefile.WriteJSONWithoutLock(path, store)
	})
}

func (s *Store) Publish(bundle Bundle, now time.Time) error {
	if err := bundle.Validate(); err != nil {
		return err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if s.Bundles == nil {
		s.Bundles = map[string]StoredBundle{}
	}
	s.Bundles[bundle.Name] = StoredBundle{
		Name:      bundle.Name,
		ID:        bundle.Program.ID,
		Kind:      bundle.Program.Kind,
		Path:      bundle.Path,
		Published: now,
	}
	return nil
}

func (s *Store) Activate(name string) error {
	if s == nil {
		return fmt.Errorf("nil policy store")
	}
	if _, ok := s.Bundles[name]; !ok {
		return fmt.Errorf("policy bundle %q is not published", name)
	}
	s.Active = name
	return nil
}

func (s *Store) ActiveBundle() (StoredBundle, bool) {
	if s == nil || s.Active == "" {
		return StoredBundle{}, false
	}
	bundle, ok := s.Bundles[s.Active]
	return bundle, ok
}
