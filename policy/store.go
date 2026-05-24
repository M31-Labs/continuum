package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"m31labs.dev/continuum/internal/statefile"
)

type Store struct {
	Path              string                  `json:"-"`
	Active            string                  `json:"active,omitempty"`
	Bundles           map[string]StoredBundle `json:"bundles,omitempty"`
	ActivationHistory []ActivationRecord      `json:"activation_history,omitempty"`
}

type StoredBundle struct {
	Name       string     `json:"name"`
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Path       string     `json:"path"`
	Published  time.Time  `json:"published"`
	Provenance Provenance `json:"provenance,omitempty"`
}

type Provenance struct {
	SourcePath   string `json:"source_path,omitempty"`
	SourceSHA256 string `json:"source_sha256,omitempty"`
	SourceBytes  int    `json:"source_bytes,omitempty"`
	Compiler     string `json:"compiler,omitempty"`
}

type ActivationRecord struct {
	From string    `json:"from,omitempty"`
	To   string    `json:"to"`
	Time time.Time `json:"time"`
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
		Name:       bundle.Name,
		ID:         bundle.Program.ID,
		Kind:       bundle.Program.Kind,
		Path:       bundle.Path,
		Published:  now,
		Provenance: BundleProvenance(bundle),
	}
	return nil
}

func BundleProvenance(bundle Bundle) Provenance {
	provenance := Provenance{
		SourcePath: bundle.Path,
		Compiler:   "github.com/odvcencio/arbiter",
	}
	if bundle.Program == nil {
		return provenance
	}
	source := []byte(bundle.Program.Source)
	if len(source) > 0 {
		sum := sha256.Sum256(source)
		provenance.SourceSHA256 = hex.EncodeToString(sum[:])
		provenance.SourceBytes = len(source)
	}
	return provenance
}

func (s *Store) Activate(name string) error {
	return s.ActivateAt(name, time.Now().UTC())
}

func (s *Store) ActivateAt(name string, now time.Time) error {
	if s == nil {
		return fmt.Errorf("nil policy store")
	}
	if _, ok := s.Bundles[name]; !ok {
		return fmt.Errorf("policy bundle %q is not published", name)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if s.Active != name {
		s.ActivationHistory = append(s.ActivationHistory, ActivationRecord{
			From: s.Active,
			To:   name,
			Time: now,
		})
	}
	s.Active = name
	return nil
}

func (s *Store) Rollback() (StoredBundle, error) {
	if s == nil {
		return StoredBundle{}, fmt.Errorf("nil policy store")
	}
	for len(s.ActivationHistory) > 0 {
		last := s.ActivationHistory[len(s.ActivationHistory)-1]
		s.ActivationHistory = s.ActivationHistory[:len(s.ActivationHistory)-1]
		if last.To != s.Active || last.From == "" {
			continue
		}
		bundle, ok := s.Bundles[last.From]
		if !ok {
			return StoredBundle{}, fmt.Errorf("previous policy bundle %q is not published", last.From)
		}
		s.Active = last.From
		return bundle, nil
	}
	return StoredBundle{}, fmt.Errorf("no previous policy activation to roll back to")
}

func (s *Store) ActiveBundle() (StoredBundle, bool) {
	if s == nil || s.Active == "" {
		return StoredBundle{}, false
	}
	bundle, ok := s.Bundles[s.Active]
	return bundle, ok
}
