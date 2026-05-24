package capability

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"m31labs.dev/continuum/internal/statefile"
)

type GrantStore struct {
	Grants []Grant `json:"grants,omitempty"`
}

func LoadGrantStore(path string) (*GrantStore, error) {
	store := &GrantStore{}
	if _, err := statefile.ReadJSON(path, store); err != nil {
		return nil, fmt.Errorf("load grant store %s: %w", path, err)
	}
	return store, nil
}

func (s *GrantStore) Save(path string) error {
	if s == nil {
		return fmt.Errorf("nil grant store")
	}
	return statefile.WriteJSON(path, s)
}

func UpdateGrantStore(path string, mutate func(*GrantStore) error) error {
	if mutate == nil {
		return fmt.Errorf("grant store mutation callback is required")
	}
	return statefile.WithLock(path, func() error {
		store, err := LoadGrantStore(path)
		if err != nil {
			return err
		}
		if err := mutate(store); err != nil {
			return err
		}
		return statefile.WriteJSONWithoutLock(path, store)
	})
}

func (s *GrantStore) Add(grant Grant) error {
	if grant.ID == "" {
		return fmt.Errorf("grant id is required")
	}
	for _, existing := range s.Grants {
		if existing.ID == grant.ID {
			return fmt.Errorf("grant %q already exists", grant.ID)
		}
	}
	s.Grants = append(s.Grants, grant)
	s.sort()
	return nil
}

func (s *GrantStore) Revoke(id string, now time.Time) (Grant, error) {
	for i := range s.Grants {
		if s.Grants[i].ID != id {
			continue
		}
		if now.IsZero() {
			now = time.Now().UTC()
		}
		s.Grants[i].RevokedAt = now
		return s.Grants[i], nil
	}
	return Grant{}, fmt.Errorf("grant %q not found", id)
}

func (s *GrantStore) Active(now time.Time) []Grant {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var out []Grant
	for _, grant := range s.Grants {
		if grant.Active(now) {
			out = append(out, grant)
		}
	}
	return out
}

func (s *GrantStore) Expired(now time.Time) []Grant {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var out []Grant
	for _, grant := range s.Grants {
		if grant.Expired(now) {
			out = append(out, grant)
		}
	}
	return out
}

func (s *GrantStore) PruneExpired(now time.Time) int {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	kept := s.Grants[:0]
	removed := 0
	for _, grant := range s.Grants {
		if grant.Expired(now) {
			removed++
			continue
		}
		kept = append(kept, grant)
	}
	s.Grants = kept
	return removed
}

func (s *GrantStore) sort() {
	slices.SortFunc(s.Grants, func(a, b Grant) int {
		if cmp := strings.Compare(a.Session, b.Session); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.ID, b.ID)
	})
}
