package capability

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"m31labs.dev/continuum/internal/statefile"
)

const GrantStoreSchemaVersion = 1

type GrantStore struct {
	SchemaVersion int     `json:"schema_version"`
	Grants        []Grant `json:"grants,omitempty"`
}

func LoadGrantStore(path string) (*GrantStore, error) {
	store := &GrantStore{SchemaVersion: GrantStoreSchemaVersion}
	if _, err := statefile.ReadJSON(path, store); err != nil {
		return nil, fmt.Errorf("load grant store %s: %w", path, err)
	}
	if err := store.MigrateSchema(); err != nil {
		return nil, fmt.Errorf("load grant store %s: %w", path, err)
	}
	return store, nil
}

func (s *GrantStore) Save(path string) error {
	if s == nil {
		return fmt.Errorf("nil grant store")
	}
	if err := s.MigrateSchema(); err != nil {
		return err
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
		if err := store.MigrateSchema(); err != nil {
			return err
		}
		return statefile.WriteJSONWithoutLock(path, store)
	})
}

func (s *GrantStore) MigrateSchema() error {
	if s == nil {
		return fmt.Errorf("nil grant store")
	}
	return statefile.MigrateSchema("grant store", &s.SchemaVersion, GrantStoreSchemaVersion, nil)
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

func (s *GrantStore) Renew(id string, ttl time.Duration, reason string, now time.Time) (Grant, error) {
	if ttl <= 0 {
		return Grant{}, fmt.Errorf("grant renewal ttl must be positive")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return Grant{}, fmt.Errorf("grant renewal reason is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	for i := range s.Grants {
		if s.Grants[i].ID != id {
			continue
		}
		grant := &s.Grants[i]
		if !grant.RevokedAt.IsZero() {
			return Grant{}, fmt.Errorf("grant %q is revoked", id)
		}
		if grant.Expired(now) {
			return Grant{}, fmt.Errorf("grant %q is expired", id)
		}
		nextExpiry := now.Add(ttl)
		if !nextExpiry.After(grant.ExpiresAt) {
			return Grant{}, fmt.Errorf("grant renewal must extend the current expiry")
		}
		previousExpiry := grant.ExpiresAt
		grant.ExpiresAt = nextExpiry
		grant.Renewals = append(grant.Renewals, GrantRenewal{
			RenewedAt:         now,
			PreviousExpiresAt: previousExpiry,
			ExpiresAt:         nextExpiry,
			Reason:            reason,
		})
		return *grant, nil
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
