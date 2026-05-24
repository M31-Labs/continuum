package runtime

import (
	"fmt"
	"strings"

	"m31labs.dev/continuum/internal/statefile"
)

const IDStoreSchemaVersion = 1

type IDFunc func() (string, error)

type IDStore struct {
	SchemaVersion int               `json:"schema_version"`
	Counters      map[string]uint64 `json:"counters,omitempty"`
}

func LoadIDStore(path string) (*IDStore, error) {
	store := &IDStore{SchemaVersion: IDStoreSchemaVersion, Counters: map[string]uint64{}}
	if _, err := statefile.ReadJSON(path, store); err != nil {
		return nil, fmt.Errorf("load id store %s: %w", path, err)
	}
	if err := store.MigrateSchema(); err != nil {
		return nil, fmt.Errorf("load id store %s: %w", path, err)
	}
	if store.Counters == nil {
		store.Counters = map[string]uint64{}
	}
	return store, nil
}

func (s *IDStore) Save(path string) error {
	if s == nil {
		return fmt.Errorf("nil id store")
	}
	if err := s.MigrateSchema(); err != nil {
		return err
	}
	return statefile.WriteJSON(path, s)
}

func UpdateIDStore(path string, mutate func(*IDStore) error) error {
	if mutate == nil {
		return fmt.Errorf("id store mutation callback is required")
	}
	return statefile.WithLock(path, func() error {
		store, err := LoadIDStore(path)
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

func (s *IDStore) MigrateSchema() error {
	if s == nil {
		return fmt.Errorf("nil id store")
	}
	if err := statefile.MigrateSchema("id store", &s.SchemaVersion, IDStoreSchemaVersion, nil); err != nil {
		return err
	}
	if s.Counters == nil {
		s.Counters = map[string]uint64{}
	}
	return nil
}

func (s *IDStore) Next(prefix string) (uint64, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return 0, fmt.Errorf("id prefix is required")
	}
	if s == nil {
		return 0, fmt.Errorf("nil id store")
	}
	if s.Counters == nil {
		s.Counters = map[string]uint64{}
	}
	s.Counters[prefix]++
	return s.Counters[prefix], nil
}

func NextID(path, prefix string) (string, error) {
	return NextIDWithSeparator(path, prefix, "_")
}

func NextIDWithSeparator(path, prefix, separator string) (string, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return "", fmt.Errorf("id prefix is required")
	}
	if path == "" {
		return "", fmt.Errorf("id store path is required")
	}
	var id string
	err := UpdateIDStore(path, func(store *IDStore) error {
		next, err := store.Next(prefix)
		if err != nil {
			return err
		}
		id = fmt.Sprintf("%s%s%d", prefix, separator, next)
		return nil
	})
	return id, err
}

func PersistentID(path, prefix string) IDFunc {
	return func() (string, error) {
		return NextID(path, prefix)
	}
}

func PersistentIDWithSeparator(path, prefix, separator string) IDFunc {
	return func() (string, error) {
		return NextIDWithSeparator(path, prefix, separator)
	}
}
