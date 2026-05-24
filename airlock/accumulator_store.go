package airlock

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/internal/statefile"
)

const AccumulatorStoreSchemaVersion = 1

type AccumulatorStore struct {
	mu            sync.Mutex
	SchemaVersion int
	accumulators  map[string]AccumulatorSnapshot
}

type accumulatorStoreFile struct {
	SchemaVersion int                   `json:"schema_version"`
	Accumulators  []AccumulatorSnapshot `json:"accumulators,omitempty"`
}

func NewAccumulatorStore() *AccumulatorStore {
	return &AccumulatorStore{
		SchemaVersion: AccumulatorStoreSchemaVersion,
		accumulators:  map[string]AccumulatorSnapshot{},
	}
}

func LoadAccumulatorStore(path string) (*AccumulatorStore, error) {
	store := NewAccumulatorStore()
	file := accumulatorStoreFile{SchemaVersion: AccumulatorStoreSchemaVersion}
	if _, err := statefile.ReadJSON(path, &file); err != nil {
		return nil, fmt.Errorf("load airlock accumulator store %s: %w", path, err)
	}
	store.SchemaVersion = file.SchemaVersion
	if err := store.MigrateSchema(); err != nil {
		return nil, fmt.Errorf("load airlock accumulator store %s: %w", path, err)
	}
	for _, snapshot := range file.Accumulators {
		normalized, err := normalizeAccumulatorSnapshot(snapshot)
		if err != nil {
			return nil, fmt.Errorf("load airlock accumulator store %s: %w", path, err)
		}
		store.accumulators[normalized.Subject] = normalized
	}
	return store, nil
}

func (s *AccumulatorStore) Save(path string) error {
	if s == nil {
		return fmt.Errorf("nil airlock accumulator store")
	}
	if err := s.MigrateSchema(); err != nil {
		return err
	}
	return statefile.WriteJSON(path, s.file())
}

func UpdateAccumulatorStore(path string, mutate func(*AccumulatorStore) error) error {
	if mutate == nil {
		return fmt.Errorf("airlock accumulator store mutation callback is required")
	}
	return statefile.WithLock(path, func() error {
		store, err := LoadAccumulatorStore(path)
		if err != nil {
			return err
		}
		if err := mutate(store); err != nil {
			return err
		}
		if err := store.MigrateSchema(); err != nil {
			return err
		}
		return statefile.WriteJSONWithoutLock(path, store.file())
	})
}

func (s *AccumulatorStore) MigrateSchema() error {
	if s == nil {
		return fmt.Errorf("nil airlock accumulator store")
	}
	return statefile.MigrateSchema("airlock accumulator store", &s.SchemaVersion, AccumulatorStoreSchemaVersion, nil)
}

func (s *AccumulatorStore) ObserveEvents(events []event.Event, now func() time.Time) []Behavior {
	if s == nil || len(events) == 0 {
		return nil
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	accumulators := map[string]*Accumulator{}
	updatedAt := map[string]time.Time{}
	for _, evt := range events {
		key := evt.Subject.String()
		if key == "" {
			key = "unknown"
		}
		acc := accumulators[key]
		if acc == nil {
			if snapshot, ok := s.accumulators[key]; ok {
				acc = NewAccumulatorFromSnapshot(snapshot)
			} else {
				acc = NewAccumulator(key)
			}
			accumulators[key] = acc
		}
		acc.Observe(evt)
		observed := evt.Time
		if observed.IsZero() {
			observed = now()
		}
		updatedAt[key] = observed
	}
	behaviors := make([]Behavior, 0, len(accumulators))
	for key, acc := range accumulators {
		snapshot := acc.Snapshot(updatedAt[key])
		s.accumulators[key] = snapshot
		behavior := snapshot.Behavior()
		if behavior.Subject == "" {
			behavior.Subject = "unknown"
		}
		behaviors = append(behaviors, behavior)
	}
	slices.SortFunc(behaviors, func(a, b Behavior) int {
		return strings.Compare(a.Subject, b.Subject)
	})
	return behaviors
}

func (s *AccumulatorStore) Get(subject string) (AccumulatorSnapshot, bool) {
	if s == nil {
		return AccumulatorSnapshot{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot, ok := s.accumulators[subject]
	return snapshot, ok
}

func (s *AccumulatorStore) List() []AccumulatorSnapshot {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AccumulatorSnapshot, 0, len(s.accumulators))
	for _, snapshot := range s.accumulators {
		out = append(out, snapshot)
	}
	slices.SortFunc(out, func(a, b AccumulatorSnapshot) int {
		return strings.Compare(a.Subject, b.Subject)
	})
	return out
}

func (s *AccumulatorStore) file() accumulatorStoreFile {
	if s == nil {
		return accumulatorStoreFile{SchemaVersion: AccumulatorStoreSchemaVersion}
	}
	return accumulatorStoreFile{SchemaVersion: s.SchemaVersion, Accumulators: s.List()}
}

func normalizeAccumulatorSnapshot(snapshot AccumulatorSnapshot) (AccumulatorSnapshot, error) {
	snapshot.Subject = strings.TrimSpace(snapshot.Subject)
	if snapshot.Subject == "" {
		return AccumulatorSnapshot{}, fmt.Errorf("airlock accumulator subject is required")
	}
	if snapshot.ExecCount < 0 {
		return AccumulatorSnapshot{}, fmt.Errorf("airlock accumulator %q exec_count must be >= 0", snapshot.Subject)
	}
	snapshot.NetworkTargets = normalizeStringSet(snapshot.NetworkTargets)
	snapshot.SecretPaths = normalizeStringSet(snapshot.SecretPaths)
	snapshot.RewrittenFiles = normalizeStringSet(snapshot.RewrittenFiles)
	return snapshot, nil
}

func normalizeStringSet(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	return sortedKeys(set)
}
