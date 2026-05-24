package airlock

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	"m31labs.dev/continuum/internal/statefile"
	"m31labs.dev/continuum/subject"
)

const StoreSchemaVersion = 1

type Store struct {
	mu            sync.Mutex
	SchemaVersion int
	sessions      map[string]Session
}

type storeFile struct {
	SchemaVersion int       `json:"schema_version"`
	Sessions      []Session `json:"sessions,omitempty"`
}

type RetentionOptions struct {
	Retain    int
	OlderThan time.Duration
	Now       time.Time
}

type RetentionReport struct {
	Before  int `json:"before"`
	After   int `json:"after"`
	Removed int `json:"removed"`
}

func NewStore() *Store {
	return &Store{SchemaVersion: StoreSchemaVersion, sessions: map[string]Session{}}
}

func LoadStore(path string) (*Store, error) {
	store := NewStore()
	file := storeFile{SchemaVersion: StoreSchemaVersion}
	if _, err := statefile.ReadJSON(path, &file); err != nil {
		return nil, fmt.Errorf("load airlock store %s: %w", path, err)
	}
	store.SchemaVersion = file.SchemaVersion
	if err := store.MigrateSchema(); err != nil {
		return nil, fmt.Errorf("load airlock store %s: %w", path, err)
	}
	for _, session := range file.Sessions {
		store.sessions[session.ID] = session
	}
	return store, nil
}

func (s *Store) Save(path string) error {
	if s == nil {
		return fmt.Errorf("nil airlock store")
	}
	if err := s.MigrateSchema(); err != nil {
		return err
	}
	return statefile.WriteJSON(path, s.file())
}

func UpdateStore(path string, mutate func(*Store) error) error {
	if mutate == nil {
		return fmt.Errorf("airlock store mutation callback is required")
	}
	return statefile.WithLock(path, func() error {
		store, err := LoadStore(path)
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

func (s *Store) MigrateSchema() error {
	if s == nil {
		return fmt.Errorf("nil airlock store")
	}
	return statefile.MigrateSchema("airlock store", &s.SchemaVersion, StoreSchemaVersion, nil)
}

func (s *Store) file() storeFile {
	if s == nil {
		return storeFile{SchemaVersion: StoreSchemaVersion}
	}
	return storeFile{SchemaVersion: s.SchemaVersion, Sessions: s.List()}
}

func (f *storeFile) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil
	}
	if trimmed[0] == '[' {
		var sessions []Session
		if err := json.Unmarshal(trimmed, &sessions); err != nil {
			return err
		}
		f.SchemaVersion = 0
		f.Sessions = sessions
		return nil
	}
	type fileAlias storeFile
	var decoded fileAlias
	if err := json.Unmarshal(trimmed, &decoded); err != nil {
		return err
	}
	*f = storeFile(decoded)
	return nil
}

func (s *Store) Enter(id string, subj subject.Subject, reason string, now time.Time) (Session, error) {
	if id == "" {
		return Session{}, fmt.Errorf("airlock session id is required")
	}
	session := Session{ID: id, Subject: subj}
	if err := session.Transition(StateAirlocked, reason, now); err != nil {
		return Session{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = session
	return session, nil
}

func (s *Store) Release(id string, reason string, now time.Time) (Session, error) {
	return s.transition(id, StateReleased, reason, now)
}

func (s *Store) Remediate(id string, reason string, now time.Time) (Session, error) {
	return s.transition(id, StateRemediated, reason, now)
}

func (s *Store) Get(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok {
		return Session{}, false
	}
	return session, true
}

func (s *Store) AddNote(id, operator, text string, now time.Time) (Session, Note, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok {
		return Session{}, Note{}, fmt.Errorf("airlock session %q not found", id)
	}
	note, err := session.AddNote(operator, text, now)
	if err != nil {
		return Session{}, Note{}, err
	}
	s.sessions[id] = session
	return session, note, nil
}

func (s *Store) Compact(opts RetentionOptions) (RetentionReport, error) {
	if err := opts.Validate(); err != nil {
		return RetentionReport{}, err
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	cutoff := now.Add(-opts.OlderThan)
	s.mu.Lock()
	defer s.mu.Unlock()
	report := RetentionReport{Before: len(s.sessions)}
	protected := newestTerminalSessionSet(s.sessions, opts.Retain)
	for id, session := range s.sessions {
		if !terminalState(session.State) || protected[id] {
			continue
		}
		if opts.OlderThan == 0 || sessionRetentionTime(session).Before(cutoff) {
			delete(s.sessions, id)
		}
	}
	report.After = len(s.sessions)
	report.Removed = report.Before - report.After
	return report, nil
}

func (s *Store) transition(id string, next State, reason string, now time.Time) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok {
		return Session{}, fmt.Errorf("airlock session %q not found", id)
	}
	if err := session.Transition(next, reason, now); err != nil {
		return Session{}, err
	}
	s.sessions[id] = session
	return session, nil
}

func (s *Store) List() []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		out = append(out, session)
	}
	slices.SortFunc(out, func(a, b Session) int {
		if a.StartedAt.Equal(b.StartedAt) {
			if a.ID < b.ID {
				return -1
			}
			if a.ID > b.ID {
				return 1
			}
			return 0
		}
		if a.StartedAt.Before(b.StartedAt) {
			return -1
		}
		return 1
	})
	return out
}

func (o RetentionOptions) Validate() error {
	if o.Retain < 0 {
		return fmt.Errorf("retain must be >= 0")
	}
	if o.OlderThan < 0 {
		return fmt.Errorf("older-than must be >= 0")
	}
	if o.Retain == 0 && o.OlderThan == 0 {
		return fmt.Errorf("retain or older-than is required")
	}
	return nil
}

func newestTerminalSessionSet(sessions map[string]Session, retain int) map[string]bool {
	protected := map[string]bool{}
	if retain <= 0 {
		return protected
	}
	terminal := make([]Session, 0, len(sessions))
	for _, session := range sessions {
		if terminalState(session.State) {
			terminal = append(terminal, session)
		}
	}
	slices.SortFunc(terminal, func(a, b Session) int {
		at := sessionRetentionTime(a)
		bt := sessionRetentionTime(b)
		if at.Equal(bt) {
			return stringsCompare(a.ID, b.ID)
		}
		if at.Before(bt) {
			return -1
		}
		return 1
	})
	start := len(terminal) - retain
	if start < 0 {
		start = 0
	}
	for _, session := range terminal[start:] {
		protected[session.ID] = true
	}
	return protected
}

func terminalState(state State) bool {
	return state == StateReleased || state == StateRemediated || state == StateDestroyed
}

func sessionRetentionTime(session Session) time.Time {
	if !session.UpdatedAt.IsZero() {
		return session.UpdatedAt
	}
	return session.StartedAt
}

func stringsCompare(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
