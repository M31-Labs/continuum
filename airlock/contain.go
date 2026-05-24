package airlock

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"m31labs.dev/continuum/internal/statefile"
	"m31labs.dev/continuum/subject"
)

type Store struct {
	mu       sync.Mutex
	sessions map[string]Session
}

func NewStore() *Store {
	return &Store{sessions: map[string]Session{}}
}

func LoadStore(path string) (*Store, error) {
	store := NewStore()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, fmt.Errorf("read airlock store %s: %w", path, err)
	}
	var sessions []Session
	if err := json.Unmarshal(data, &sessions); err != nil {
		return nil, fmt.Errorf("parse airlock store %s: %w", path, err)
	}
	for _, session := range sessions {
		store.sessions[session.ID] = session
	}
	return store, nil
}

func (s *Store) Save(path string) error {
	if s == nil {
		return fmt.Errorf("nil airlock store")
	}
	return statefile.WriteJSON(path, s.List())
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
		return statefile.WriteJSONWithoutLock(path, store.List())
	})
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
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok {
		return Session{}, fmt.Errorf("airlock session %q not found", id)
	}
	if err := session.Transition(StateReleased, reason, now); err != nil {
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
