package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"m31labs.dev/continuum/subject"
)

type SessionState string

const (
	SessionRunning SessionState = "running"
	SessionExited  SessionState = "exited"
	SessionFailed  SessionState = "failed"
)

type Session struct {
	ID        string          `json:"id"`
	Subject   subject.Subject `json:"subject"`
	Command   []string        `json:"command,omitempty"`
	Policy    string          `json:"policy,omitempty"`
	AuditPath string          `json:"audit_path,omitempty"`
	State     SessionState    `json:"state"`
	ExitCode  int             `json:"exit_code,omitempty"`
	StartedAt time.Time       `json:"started_at"`
	EndedAt   time.Time       `json:"ended_at,omitempty"`
}

type SessionStore struct {
	Sessions []Session `json:"sessions,omitempty"`
}

func LoadSessionStore(path string) (*SessionStore, error) {
	store := &SessionStore{}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, fmt.Errorf("read session store %s: %w", path, err)
	}
	if err := json.Unmarshal(data, store); err != nil {
		return nil, fmt.Errorf("parse session store %s: %w", path, err)
	}
	return store, nil
}

func (s *SessionStore) Save(path string) error {
	if s == nil {
		return fmt.Errorf("nil session store")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create session store dir: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}

func (s *SessionStore) Upsert(session Session) {
	for i := range s.Sessions {
		if s.Sessions[i].ID == session.ID {
			s.Sessions[i] = session
			s.sort()
			return
		}
	}
	s.Sessions = append(s.Sessions, session)
	s.sort()
}

func (s *SessionStore) Finish(id string, state SessionState, exitCode int, endedAt time.Time) (Session, error) {
	for i := range s.Sessions {
		if s.Sessions[i].ID != id {
			continue
		}
		s.Sessions[i].State = state
		s.Sessions[i].ExitCode = exitCode
		s.Sessions[i].EndedAt = endedAt
		return s.Sessions[i], nil
	}
	return Session{}, fmt.Errorf("session %q not found", id)
}

func (s *SessionStore) Running() []Session {
	var out []Session
	for _, session := range s.Sessions {
		if session.State == SessionRunning {
			out = append(out, session)
		}
	}
	return out
}

func (s *SessionStore) sort() {
	slices.SortFunc(s.Sessions, func(a, b Session) int {
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
}
