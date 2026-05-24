package runtime

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/internal/statefile"
	"m31labs.dev/continuum/subject"
)

type SessionState string

const (
	SessionRunning SessionState = "running"
	SessionExited  SessionState = "exited"
	SessionFailed  SessionState = "failed"
	SessionStale   SessionState = "stale"
)

const SessionStoreSchemaVersion = 1

type Session struct {
	ID              string          `json:"id"`
	Subject         subject.Subject `json:"subject"`
	Command         []string        `json:"command,omitempty"`
	Policy          string          `json:"policy,omitempty"`
	AuditPath       string          `json:"audit_path,omitempty"`
	State           SessionState    `json:"state"`
	ExitCode        int             `json:"exit_code,omitempty"`
	ProcessTree     *ProcessTree    `json:"process_tree,omitempty"`
	StartedAt       time.Time       `json:"started_at"`
	LastHeartbeatAt time.Time       `json:"last_heartbeat_at,omitempty"`
	EndedAt         time.Time       `json:"ended_at,omitempty"`
}

type SessionStore struct {
	SchemaVersion int       `json:"schema_version"`
	Sessions      []Session `json:"sessions,omitempty"`
}

func LoadSessionStore(path string) (*SessionStore, error) {
	store := &SessionStore{SchemaVersion: SessionStoreSchemaVersion}
	if _, err := statefile.ReadJSON(path, store); err != nil {
		return nil, fmt.Errorf("load session store %s: %w", path, err)
	}
	if err := store.MigrateSchema(); err != nil {
		return nil, fmt.Errorf("load session store %s: %w", path, err)
	}
	return store, nil
}

func (s *SessionStore) Save(path string) error {
	if s == nil {
		return fmt.Errorf("nil session store")
	}
	if err := s.MigrateSchema(); err != nil {
		return err
	}
	return statefile.WriteJSON(path, s)
}

func UpdateSessionStore(path string, mutate func(*SessionStore) error) error {
	if mutate == nil {
		return fmt.Errorf("session store mutation callback is required")
	}
	return statefile.WithLock(path, func() error {
		store, err := LoadSessionStore(path)
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

func (s *SessionStore) MigrateSchema() error {
	if s == nil {
		return fmt.Errorf("nil session store")
	}
	return statefile.MigrateSchema("session store", &s.SchemaVersion, SessionStoreSchemaVersion, nil)
}

func (s *SessionStore) Upsert(session Session) {
	if session.State == SessionRunning && session.LastHeartbeatAt.IsZero() && !session.StartedAt.IsZero() {
		session.LastHeartbeatAt = session.StartedAt
	}
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
		session := &s.Sessions[i]
		session.State = state
		session.ExitCode = exitCode
		session.EndedAt = endedAt
		session.LastHeartbeatAt = endedAt
		processState := ProcessExited
		if state == SessionFailed {
			processState = ProcessFailed
		}
		tree := session.ensureProcessTree(endedAt)
		pid := session.Subject.PID
		if pid == 0 {
			pid = tree.RootPID
		}
		tree.FinishPID(pid, processState, exitCode, endedAt)
		return s.Sessions[i], nil
	}
	return Session{}, fmt.Errorf("session %q not found", id)
}

func (s *SessionStore) TrackProcessEvent(evt event.Event, now time.Time) (Session, bool, error) {
	if s == nil {
		return Session{}, false, fmt.Errorf("nil session store")
	}
	if !isProcessLifecycleEvent(evt.Kind) {
		return Session{}, false, nil
	}
	sessionID := processEventSessionID(evt)
	if sessionID == "" {
		return Session{}, false, nil
	}
	index := s.findIndex(sessionID)
	if index == -1 {
		started := processEventTime(evt, now)
		s.Sessions = append(s.Sessions, Session{
			ID:              sessionID,
			Subject:         evt.Subject,
			State:           SessionRunning,
			StartedAt:       started,
			LastHeartbeatAt: started,
		})
		index = len(s.Sessions) - 1
	}
	session := &s.Sessions[index]
	if session.Subject.Empty() {
		session.Subject = evt.Subject
	}
	if session.StartedAt.IsZero() {
		session.StartedAt = processEventTime(evt, now)
	}
	session.LastHeartbeatAt = processEventTime(evt, now)
	if session.State == SessionStale {
		session.State = SessionRunning
	}
	changed := session.ensureProcessTree(now).ObserveEvent(evt, now)
	if changed {
		s.applyLifecycleToSession(session, evt, now)
		s.sort()
	}
	return *session, changed, nil
}

func (s *SessionStore) TrackProcessEvents(events []event.Event, now func() time.Time) (int, error) {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	changed := 0
	for _, evt := range events {
		_, ok, err := s.TrackProcessEvent(evt, now())
		if err != nil {
			return changed, err
		}
		if ok {
			changed++
		}
	}
	return changed, nil
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

func (s *SessionStore) Stale() []Session {
	var out []Session
	for _, session := range s.Sessions {
		if session.State == SessionStale {
			out = append(out, session)
		}
	}
	return out
}

func (s *SessionStore) Heartbeat(id string, now time.Time) (Session, error) {
	if s == nil {
		return Session{}, fmt.Errorf("nil session store")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	for i := range s.Sessions {
		if s.Sessions[i].ID != id {
			continue
		}
		session := &s.Sessions[i]
		if session.State == SessionExited || session.State == SessionFailed {
			return Session{}, fmt.Errorf("session %q is %s", id, session.State)
		}
		if session.StartedAt.IsZero() {
			session.StartedAt = now
		}
		session.LastHeartbeatAt = now
		session.State = SessionRunning
		s.sort()
		return *session, nil
	}
	return Session{}, fmt.Errorf("session %q not found", id)
}

func (s *SessionStore) MarkStale(now time.Time, maxAge time.Duration) []Session {
	if s == nil || maxAge <= 0 {
		return nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	var stale []Session
	for i := range s.Sessions {
		session := &s.Sessions[i]
		if session.State != SessionRunning {
			continue
		}
		last := session.LastHeartbeatAt
		if last.IsZero() {
			last = session.StartedAt
		}
		if last.IsZero() || last.After(now) {
			continue
		}
		if now.Sub(last) <= maxAge {
			continue
		}
		session.State = SessionStale
		stale = append(stale, *session)
	}
	if len(stale) > 0 {
		s.sort()
	}
	return stale
}

func (s *SessionStore) Compact(opts RetentionOptions) (RetentionReport, error) {
	if s == nil {
		return RetentionReport{}, fmt.Errorf("nil session store")
	}
	if err := opts.Validate(); err != nil {
		return RetentionReport{}, err
	}
	now := retentionNow(opts)
	cutoff := now.Add(-opts.OlderThan)
	report := RetentionReport{Before: len(s.Sessions)}
	retained := retainedTerminalSessionIndexes(s.Sessions, opts.Retain)
	kept := s.Sessions[:0]
	for i, session := range s.Sessions {
		if !terminalSessionState(session.State) || retained[i] || !sessionExpiredForRetention(session, opts, cutoff) {
			kept = append(kept, session)
		}
	}
	s.Sessions = kept
	s.sort()
	report.After = len(s.Sessions)
	report.Removed = report.Before - report.After
	return report, nil
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

func retainedTerminalSessionIndexes(sessions []Session, retain int) map[int]bool {
	out := map[int]bool{}
	if retain <= 0 {
		return out
	}
	indexes := make([]int, 0, len(sessions))
	for i, session := range sessions {
		if terminalSessionState(session.State) {
			indexes = append(indexes, i)
		}
	}
	slices.SortFunc(indexes, func(a, b int) int {
		at := sessionRetentionTime(sessions[a])
		bt := sessionRetentionTime(sessions[b])
		if at.Equal(bt) {
			return strings.Compare(sessions[b].ID, sessions[a].ID)
		}
		if at.After(bt) {
			return -1
		}
		return 1
	})
	for i, index := range indexes {
		if i >= retain {
			break
		}
		out[index] = true
	}
	return out
}

func terminalSessionState(state SessionState) bool {
	return state == SessionExited || state == SessionFailed
}

func sessionExpiredForRetention(session Session, opts RetentionOptions, cutoff time.Time) bool {
	if opts.OlderThan == 0 {
		return true
	}
	t := sessionRetentionTime(session)
	return !t.IsZero() && t.Before(cutoff)
}

func sessionRetentionTime(session Session) time.Time {
	if !session.EndedAt.IsZero() {
		return session.EndedAt
	}
	if !session.LastHeartbeatAt.IsZero() {
		return session.LastHeartbeatAt
	}
	return session.StartedAt
}

func (s *SessionStore) findIndex(id string) int {
	for i := range s.Sessions {
		if s.Sessions[i].ID == id {
			return i
		}
	}
	return -1
}

func (s *SessionStore) applyLifecycleToSession(session *Session, evt event.Event, now time.Time) {
	if session == nil || session.ProcessTree == nil {
		return
	}
	if session.Subject.PID == 0 && session.ProcessTree.RootPID != 0 {
		session.Subject.PID = session.ProcessTree.RootPID
	}
	if session.Subject.Cgroup == "" && evt.Subject.Cgroup != "" {
		session.Subject.Cgroup = evt.Subject.Cgroup
	}
	if evt.Kind != event.KindProcessExit {
		return
	}
	pid := processEventPID(evt)
	if pid == 0 {
		return
	}
	rootPID := session.Subject.PID
	if rootPID == 0 {
		rootPID = session.ProcessTree.RootPID
	}
	if pid != rootPID {
		return
	}
	exitCode := processExitCode(evt)
	session.ExitCode = exitCode
	session.EndedAt = processEventTime(evt, now)
	if exitCode != 0 || processBoolField(evt.Fields, "failed") {
		session.State = SessionFailed
		return
	}
	session.State = SessionExited
}

func (s *Session) ensureProcessTree(now time.Time) *ProcessTree {
	if s.ProcessTree != nil {
		return s.ProcessTree
	}
	started := s.StartedAt
	if started.IsZero() {
		started = now
	}
	s.ProcessTree = NewProcessLifecycleTree(s.Subject, s.Command, started)
	return s.ProcessTree
}

func isProcessLifecycleEvent(kind string) bool {
	return kind == event.KindProcessExec || kind == event.KindProcessExit
}

func processEventSessionID(evt event.Event) string {
	if evt.Subject.Session != "" {
		return evt.Subject.Session
	}
	if strings.HasPrefix(evt.Subject.ID, "process-tree:") {
		return strings.TrimPrefix(evt.Subject.ID, "process-tree:")
	}
	return ""
}
