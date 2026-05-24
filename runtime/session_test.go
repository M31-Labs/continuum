package runtime

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/subject"
)

func TestSessionStorePersistsAndFinishes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	store := &SessionStore{}
	store.Upsert(Session{
		ID:        "agent-session-1",
		Subject:   subject.NewAgent("claude", "agent-session-1", "/repo", "", 123),
		Command:   []string{"go", "test", "./..."},
		State:     SessionRunning,
		StartedAt: now,
	})
	if store.Sessions[0].LastHeartbeatAt.IsZero() {
		t.Fatalf("upsert did not seed heartbeat: %+v", store.Sessions[0])
	}
	if len(store.Running()) != 1 {
		t.Fatalf("running = %+v", store.Running())
	}
	if _, err := store.Finish("agent-session-1", SessionExited, 0, now.Add(time.Second)); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if len(store.Running()) != 0 {
		t.Fatalf("running after finish = %+v", store.Running())
	}
	if err := store.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	reloaded, err := LoadSessionStore(path)
	if err != nil {
		t.Fatalf("LoadSessionStore: %v", err)
	}
	if len(reloaded.Sessions) != 1 || reloaded.Sessions[0].State != SessionExited {
		t.Fatalf("reloaded = %+v", reloaded.Sessions)
	}
	if !reloaded.Sessions[0].LastHeartbeatAt.Equal(now.Add(time.Second)) {
		t.Fatalf("finish heartbeat = %s", reloaded.Sessions[0].LastHeartbeatAt)
	}
	tree := reloaded.Sessions[0].ProcessTree
	if tree == nil || len(tree.Processes) != 1 || tree.Processes[0].State != ProcessExited {
		t.Fatalf("process tree = %+v", tree)
	}
}

func TestSessionStoreSchemaMigration(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "legacy-sessions.json")
	if err := os.WriteFile(legacyPath, []byte(`{"sessions":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	legacy, err := LoadSessionStore(legacyPath)
	if err != nil {
		t.Fatalf("LoadSessionStore legacy: %v", err)
	}
	if legacy.SchemaVersion != SessionStoreSchemaVersion {
		t.Fatalf("legacy schema version = %d", legacy.SchemaVersion)
	}
	futurePath := filepath.Join(dir, "future-sessions.json")
	if err := os.WriteFile(futurePath, []byte(`{"schema_version":99,"sessions":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSessionStore(futurePath); err == nil {
		t.Fatal("future session store schema loaded without error")
	}
}

func TestSessionStoreCompactRetainsRunningAndNewestTerminal(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	store := &SessionStore{SchemaVersion: SessionStoreSchemaVersion, Sessions: []Session{
		{ID: "old", State: SessionExited, StartedAt: now.Add(-4 * time.Hour), EndedAt: now.Add(-3 * time.Hour)},
		{ID: "new", State: SessionFailed, StartedAt: now.Add(-2 * time.Hour), EndedAt: now.Add(-time.Hour)},
		{ID: "running", State: SessionRunning, StartedAt: now.Add(-5 * time.Hour), LastHeartbeatAt: now.Add(-5 * time.Hour)},
	}}
	report, err := store.Compact(RetentionOptions{Retain: 1, Now: now})
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if report.Removed != 1 || len(store.Sessions) != 2 {
		t.Fatalf("report=%+v sessions=%+v", report, store.Sessions)
	}
	if _, ok := findSessionForTest(store.Sessions, "running"); !ok {
		t.Fatalf("running session pruned: %+v", store.Sessions)
	}
	if _, ok := findSessionForTest(store.Sessions, "new"); !ok {
		t.Fatalf("newest terminal session pruned: %+v", store.Sessions)
	}
}

func TestSessionStoreHeartbeatAndMarkStale(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	store := &SessionStore{}
	store.Upsert(Session{
		ID:              "agent-session-1",
		Subject:         subject.NewAgent("claude", "agent-session-1", "/repo", "", 123),
		State:           SessionRunning,
		StartedAt:       now.Add(-time.Hour),
		LastHeartbeatAt: now.Add(-time.Hour),
	})
	stale := store.MarkStale(now, 10*time.Minute)
	if len(stale) != 1 || stale[0].State != SessionStale || len(store.Stale()) != 1 || len(store.Running()) != 0 {
		t.Fatalf("stale=%+v store=%+v", stale, store.Sessions)
	}
	session, err := store.Heartbeat("agent-session-1", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if session.State != SessionRunning || !session.LastHeartbeatAt.Equal(now.Add(time.Minute)) || len(store.Running()) != 1 {
		t.Fatalf("heartbeat session=%+v store=%+v", session, store.Sessions)
	}
}

func TestSessionStoreTracksChildProcessEvents(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	subj := subject.NewAgent("claude", "agent-session-1", "/repo", "bash", 123)
	store := &SessionStore{}
	store.Upsert(Session{
		ID:          "agent-session-1",
		Subject:     subj,
		Command:     []string{"bash"},
		State:       SessionRunning,
		ProcessTree: NewProcessLifecycleTree(subj, []string{"bash"}, now),
		StartedAt:   now,
	})
	execEvent := event.NewProcessExec(subj, map[string]any{
		"pid":       456,
		"ppid":      123,
		"comm":      "go",
		"argv_text": "go test ./...",
		"cwd":       "/repo",
	})
	execEvent.Time = now.Add(time.Second)
	session, changed, err := store.TrackProcessEvent(execEvent, now.Add(time.Second))
	if err != nil {
		t.Fatalf("TrackProcessEvent: %v", err)
	}
	if !changed {
		t.Fatal("TrackProcessEvent did not report child exec")
	}
	if got := len(session.ProcessTree.Processes); got != 2 {
		t.Fatalf("process count = %d tree=%+v", got, session.ProcessTree)
	}
	child := findProcess(t, session.ProcessTree, 456)
	if child.ParentPID != 123 || child.Comm != "go" || child.State != ProcessRunning {
		t.Fatalf("child = %+v", child)
	}
	exitEvent := event.NewProcessExit(subj, map[string]any{
		"pid":       456,
		"exit_code": 1,
	})
	exitEvent.Time = now.Add(2 * time.Second)
	session, changed, err = store.TrackProcessEvent(exitEvent, now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("TrackProcessEvent exit: %v", err)
	}
	if !changed {
		t.Fatal("TrackProcessEvent did not report child exit")
	}
	child = findProcess(t, session.ProcessTree, 456)
	if child.State != ProcessFailed || child.ExitCode != 1 {
		t.Fatalf("child after exit = %+v", child)
	}
	if session.State != SessionRunning {
		t.Fatalf("child exit changed session state: %+v", session)
	}
}

func TestSessionStoreTracksChildProcessFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "events", "child_process_tree.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	events, err := DecodeEvents(data, nil)
	if err != nil {
		t.Fatalf("DecodeEvents: %v", err)
	}
	store := &SessionStore{}
	changed, err := store.TrackProcessEvents(events, nil)
	if err != nil {
		t.Fatalf("TrackProcessEvents: %v", err)
	}
	if changed != len(events) {
		t.Fatalf("changed = %d, want %d", changed, len(events))
	}
	if len(store.Sessions) != 1 {
		t.Fatalf("sessions = %+v", store.Sessions)
	}
	session := store.Sessions[0]
	if session.ID != "agent-child-fixture" || session.State != SessionExited {
		t.Fatalf("session = %+v", session)
	}
	if session.Subject.Cgroup != "/user.slice/agent.scope" || session.Subject.RepoRoot != "/src/app" {
		t.Fatalf("session subject = %+v", session.Subject)
	}
	if session.ProcessTree == nil || session.ProcessTree.RootPID != 100 || len(session.ProcessTree.Processes) != 2 {
		t.Fatalf("process tree = %+v", session.ProcessTree)
	}
	child := findProcess(t, session.ProcessTree, 101)
	if child.ParentPID != 100 || child.Comm != "go" || child.State != ProcessExited {
		t.Fatalf("child = %+v", child)
	}
}

func findSessionForTest(sessions []Session, id string) (Session, bool) {
	for _, session := range sessions {
		if session.ID == id {
			return session, true
		}
	}
	return Session{}, false
}

func TestSessionStoreCreatesObservedSessionFromProcessEvent(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	subj := subject.NewAgent("claude", "agent-session-2", "/repo", "", 0)
	evt := event.NewProcessExec(subj, map[string]any{
		"pid":       float64(789),
		"comm":      "node",
		"argv_text": "node server.js",
		"cwd":       "/repo",
	})
	store := &SessionStore{}
	session, changed, err := store.TrackProcessEvent(evt, now)
	if err != nil {
		t.Fatalf("TrackProcessEvent: %v", err)
	}
	if !changed || len(store.Sessions) != 1 {
		t.Fatalf("changed=%v sessions=%+v", changed, store.Sessions)
	}
	if session.ID != "agent-session-2" || session.Subject.PID != 789 || session.ProcessTree == nil || session.ProcessTree.RootPID != 789 {
		t.Fatalf("session = %+v", session)
	}
}

func TestSessionStoreMergesSubjectIdentityFromLifecycleEvents(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	store := &SessionStore{}
	store.Upsert(Session{
		ID:        "agent-session-merge",
		Subject:   subject.Subject{Kind: string(subject.KindAgent), Session: "agent-session-merge", AgentName: "claude"},
		State:     SessionRunning,
		StartedAt: now,
	})
	evt := event.NewProcessExec(subject.Subject{
		Kind:     string(subject.KindProcess),
		Session:  "agent-session-merge",
		Cgroup:   "/user.slice/agent.scope",
		RepoRoot: "/src/app",
	}, map[string]any{
		"pid":       321,
		"comm":      "bash",
		"argv_text": "bash",
		"cwd":       "/src/app",
	})
	evt.Time = now.Add(time.Second)
	session, changed, err := store.TrackProcessEvent(evt, now.Add(time.Second))
	if err != nil {
		t.Fatalf("TrackProcessEvent: %v", err)
	}
	if !changed {
		t.Fatal("TrackProcessEvent did not report process exec")
	}
	if session.Subject.Kind != string(subject.KindAgent) || session.Subject.AgentName != "claude" || session.Subject.Session != "agent-session-merge" {
		t.Fatalf("primary/session identity changed: %+v", session.Subject)
	}
	if session.Subject.PID != 321 || session.Subject.Cgroup != "/user.slice/agent.scope" || session.Subject.RepoRoot != "/src/app" {
		t.Fatalf("process, cgroup, and repo identity were not merged: %+v", session.Subject)
	}
}

func findProcess(t *testing.T, tree *ProcessTree, pid int) ProcessRecord {
	t.Helper()
	if tree == nil {
		t.Fatal("nil process tree")
	}
	for _, process := range tree.Processes {
		if process.PID == pid {
			return process
		}
	}
	t.Fatalf("pid %d not found in %+v", pid, tree.Processes)
	return ProcessRecord{}
}
