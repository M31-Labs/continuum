package runtime

import (
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
	tree := reloaded.Sessions[0].ProcessTree
	if tree == nil || len(tree.Processes) != 1 || tree.Processes[0].State != ProcessExited {
		t.Fatalf("process tree = %+v", tree)
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
