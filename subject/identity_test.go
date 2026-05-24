package subject

import "testing"

func TestSubjectMatching(t *testing.T) {
	a := NewAgent("claude", "s1", "/repo", "", 123)
	b := NewProcess(123)
	b.Session = "s1"
	if !SameSession(a, b) {
		t.Fatal("expected same session")
	}
	if !Matches(Subject{PID: 123}, b) {
		t.Fatal("expected pid match")
	}
}

func TestSubjectMergePreservesPrimaryIdentityAndFillsScopes(t *testing.T) {
	base := NewAgent("claude", "agent-session-1", "", "implement feature", 0)
	scoped := Subject{
		Kind:     string(KindProcess),
		ID:       "process:123",
		Session:  "agent-session-1",
		PID:      123,
		Cgroup:   "/user.slice/session.scope",
		RepoRoot: "/src/app",
	}
	got := Merge(base, scoped)
	if got.Kind != string(KindAgent) || got.ID != "agent:claude" || got.AgentName != "claude" {
		t.Fatalf("primary identity was not preserved: %+v", got)
	}
	if got.Session != "agent-session-1" || got.PID != 123 || got.Cgroup != "/user.slice/session.scope" || got.RepoRoot != "/src/app" {
		t.Fatalf("scoped identity was not merged: %+v", got)
	}

	conflicting := Subject{
		Kind:      string(KindCgroup),
		ID:        "cgroup:/other.scope",
		Session:   "other-session",
		PID:       999,
		Cgroup:    "/other.scope",
		RepoRoot:  "/other/repo",
		AgentName: "other-agent",
		Task:      "other task",
	}
	got = Merge(got, conflicting)
	if got.Session != "agent-session-1" || got.PID != 123 || got.Cgroup != "/user.slice/session.scope" || got.RepoRoot != "/src/app" {
		t.Fatalf("merge overwrote existing scoped identity: %+v", got)
	}
	if got.AgentName != "claude" || got.Task != "implement feature" {
		t.Fatalf("merge overwrote agent identity: %+v", got)
	}
}

func TestSubjectMergeHandlesEmptySubjects(t *testing.T) {
	repo := NewRepo("/src/app")
	if got := Merge(Subject{}, repo); got != repo {
		t.Fatalf("empty base merge = %+v, want %+v", got, repo)
	}
	if got := Merge(repo, Subject{}); got != repo {
		t.Fatalf("empty incoming merge = %+v, want %+v", got, repo)
	}
}
