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
