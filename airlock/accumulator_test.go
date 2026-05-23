package airlock

import (
	"fmt"
	"testing"

	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/subject"
)

func TestAccumulatorBuildsBehavior(t *testing.T) {
	subj := subject.NewProcessTree("demo", 123)
	acc := NewAccumulator("process-tree:demo")
	for i := 0; i < 3; i++ {
		acc.Observe(event.NewProcessExec(subj, map[string]any{"comm": "sh"}))
	}
	for i := 0; i < 2; i++ {
		acc.Observe(event.NewNetworkConnect(subj, fmt.Sprintf("host-%d.example", i), "", 443))
	}
	acc.Observe(event.NewFileAccess(subj, "/home/draco/.ssh/id_ed25519", "read"))
	acc.Observe(event.Event{
		Kind:    event.KindFileAccess,
		Subject: subj,
		Fields: map[string]any{
			"path":                   "/repo/a.txt",
			"op":                     "write",
			"entropy_increase_score": 0.91,
		},
	})
	behavior := acc.Behavior()
	if behavior.ExecCount != 3 || behavior.UniqueNetworkTargets != 2 {
		t.Fatalf("behavior counts = %+v", behavior)
	}
	if behavior.TouchedSecretPaths != 1 || behavior.RewrittenFiles != 1 || behavior.EntropyIncreaseScore != 0.91 {
		t.Fatalf("file behavior = %+v", behavior)
	}
}
