package runtime

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"

	"m31labs.dev/continuum/airlock"
	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/subject"
)

func TestEvaluateAirlockPersistsAccumulatorsAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	subj := subject.NewAgent("claude", "agent-42", "/repo", "", 123)
	opts := AirlockOptions{
		PolicyPath:           filepath.Join("..", "examples", "airlock", "policies", "main.arb"),
		StorePath:            filepath.Join(dir, "airlock.json"),
		AccumulatorStorePath: filepath.Join(dir, "airlock-accumulators.json"),
		AuditPath:            filepath.Join(dir, "audit.jsonl"),
		IDStore:              filepath.Join(dir, "ids.json"),
	}
	first := airlockFanoutEvents(subj, 20, 50, 0)
	results, err := EvaluateAirlockForEvents(context.Background(), first, opts)
	if err != nil {
		t.Fatalf("EvaluateAirlockForEvents first: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("first batch should not enter airlock: %+v", results)
	}
	second := airlockFanoutEvents(subj, 1, 1, 50)
	results, err = EvaluateAirlockForEvents(context.Background(), second, opts)
	if err != nil {
		t.Fatalf("EvaluateAirlockForEvents second: %v", err)
	}
	if len(results) != 1 || results[0].Session == nil {
		t.Fatalf("second batch should enter airlock: %+v", results)
	}
	store, err := airlock.LoadAccumulatorStore(opts.AccumulatorStorePath)
	if err != nil {
		t.Fatalf("LoadAccumulatorStore: %v", err)
	}
	snapshot, ok := store.Get("agent:claude")
	if !ok {
		t.Fatal("missing persisted agent accumulator")
	}
	if got := snapshot.Behavior(); got.ExecCount != 21 || got.UniqueNetworkTargets != 51 {
		t.Fatalf("persisted behavior = %+v", got)
	}
	results, err = EvaluateAirlockForEvents(context.Background(), airlockFanoutEvents(subj, 1, 1, 51), opts)
	if err != nil {
		t.Fatalf("EvaluateAirlockForEvents repeated: %v", err)
	}
	if len(results) != 1 || results[0].Session == nil {
		t.Fatalf("repeated threshold result = %+v", results)
	}
	airlocks, err := airlock.LoadStore(opts.StorePath)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if len(airlocks.List()) != 1 {
		t.Fatalf("duplicate airlock sessions were created: %+v", airlocks.List())
	}
}

func airlockFanoutEvents(subj subject.Subject, execCount, networkTargets, networkOffset int) []event.Event {
	events := make([]event.Event, 0, execCount+networkTargets)
	for i := 0; i < execCount; i++ {
		events = append(events, event.NewProcessExec(subj, map[string]any{
			"comm":      "sh",
			"argv_text": "sh -c true",
			"cwd":       "/repo",
		}))
	}
	for i := 0; i < networkTargets; i++ {
		target := networkOffset + i
		events = append(events, event.NewNetworkConnect(subj, "host-"+strconv.Itoa(target)+".example", "10.0.0."+strconv.Itoa(target), 443))
	}
	return events
}
