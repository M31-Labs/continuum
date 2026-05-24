package runtime

import (
	"slices"
	"testing"
	"time"
)

func TestProcessTreePruneRetainsRootRunningAndNewestTerminal(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	tree := &ProcessTree{RootPID: 1, Processes: []ProcessRecord{
		{PID: 1, State: ProcessExited, StartedAt: now.Add(-5 * time.Hour), EndedAt: now.Add(-5 * time.Hour)},
		{PID: 2, State: ProcessExited, StartedAt: now.Add(-4 * time.Hour), EndedAt: now.Add(-4 * time.Hour)},
		{PID: 3, State: ProcessFailed, StartedAt: now.Add(-3 * time.Hour), EndedAt: now.Add(-3 * time.Hour)},
		{PID: 4, State: ProcessRunning, StartedAt: now.Add(-2 * time.Hour)},
		{PID: 5, State: ProcessExited, StartedAt: now.Add(-time.Hour), EndedAt: now.Add(-time.Hour)},
	}}
	report, err := tree.Prune(ProcessTreeRetentionOptions{MaxRecords: 3})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if report.Before != 5 || report.After != 3 || report.Removed != 2 {
		t.Fatalf("report = %+v", report)
	}
	got := processTreePIDsForTest(tree)
	want := []int{1, 4, 5}
	if !slices.Equal(got, want) {
		t.Fatalf("pids = %+v, want %+v", got, want)
	}
}

func processTreePIDsForTest(tree *ProcessTree) []int {
	pids := make([]int, 0, len(tree.Processes))
	for _, record := range tree.Processes {
		pids = append(pids, record.PID)
	}
	slices.Sort(pids)
	return pids
}
