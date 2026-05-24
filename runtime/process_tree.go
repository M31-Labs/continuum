package runtime

import (
	"slices"
	"strings"
	"time"

	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/subject"
)

type ProcessState string

const (
	ProcessRunning ProcessState = "running"
	ProcessExited  ProcessState = "exited"
	ProcessFailed  ProcessState = "failed"
)

type ProcessRecord struct {
	PID       int          `json:"pid"`
	ParentPID int          `json:"parent_pid,omitempty"`
	Cgroup    string       `json:"cgroup,omitempty"`
	Comm      string       `json:"comm,omitempty"`
	ArgvText  string       `json:"argv_text,omitempty"`
	CWD       string       `json:"cwd,omitempty"`
	State     ProcessState `json:"state"`
	StartedAt time.Time    `json:"started_at,omitempty"`
	EndedAt   time.Time    `json:"ended_at,omitempty"`
	ExitCode  int          `json:"exit_code,omitempty"`
}

type ProcessTree struct {
	RootPID   int             `json:"root_pid,omitempty"`
	Processes []ProcessRecord `json:"processes,omitempty"`
}

func NewProcessLifecycleTree(subj subject.Subject, command []string, now time.Time) *ProcessTree {
	tree := &ProcessTree{RootPID: subj.PID}
	if subj.PID == 0 {
		return tree
	}
	comm := ""
	if len(command) > 0 {
		comm = command[0]
	}
	tree.upsert(ProcessRecord{
		PID:       subj.PID,
		Cgroup:    subj.Cgroup,
		Comm:      comm,
		ArgvText:  strings.Join(command, " "),
		State:     ProcessRunning,
		StartedAt: now,
	})
	return tree
}

func (t *ProcessTree) ObserveEvent(evt event.Event, now time.Time) bool {
	if t == nil {
		return false
	}
	switch evt.Kind {
	case event.KindProcessExec:
		return t.observeExec(evt, now)
	case event.KindProcessExit:
		return t.observeExit(evt, now)
	default:
		return false
	}
}

func (t *ProcessTree) FinishPID(pid int, state ProcessState, exitCode int, endedAt time.Time) bool {
	if t == nil || pid == 0 {
		return false
	}
	if t.RootPID == 0 {
		t.RootPID = pid
	}
	for i := range t.Processes {
		if t.Processes[i].PID != pid {
			continue
		}
		t.Processes[i].State = state
		t.Processes[i].ExitCode = exitCode
		t.Processes[i].EndedAt = endedAt
		t.sort()
		return true
	}
	t.upsert(ProcessRecord{
		PID:      pid,
		State:    state,
		ExitCode: exitCode,
		EndedAt:  endedAt,
	})
	return true
}

func (t *ProcessTree) Running() []ProcessRecord {
	if t == nil {
		return nil
	}
	out := make([]ProcessRecord, 0, len(t.Processes))
	for _, process := range t.Processes {
		if process.State == ProcessRunning {
			out = append(out, process)
		}
	}
	return out
}

func (t *ProcessTree) observeExec(evt event.Event, now time.Time) bool {
	pid := processEventPID(evt)
	if pid == 0 {
		return false
	}
	if t.RootPID == 0 {
		t.RootPID = pid
	}
	record := ProcessRecord{
		PID:       pid,
		ParentPID: processParentPID(evt),
		Cgroup:    processStringField(evt.Fields, "cgroup"),
		Comm:      processStringField(evt.Fields, "comm"),
		ArgvText:  processStringField(evt.Fields, "argv_text"),
		CWD:       processStringField(evt.Fields, "cwd"),
		State:     ProcessRunning,
		StartedAt: processEventTime(evt, now),
	}
	if record.Cgroup == "" {
		record.Cgroup = evt.Subject.Cgroup
	}
	t.upsert(record)
	return true
}

func (t *ProcessTree) observeExit(evt event.Event, now time.Time) bool {
	pid := processEventPID(evt)
	if pid == 0 {
		return false
	}
	exitCode := processExitCode(evt)
	state := ProcessExited
	if exitCode != 0 || processBoolField(evt.Fields, "failed") {
		state = ProcessFailed
	}
	if rawState := processStringField(evt.Fields, "state"); rawState == string(ProcessExited) || rawState == string(ProcessFailed) {
		state = ProcessState(rawState)
	}
	return t.FinishPID(pid, state, exitCode, processEventTime(evt, now))
}

func (t *ProcessTree) upsert(record ProcessRecord) {
	for i := range t.Processes {
		if t.Processes[i].PID != record.PID {
			continue
		}
		mergeProcessRecord(&t.Processes[i], record)
		t.sort()
		return
	}
	t.Processes = append(t.Processes, record)
	t.sort()
}

func mergeProcessRecord(existing *ProcessRecord, next ProcessRecord) {
	if next.ParentPID != 0 {
		existing.ParentPID = next.ParentPID
	}
	if next.Cgroup != "" {
		existing.Cgroup = next.Cgroup
	}
	if next.Comm != "" {
		existing.Comm = next.Comm
	}
	if next.ArgvText != "" {
		existing.ArgvText = next.ArgvText
	}
	if next.CWD != "" {
		existing.CWD = next.CWD
	}
	if next.State != "" {
		existing.State = next.State
	}
	if !next.StartedAt.IsZero() && (existing.StartedAt.IsZero() || next.StartedAt.Before(existing.StartedAt)) {
		existing.StartedAt = next.StartedAt
	}
	if !next.EndedAt.IsZero() {
		existing.EndedAt = next.EndedAt
	}
	if next.ExitCode != 0 {
		existing.ExitCode = next.ExitCode
	}
}

func (t *ProcessTree) sort() {
	slices.SortFunc(t.Processes, func(a, b ProcessRecord) int {
		if a.StartedAt.IsZero() != b.StartedAt.IsZero() {
			if a.StartedAt.IsZero() {
				return 1
			}
			return -1
		}
		if !a.StartedAt.Equal(b.StartedAt) {
			if a.StartedAt.Before(b.StartedAt) {
				return -1
			}
			return 1
		}
		if a.PID < b.PID {
			return -1
		}
		if a.PID > b.PID {
			return 1
		}
		return 0
	})
}

func processEventPID(evt event.Event) int {
	if pid := processIntField(evt.Fields, "pid"); pid != 0 {
		return pid
	}
	return evt.Subject.PID
}

func processParentPID(evt event.Event) int {
	if ppid := processIntField(evt.Fields, "ppid"); ppid != 0 {
		return ppid
	}
	return processIntField(evt.Fields, "parent_pid")
}

func processExitCode(evt event.Event) int {
	for _, key := range []string{"exit_code", "status", "code"} {
		if value := processIntField(evt.Fields, key); value != 0 {
			return value
		}
	}
	return 0
}

func processEventTime(evt event.Event, fallback time.Time) time.Time {
	if !evt.Time.IsZero() {
		return evt.Time
	}
	return fallback
}

func processStringField(fields map[string]any, key string) string {
	value, _ := fields[key].(string)
	return value
}

func processIntField(fields map[string]any, key string) int {
	switch value := fields[key].(type) {
	case int:
		return value
	case int8:
		return int(value)
	case int16:
		return int(value)
	case int32:
		return int(value)
	case int64:
		return int(value)
	case uint:
		return int(value)
	case uint8:
		return int(value)
	case uint16:
		return int(value)
	case uint32:
		return int(value)
	case uint64:
		return int(value)
	case float32:
		return int(value)
	case float64:
		return int(value)
	default:
		return 0
	}
}

func processBoolField(fields map[string]any, key string) bool {
	value, _ := fields[key].(bool)
	return value
}
