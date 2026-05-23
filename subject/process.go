package subject

import "fmt"
import "strings"

func NewProcess(pid int) Subject {
	return Subject{
		Kind: string(KindProcess),
		ID:   fmt.Sprintf("process:%d", pid),
		PID:  pid,
	}
}

func NewProcessTree(session string, pid int) Subject {
	id := "process-tree"
	if strings.HasPrefix(session, "process-tree:") {
		id = session
		session = strings.TrimPrefix(session, "process-tree:")
	} else if session != "" {
		id += ":" + session
	}
	return Subject{
		Kind:    string(KindProcessTree),
		ID:      id,
		Session: session,
		PID:     pid,
	}
}
