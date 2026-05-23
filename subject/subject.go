package subject

import "fmt"

type Kind string

const (
	KindAgent       Kind = "agent"
	KindProcess     Kind = "process"
	KindProcessTree Kind = "process-tree"
	KindCgroup      Kind = "cgroup"
	KindRepo        Kind = "repo"
)

type Subject struct {
	Kind      string `json:"kind,omitempty"`
	ID        string `json:"id,omitempty"`
	Session   string `json:"session,omitempty"`
	PID       int    `json:"pid,omitempty"`
	Cgroup    string `json:"cgroup,omitempty"`
	RepoRoot  string `json:"repo_root,omitempty"`
	AgentName string `json:"agent_name,omitempty"`
	Task      string `json:"task,omitempty"`
}

func (s Subject) String() string {
	if s.ID != "" {
		return s.ID
	}
	switch {
	case s.Kind == string(KindAgent) && s.AgentName != "":
		return "agent:" + s.AgentName
	case s.Kind == string(KindProcessTree) && s.Session != "":
		return "process-tree:" + s.Session
	case s.PID != 0:
		return fmt.Sprintf("%s:%d", s.Kind, s.PID)
	case s.Session != "":
		return s.Kind + ":" + s.Session
	case s.Kind != "":
		return s.Kind
	default:
		return "unknown"
	}
}

func (s Subject) Empty() bool {
	return s.Kind == "" && s.ID == "" && s.Session == "" && s.PID == 0 && s.Cgroup == "" && s.RepoRoot == "" && s.AgentName == ""
}
