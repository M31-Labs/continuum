package subject

type Identity struct {
	Kind      string `json:"kind,omitempty"`
	ID        string `json:"id,omitempty"`
	Subject   string `json:"subject,omitempty"`
	Session   string `json:"session,omitempty"`
	PID       int    `json:"pid,omitempty"`
	Cgroup    string `json:"cgroup,omitempty"`
	RepoRoot  string `json:"repo_root,omitempty"`
	AgentName string `json:"agent_name,omitempty"`
	Task      string `json:"task,omitempty"`
}

func IdentityFromSubject(s Subject) *Identity {
	if s.Empty() {
		return nil
	}
	return &Identity{
		Kind:      s.Kind,
		ID:        s.ID,
		Subject:   s.String(),
		Session:   s.Session,
		PID:       s.PID,
		Cgroup:    s.Cgroup,
		RepoRoot:  s.RepoRoot,
		AgentName: s.AgentName,
		Task:      s.Task,
	}
}

func SameSession(a, b Subject) bool {
	return a.Session != "" && a.Session == b.Session
}

func Matches(want, got Subject) bool {
	if want.ID != "" && got.ID != "" {
		return want.ID == got.ID
	}
	if want.Session != "" && got.Session != "" {
		return want.Session == got.Session
	}
	if want.PID != 0 && got.PID != 0 {
		return want.PID == got.PID
	}
	return want.Kind != "" && want.Kind == got.Kind
}
