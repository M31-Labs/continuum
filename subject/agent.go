package subject

func NewAgent(name, session, repoRoot, task string, pid int) Subject {
	id := ""
	if name != "" {
		id = "agent:" + name
	}
	return Subject{
		Kind:      string(KindAgent),
		ID:        id,
		Session:   session,
		PID:       pid,
		RepoRoot:  repoRoot,
		AgentName: name,
		Task:      task,
	}
}
