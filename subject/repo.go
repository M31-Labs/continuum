package subject

func NewRepo(root string) Subject {
	return Subject{
		Kind:     string(KindRepo),
		ID:       "repo:" + root,
		RepoRoot: root,
	}
}
