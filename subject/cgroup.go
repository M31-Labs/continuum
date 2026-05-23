package subject

func NewCgroup(path string) Subject {
	return Subject{
		Kind:   string(KindCgroup),
		ID:     "cgroup:" + path,
		Cgroup: path,
	}
}
