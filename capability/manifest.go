package capability

type Kind string

const (
	KindSource Kind = "source"
	KindSink   Kind = "sink"
	KindWorker Kind = "worker"
)

type Requirement struct {
	Name   string `json:"name"`
	Reason string `json:"reason,omitempty"`
}

type Capability struct {
	Name        string         `json:"name"`
	Kind        Kind           `json:"kind"`
	Owner       string         `json:"owner,omitempty"`
	Input       string         `json:"input,omitempty"`
	Output      string         `json:"output,omitempty"`
	Program     string         `json:"program,omitempty"`
	Section     string         `json:"section,omitempty"`
	Danger      Danger         `json:"danger"`
	Backend     string         `json:"backend,omitempty"`
	Description string         `json:"description,omitempty"`
	Requires    []Requirement  `json:"requires,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}
