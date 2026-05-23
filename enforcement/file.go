package enforcement

type FileDeny struct {
	Session string `json:"session,omitempty"`
	Path    string `json:"path"`
	Op      string `json:"op,omitempty"`
	Reason  string `json:"reason,omitempty"`
}
