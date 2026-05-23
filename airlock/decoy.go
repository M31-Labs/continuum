package airlock

type Decoy struct {
	Capability string         `json:"capability"`
	Fields     map[string]any `json:"fields,omitempty"`
}
