package enforcement

type ProcessKill struct {
	PID    int    `json:"pid"`
	Reason string `json:"reason,omitempty"`
}
