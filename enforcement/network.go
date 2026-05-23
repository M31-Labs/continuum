package enforcement

type NetworkGrant struct {
	Session string `json:"session,omitempty"`
	Host    string `json:"host,omitempty"`
	IP      string `json:"ip,omitempty"`
	Port    int    `json:"port,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

type NetworkDeny struct {
	Session string `json:"session,omitempty"`
	Host    string `json:"host,omitempty"`
	IP      string `json:"ip,omitempty"`
	Port    int    `json:"port,omitempty"`
	Reason  string `json:"reason,omitempty"`
}
