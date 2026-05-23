package enforcement

type CgroupAttach struct {
	Session string `json:"session,omitempty"`
	PID     int    `json:"pid"`
	Cgroup  string `json:"cgroup"`
	Reason  string `json:"reason,omitempty"`
}

type CgroupFreeze struct {
	Session string `json:"session,omitempty"`
	Cgroup  string `json:"cgroup"`
	Reason  string `json:"reason,omitempty"`
}

type CgroupThaw struct {
	Session string `json:"session,omitempty"`
	Cgroup  string `json:"cgroup"`
	Reason  string `json:"reason,omitempty"`
}

type NamespaceIsolation struct {
	Session   string   `json:"session,omitempty"`
	PID       int      `json:"pid,omitempty"`
	Cgroup    string   `json:"cgroup,omitempty"`
	AllowCIDR []string `json:"allow_cidr,omitempty"`
	AllowHost []string `json:"allow_host,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

type NamespaceRelease struct {
	Session string `json:"session,omitempty"`
	PID     int    `json:"pid,omitempty"`
	Cgroup  string `json:"cgroup,omitempty"`
	Reason  string `json:"reason,omitempty"`
}
