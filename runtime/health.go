package runtime

type Health struct {
	OK              bool     `json:"ok"`
	Capabilities    int      `json:"capabilities"`
	SourceCount     int      `json:"source_count"`
	SinkCount       int      `json:"sink_count"`
	WorkerCount     int      `json:"worker_count"`
	PrivilegedCount int      `json:"privileged_count"`
	Issues          []string `json:"issues,omitempty"`
}

func (d *Daemon) Health() Health {
	if d == nil || d.Registry == nil {
		return Health{OK: false, Issues: []string{"daemon not initialized"}}
	}
	caps := d.Registry.List()
	health := Health{OK: true, Capabilities: len(caps)}
	for _, cap := range caps {
		switch cap.Kind {
		case "source":
			health.SourceCount++
		case "sink":
			health.SinkCount++
		case "worker":
			health.WorkerCount++
		}
		if cap.Danger == "privileged" {
			health.PrivilegedCount++
		}
	}
	return health
}
