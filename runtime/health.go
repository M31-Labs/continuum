package runtime

type Health struct {
	OK              bool           `json:"ok"`
	Capabilities    int            `json:"capabilities"`
	SourceCount     int            `json:"source_count"`
	SinkCount       int            `json:"sink_count"`
	WorkerCount     int            `json:"worker_count"`
	PrivilegedCount int            `json:"privileged_count"`
	SourceRunning   int            `json:"source_running"`
	SourceFailed    int            `json:"source_failed"`
	SourceHealth    []SourceHealth `json:"source_health,omitempty"`
	Issues          []string       `json:"issues,omitempty"`
}

func (d *Daemon) Health() Health {
	if d == nil || d.Registry == nil {
		return Health{OK: false, Issues: []string{"daemon not initialized"}}
	}
	caps := d.Registry.List()
	health := Health{OK: true, Capabilities: len(caps)}
	sourceHealth := d.SourceHealth()
	health.SourceHealth = sourceHealth
	sourceHealthByName := map[string]SourceHealth{}
	for _, source := range sourceHealth {
		sourceHealthByName[source.Name] = source
		switch source.Status {
		case SourceStatusRunning:
			health.SourceRunning++
		case SourceStatusFailed:
			health.OK = false
			health.SourceFailed++
			health.Issues = append(health.Issues, sourceHealthIssue(source))
		}
	}
	for _, cap := range caps {
		switch cap.Kind {
		case "source":
			health.SourceCount++
			if _, ok := sourceHealthByName[cap.Name]; !ok {
				health.OK = false
				health.Issues = append(health.Issues, "source "+cap.Name+" has no lifecycle health")
			}
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
