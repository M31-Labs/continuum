package airlock

import "time"

type Observation struct {
	Time    time.Time      `json:"time"`
	Session string         `json:"session"`
	Kind    string         `json:"kind"`
	Fields  map[string]any `json:"fields,omitempty"`
}
