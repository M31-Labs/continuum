package event

import (
	"time"

	"m31labs.dev/continuum/subject"
)

type Event struct {
	ID      string          `json:"id,omitempty"`
	Time    time.Time       `json:"time,omitempty"`
	Source  string          `json:"source,omitempty"`
	Subject subject.Subject `json:"subject,omitempty"`
	Kind    string          `json:"kind,omitempty"`
	Fields  map[string]any  `json:"fields,omitempty"`
	Raw     map[string]any  `json:"raw,omitempty"`
}
