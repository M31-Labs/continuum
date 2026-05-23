package explain

import (
	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/audit"
)

type Explanation struct {
	EventID  string           `json:"event_id"`
	Decision string           `json:"decision"`
	Outcome  arbiterx.Outcome `json:"outcome"`
	Reason   string           `json:"reason,omitempty"`
	Trace    []arbiterx.Step  `json:"trace,omitempty"`
}

func FromAudit(evt audit.Event) Explanation {
	return Explanation{
		EventID:  evt.ID,
		Decision: evt.Decision,
		Outcome:  evt.Outcome,
		Reason:   evt.Reason,
		Trace:    evt.Arbitraces,
	}
}
