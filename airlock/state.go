package airlock

import (
	"fmt"
	"time"

	"m31labs.dev/continuum/subject"
)

type State string

const (
	StateNormal     State = "normal"
	StateSuspicious State = "suspicious"
	StateContained  State = "contained"
	StateAirlocked  State = "airlocked"
	StateReleased   State = "released"
	StateRemediated State = "remediated"
	StateDestroyed  State = "destroyed"
)

type Session struct {
	ID        string          `json:"id"`
	Subject   subject.Subject `json:"subject"`
	State     State           `json:"state"`
	Reason    string          `json:"reason,omitempty"`
	StartedAt time.Time       `json:"started_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

func (s *Session) Transition(next State, reason string, now time.Time) error {
	if s == nil {
		return fmt.Errorf("nil airlock session")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !validTransition(s.State, next) {
		return fmt.Errorf("invalid airlock transition %s -> %s", s.State, next)
	}
	if s.StartedAt.IsZero() {
		s.StartedAt = now
	}
	s.State = next
	s.Reason = reason
	s.UpdatedAt = now
	return nil
}

func validTransition(from, to State) bool {
	if from == "" {
		return to == StateNormal || to == StateSuspicious || to == StateContained || to == StateAirlocked
	}
	if from == to {
		return knownState(from)
	}
	switch from {
	case StateNormal:
		return to == StateSuspicious || to == StateContained || to == StateAirlocked
	case StateSuspicious:
		return to == StateContained || to == StateAirlocked || to == StateReleased
	case StateContained:
		return to == StateAirlocked || to == StateReleased || to == StateRemediated || to == StateDestroyed
	case StateAirlocked:
		return to == StateReleased || to == StateRemediated || to == StateDestroyed
	default:
		return false
	}
}

func knownState(state State) bool {
	switch state {
	case StateNormal, StateSuspicious, StateContained, StateAirlocked, StateReleased, StateRemediated, StateDestroyed:
		return true
	default:
		return false
	}
}
