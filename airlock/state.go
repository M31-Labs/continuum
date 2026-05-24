package airlock

import (
	"fmt"
	"strings"
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
	Notes     []Note          `json:"notes,omitempty"`
	StartedAt time.Time       `json:"started_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type Note struct {
	Time     time.Time `json:"time"`
	Operator string    `json:"operator,omitempty"`
	Text     string    `json:"text"`
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

func (s *Session) AddNote(operator, text string, now time.Time) (Note, error) {
	if s == nil {
		return Note{}, fmt.Errorf("nil airlock session")
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return Note{}, fmt.Errorf("airlock note text is required")
	}
	operator = strings.TrimSpace(operator)
	if now.IsZero() {
		now = time.Now().UTC()
	}
	note := Note{Time: now, Operator: operator, Text: text}
	s.Notes = append(s.Notes, note)
	if s.StartedAt.IsZero() {
		s.StartedAt = now
	}
	s.UpdatedAt = now
	return note, nil
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
