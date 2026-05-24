package approval

import (
	"context"

	"m31labs.dev/continuum/subject"
)

type Request struct {
	Session   string            `json:"session,omitempty"`
	Requester *subject.Identity `json:"requester,omitempty"`
	Question  string            `json:"question"`
	Risk      string            `json:"risk,omitempty"`
}

type Response struct {
	Approved bool   `json:"approved"`
	Reason   string `json:"reason,omitempty"`
}

type Asker interface {
	Ask(context.Context, Request) (Response, error)
}
