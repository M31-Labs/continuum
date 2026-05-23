package approval

import "context"

type Request struct {
	Session  string `json:"session,omitempty"`
	Question string `json:"question"`
	Risk     string `json:"risk,omitempty"`
}

type Response struct {
	Approved bool   `json:"approved"`
	Reason   string `json:"reason,omitempty"`
}

type Asker interface {
	Ask(context.Context, Request) (Response, error)
}
