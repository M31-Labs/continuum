package approval

import "context"

type Server struct {
	Default Response
}

func (s Server) Ask(context.Context, Request) (Response, error) {
	return s.Default, nil
}
