package approval

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
)

type CLI struct {
	In  io.Reader
	Out io.Writer
}

func (c CLI) Ask(_ context.Context, req Request) (Response, error) {
	if c.In == nil {
		return Response{}, fmt.Errorf("approval input is nil")
	}
	if c.Out != nil {
		fmt.Fprintf(c.Out, "%s\nrisk: %s\napprove? [y/N] ", req.Question, req.Risk)
	}
	line, err := bufio.NewReader(c.In).ReadString('\n')
	if err != nil && len(line) == 0 {
		return Response{}, err
	}
	approved := strings.EqualFold(strings.TrimSpace(line), "y") || strings.EqualFold(strings.TrimSpace(line), "yes")
	return Response{Approved: approved}, nil
}
