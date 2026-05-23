package capability

import (
	"context"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/subject"
)

type Worker interface {
	Name() string
	Execute(context.Context, Invocation) (WorkerResult, error)
}

type Invocation struct {
	Subject subject.Subject  `json:"subject"`
	Outcome arbiterx.Outcome `json:"outcome"`
	Grant   *Grant           `json:"grant,omitempty"`
}

type WorkerResult struct {
	Facts    []arbiterx.Fact    `json:"facts,omitempty"`
	Outcomes []arbiterx.Outcome `json:"outcomes,omitempty"`
}
