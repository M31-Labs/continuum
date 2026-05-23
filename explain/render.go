package explain

import (
	"fmt"
	"io"
)

func Render(w io.Writer, exp Explanation) {
	fmt.Fprintf(w, "decision=%s outcome=%s reason=%q\n", exp.Decision, exp.Outcome.Name, exp.Reason)
	for _, step := range exp.Trace {
		fmt.Fprintf(w, "rule=%s result=%s message=%q\n", step.Rule, step.Result, step.Message)
	}
}
