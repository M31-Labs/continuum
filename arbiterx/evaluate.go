package arbiterx

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	arbiter "github.com/odvcencio/arbiter"
	"github.com/odvcencio/arbiter/expert"
	"github.com/odvcencio/arbiter/govern"
	"github.com/odvcencio/arbiter/vm"
)

type Decision struct {
	BundleID  string    `json:"bundle_id,omitempty"`
	Outcomes  []Outcome `json:"outcomes,omitempty"`
	Selected  *Outcome  `json:"selected,omitempty"`
	Arbitrace []Step    `json:"arbitrace,omitempty"`
}

func Evaluate(ctx context.Context, bundle *Bundle, facts []Fact) (Decision, error) {
	decision := Decision{}
	if bundle != nil {
		decision.BundleID = bundle.ID
	}
	input := collectInput(facts)
	if input.behavior != nil || (bundle != nil && bundle.Kind == "airlock") {
		return evaluateAirlock(ctx, decision, bundle, input)
	}
	return evaluateAgentGuard(ctx, decision, bundle, input)
}

type normalizedInput struct {
	agent    map[string]any
	file     map[string]any
	net      map[string]any
	process  map[string]any
	grants   []map[string]any
	behavior map[string]any
}

func collectInput(facts []Fact) normalizedInput {
	var in normalizedInput
	for _, fact := range facts {
		switch fact.Type {
		case FactAgentContext:
			in.agent = merge(in.agent, fact.Fields)
		case FactFileAccess:
			in.file = merge(in.file, fact.Fields)
		case FactNetworkConnect:
			in.net = merge(in.net, fact.Fields)
		case FactProcessExec:
			in.process = merge(in.process, fact.Fields)
		case FactCapabilityGrant:
			in.grants = append(in.grants, merge(nil, fact.Fields))
		case FactBehavior:
			in.behavior = merge(in.behavior, fact.Fields)
		}
		if !fact.Subject.Empty() {
			if in.agent == nil {
				in.agent = map[string]any{}
			}
			if fact.Subject.Session != "" {
				in.agent["session"] = fact.Subject.Session
			}
			if fact.Subject.AgentName != "" {
				in.agent["name"] = fact.Subject.AgentName
			}
			if fact.Subject.RepoRoot != "" {
				in.agent["repo_root"] = fact.Subject.RepoRoot
			}
			if fact.Subject.Task != "" {
				in.agent["task"] = fact.Subject.Task
			}
		}
	}
	return in
}

func merge(dst map[string]any, src map[string]any) map[string]any {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]any, len(src))
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func evaluateAgentGuard(_ context.Context, decision Decision, bundle *Bundle, in normalizedInput) (Decision, error) {
	policyOutcome, trace, err := evaluateRules(bundle, in)
	if err != nil {
		return decision, err
	}
	decision.Arbitrace = append(decision.Arbitrace, trace...)
	if policyOutcome != nil && policyOutcome.Name == OutcomeDeny {
		return selectOutcome(decision, *policyOutcome), nil
	}
	if grantID := matchingNetworkGrant(in); grantID != "" {
		return selectOutcome(decision, NewOutcome(OutcomeAllow, "AllowTemporaryGrant", map[string]any{
			"reason": "temporary grant permits network connection",
			"grant":  grantID,
		})), nil
	}
	if grantID := matchingFileGrant(in); grantID != "" {
		return selectOutcome(decision, NewOutcome(OutcomeAllow, "AllowTemporaryGrant", map[string]any{
			"reason": "temporary grant permits file access",
			"grant":  grantID,
		})), nil
	}
	if grantID := matchingProcessGrant(in); grantID != "" {
		return selectOutcome(decision, NewOutcome(OutcomeAllow, "AllowTemporaryGrant", map[string]any{
			"reason": "temporary grant permits process execution",
			"grant":  grantID,
		})), nil
	}
	if policyOutcome != nil {
		return selectOutcome(decision, *policyOutcome), nil
	}
	return selectOutcome(decision, NewOutcome(OutcomeAudit, "NoMatchingRule", map[string]any{
		"severity": "info",
		"reason":   "no matching policy rule",
	})), nil
}

func evaluateRules(bundle *Bundle, in normalizedInput) (*Outcome, []Step, error) {
	if bundle == nil || bundle.Program == nil {
		return nil, nil, nil
	}
	envelope := arbiterEnvelope(in)
	dc := arbiter.DataFromMap(envelope, bundle.Program)
	matches, trace, err := arbiter.EvalGovernedWithOverrides(bundle.Program, dc, bundle.Program.Segments, envelope, bundle.ID, nil)
	if err != nil {
		return nil, stepsFromArbitrace(trace), err
	}
	if len(matches) == 0 {
		return nil, stepsFromArbitrace(trace), nil
	}
	sort.SliceStable(matches, func(i, j int) bool {
		return matches[i].Priority < matches[j].Priority
	})
	outcome := outcomeFromMatch(matches[0])
	return &outcome, stepsFromArbitrace(trace), nil
}

func arbiterEnvelope(in normalizedInput) map[string]any {
	envelope := map[string]any{}
	if in.agent != nil {
		envelope["agent"] = in.agent
	}
	if in.file != nil {
		envelope["file"] = in.file
	}
	if in.net != nil {
		envelope["net"] = in.net
	}
	if in.process != nil {
		envelope["process"] = in.process
	}
	if in.behavior != nil {
		envelope["behavior"] = in.behavior
	}
	return envelope
}

func outcomeFromMatch(match vm.MatchedRule) Outcome {
	return NewOutcome(match.Action, match.Name, match.Params)
}

func matchingNetworkGrant(in normalizedInput) string {
	if len(in.grants) == 0 || in.net == nil {
		return ""
	}
	session := stringField(in.agent, "session")
	host := stringField(in.net, "host")
	port := numberField(in.net, "port")
	for _, grant := range in.grants {
		if stringField(grant, "session") != session {
			continue
		}
		capability := stringField(grant, "capability")
		if capability != "network.connect" && capability != "kernel.network.connect.grant" {
			continue
		}
		if stringField(grant, "host") != host {
			continue
		}
		grantPort := numberField(grant, "port")
		if grantPort != 0 && grantPort != port {
			continue
		}
		id := stringField(grant, "id")
		if id == "" {
			id = "grant"
		}
		return id
	}
	return ""
}

func matchingFileGrant(in normalizedInput) string {
	if len(in.grants) == 0 || in.file == nil {
		return ""
	}
	session := stringField(in.agent, "session")
	path := stringField(in.file, "path")
	op := stringField(in.file, "op")
	for _, grant := range in.grants {
		if stringField(grant, "session") != session {
			continue
		}
		capability := stringField(grant, "capability")
		if capability != "file.access" && capability != "file."+op {
			continue
		}
		if scopeOp := stringField(grant, "op"); scopeOp != "" && scopeOp != op {
			continue
		}
		if grantPath := stringField(grant, "path"); grantPath != "" && samePath(grantPath, path) {
			return grantID(grant)
		}
		if prefix := stringField(grant, "path_prefix"); prefix != "" && pathInside(prefix, path) {
			return grantID(grant)
		}
	}
	return ""
}

func matchingProcessGrant(in normalizedInput) string {
	if len(in.grants) == 0 || in.process == nil {
		return ""
	}
	session := stringField(in.agent, "session")
	comm := stringField(in.process, "comm")
	argvText := stringField(in.process, "argv_text")
	for _, grant := range in.grants {
		if stringField(grant, "session") != session || stringField(grant, "capability") != "process.exec" {
			continue
		}
		scopeComm := stringField(grant, "comm")
		scopeArgv := stringField(grant, "argv_text")
		scopePrefix := stringField(grant, "argv_prefix")
		if scopeComm != "" && scopeComm != comm && filepath.Base(scopeComm) != filepath.Base(comm) {
			continue
		}
		if scopeArgv != "" && scopeArgv != argvText {
			continue
		}
		if scopePrefix != "" && !strings.HasPrefix(argvText, scopePrefix) {
			continue
		}
		if scopeComm != "" || scopeArgv != "" || scopePrefix != "" {
			return grantID(grant)
		}
	}
	return ""
}

func grantID(grant map[string]any) string {
	id := stringField(grant, "id")
	if id == "" {
		id = "grant"
	}
	return id
}

func evaluateAirlock(ctx context.Context, decision Decision, bundle *Bundle, in normalizedInput) (Decision, error) {
	if bundle != nil && bundle.Expert != nil {
		result, err := expert.NewSession(bundle.Expert, arbiterEnvelope(in), nil, expert.Options{BundleID: decision.BundleID}).Run(ctx)
		if err != nil {
			return decision, err
		}
		decision.Arbitrace = append(decision.Arbitrace, stepsFromActivations(result.Activations)...)
		if len(result.Outcomes) > 0 {
			outcome := outcomeFromExpert(result.Outcomes[0])
			return selectOutcome(decision, outcome), nil
		}
	}
	return selectOutcome(decision, NewOutcome(OutcomeAudit, "AirlockNoMatch", map[string]any{
		"severity": "info",
		"reason":   "behavior did not cross airlock thresholds",
	})), nil
}

func outcomeFromExpert(outcome expert.Outcome) Outcome {
	return NewOutcome(outcome.Name, outcome.Rule, outcome.Params)
}

func stepsFromActivations(activations []expert.Activation) []Step {
	var out []Step
	for _, activation := range activations {
		out = append(out, stepsFromArbitrace(&govern.Arbitrace{Steps: activation.Arbitrace})...)
		if len(activation.Arbitrace) == 0 {
			result := "blocked"
			if activation.Changed {
				result = "matched"
			}
			out = append(out, Step{
				Rule:    activation.Rule,
				Result:  result,
				Message: activation.Detail,
			})
		}
	}
	return out
}

func stepsFromArbitrace(trace *govern.Arbitrace) []Step {
	if trace == nil || len(trace.Steps) == 0 {
		return nil
	}
	out := make([]Step, 0, len(trace.Steps))
	for _, step := range trace.Steps {
		result := "blocked"
		if step.Result {
			result = "matched"
		}
		rule := step.Subject
		if rule == "" {
			rule = step.Check
		}
		out = append(out, Step{
			Rule:    rule,
			Result:  result,
			Message: step.Detail,
		})
	}
	return out
}

func selectOutcome(decision Decision, outcome Outcome) Decision {
	decision.Outcomes = append(decision.Outcomes, outcome)
	decision.Selected = &decision.Outcomes[len(decision.Outcomes)-1]
	decision.Arbitrace = append(decision.Arbitrace, Step{
		Rule:    outcome.Rule,
		Result:  "matched",
		Message: outcome.Reason(),
	})
	return decision
}

func pathInside(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	if root == "." || root == "" {
		return false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(filepath.ToSlash(rel), "../"))
}

func samePath(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}

func stringField(fields map[string]any, key string) string {
	if fields == nil {
		return ""
	}
	switch v := fields[key].(type) {
	case string:
		return v
	default:
		return ""
	}
}

func numberField(fields map[string]any, key string) float64 {
	if fields == nil {
		return 0
	}
	switch v := fields[key].(type) {
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case float64:
		return v
	case float32:
		return float64(v)
	case jsonNumber:
		n, _ := v.Float64()
		return n
	default:
		return 0
	}
}

type jsonNumber interface {
	Float64() (float64, error)
}
