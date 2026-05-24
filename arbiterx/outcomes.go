package arbiterx

import (
	"slices"

	"github.com/odvcencio/arbiter/ir"
)

const (
	OutcomeAllow        = "Allow"
	OutcomeDeny         = "Deny"
	OutcomeAskHuman     = "AskHuman"
	OutcomeAudit        = "Audit"
	OutcomeGrantNetwork = "GrantNetwork"
	OutcomeKillProcess  = "KillProcess"
	OutcomeEnterAirlock = "EnterAirlock"
)

type Outcome struct {
	Name   string         `json:"name"`
	Rule   string         `json:"rule,omitempty"`
	Fields map[string]any `json:"fields,omitempty"`
}

func NewOutcome(name, rule string, fields map[string]any) Outcome {
	return Outcome{Name: name, Rule: rule, Fields: cloneFields(fields)}
}

func (o Outcome) Reason() string {
	if o.Fields == nil {
		return ""
	}
	reason, _ := o.Fields["reason"].(string)
	return reason
}

func (o Outcome) Decision() string {
	switch o.Name {
	case OutcomeAllow:
		return "allow"
	case OutcomeDeny:
		return "deny"
	case OutcomeAskHuman:
		return "ask"
	case OutcomeEnterAirlock:
		return "enter_airlock"
	case OutcomeKillProcess:
		return "kill"
	case OutcomeGrantNetwork:
		return "grant"
	default:
		return "audit"
	}
}

func OutcomeNames(bundle *Bundle) []string {
	if bundle == nil || bundle.Program == nil || bundle.Program.IR == nil {
		return nil
	}
	seen := map[string]bool{}
	add := func(name string) {
		if name != "" {
			seen[name] = true
		}
	}
	program := bundle.Program.IR
	for _, schema := range program.OutcomeSchemas {
		add(schema.Name)
	}
	for _, rule := range program.Rules {
		add(rule.Action.Name)
		if rule.Fallback != nil {
			add(rule.Fallback.Name)
		}
	}
	for _, rule := range program.Expert {
		if rule.ActionKind == ir.ExpertEmit {
			add(rule.Target)
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}
