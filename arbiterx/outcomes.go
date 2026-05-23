package arbiterx

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
