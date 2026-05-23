package arbiterx

import "m31labs.dev/continuum/subject"

const (
	FactAgentContext    = "AgentContext"
	FactProcessExec     = "ProcessExec"
	FactFileAccess      = "FileAccess"
	FactNetworkConnect  = "NetworkConnect"
	FactCapabilityGrant = "CapabilityGrant"
	FactSourceHealth    = "SourceHealth"
	FactAirlockState    = "AirlockState"
	FactBehavior        = "Behavior"
)

type Fact struct {
	Type    string          `json:"type"`
	Key     string          `json:"key,omitempty"`
	Subject subject.Subject `json:"subject,omitempty"`
	Fields  map[string]any  `json:"fields,omitempty"`
}

func NewFact(typ string, subj subject.Subject, fields map[string]any) Fact {
	return Fact{Type: typ, Subject: subj, Fields: cloneFields(fields)}
}

func cloneFields(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
