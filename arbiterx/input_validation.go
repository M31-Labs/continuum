package arbiterx

import (
	"fmt"
	"slices"
	"strings"

	"github.com/odvcencio/arbiter/ir"
)

type PolicyInputReport struct {
	OK      bool                          `json:"ok"`
	Fields  []PolicyInputField            `json:"fields,omitempty"`
	Missing []UnsupportedPolicyInputField `json:"missing,omitempty"`
}

type PolicyInputField struct {
	Path       string `json:"path"`
	Type       string `json:"type"`
	SourceFact string `json:"source_fact"`
}

type UnsupportedPolicyInputField struct {
	Path    string   `json:"path"`
	Type    string   `json:"type,omitempty"`
	Reason  string   `json:"reason"`
	Allowed []string `json:"allowed,omitempty"`
}

type continuumFieldSpec struct {
	Type       string
	SourceFact string
	Children   map[string]continuumFieldSpec
}

func ValidatePolicyInputs(bundle *Bundle) (PolicyInputReport, error) {
	report := PolicyInputReport{OK: true}
	if bundle == nil || bundle.Program == nil || bundle.Program.IR == nil {
		return report, fmt.Errorf("policy bundle is required")
	}
	program := bundle.Program.IR
	if program.Input != nil {
		validatePolicyFields(&report, "input", program.Input.Fields, continuumInputEnvelope())
	}
	for _, schema := range program.FactSchemas {
		spec, ok := continuumFactSchemas()[schema.Name]
		if !ok {
			report.addMissing("fact."+schema.Name, "", "unsupported Continuum fact schema", sortedSpecKeys(continuumFactSchemas()))
			continue
		}
		validatePolicyFields(&report, "fact."+schema.Name, schema.Fields, spec.Children)
	}
	if len(report.Missing) > 0 {
		return report, report.Err()
	}
	return report, nil
}

func (r PolicyInputReport) Err() error {
	if r.OK {
		return nil
	}
	parts := make([]string, 0, len(r.Missing))
	for _, missing := range r.Missing {
		if len(missing.Allowed) == 0 {
			parts = append(parts, fmt.Sprintf("%s: %s", missing.Path, missing.Reason))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s: %s; allowed=%s", missing.Path, missing.Reason, strings.Join(missing.Allowed, ",")))
	}
	return fmt.Errorf("policy input validation failed: %s", strings.Join(parts, "; "))
}

func (r *PolicyInputReport) addField(path string, field ir.SchemaField, spec continuumFieldSpec) {
	r.Fields = append(r.Fields, PolicyInputField{
		Path:       path,
		Type:       fieldTypeName(field.Type),
		SourceFact: spec.SourceFact,
	})
}

func (r *PolicyInputReport) addMissing(path, typ, reason string, allowed []string) {
	r.OK = false
	r.Missing = append(r.Missing, UnsupportedPolicyInputField{
		Path:    path,
		Type:    typ,
		Reason:  reason,
		Allowed: append([]string(nil), allowed...),
	})
}

func validatePolicyFields(report *PolicyInputReport, prefix string, fields []ir.SchemaField, specs map[string]continuumFieldSpec) {
	for _, field := range fields {
		path := prefix + "." + field.Name
		spec, ok := specs[field.Name]
		if !ok {
			report.addMissing(path, fieldTypeName(field.Type), "not emitted by normalized Continuum facts", sortedSpecKeys(specs))
			continue
		}
		validatePolicyField(report, path, field, spec)
	}
}

func validatePolicyField(report *PolicyInputReport, path string, field ir.SchemaField, spec continuumFieldSpec) {
	if !fieldTypeCompatible(field, spec) {
		report.addMissing(path, fieldTypeName(field.Type), fmt.Sprintf("type mismatch, Continuum emits %s", spec.Type), nil)
		return
	}
	if spec.Type == "object" {
		validatePolicyFields(report, path, field.Children, spec.Children)
		return
	}
	report.addField(path, field, spec)
}

func fieldTypeCompatible(field ir.SchemaField, spec continuumFieldSpec) bool {
	if spec.Type == "object" {
		return field.Type.Base == "object" || len(field.Children) > 0
	}
	if len(field.Children) > 0 {
		return false
	}
	return field.Type.Base == spec.Type
}

func fieldTypeName(typ ir.FieldType) string {
	if typ.Base == "list" && typ.Element != nil {
		return "list<" + fieldTypeName(*typ.Element) + ">"
	}
	if typ.Dimension != "" {
		return typ.Base + "<" + typ.Dimension + ">"
	}
	return typ.Base
}

func sortedSpecKeys(specs map[string]continuumFieldSpec) []string {
	if len(specs) == 0 {
		return nil
	}
	out := make([]string, 0, len(specs))
	for key := range specs {
		out = append(out, key)
	}
	slices.Sort(out)
	return out
}

func continuumInputEnvelope() map[string]continuumFieldSpec {
	return map[string]continuumFieldSpec{
		"agent":   objectSpec(FactAgentContext, agentFields()),
		"file":    objectSpec(FactFileAccess, fileFields()),
		"net":     objectSpec(FactNetworkConnect, networkFields()),
		"process": objectSpec(FactProcessExec, processFields()),
		"behavior": objectSpec(FactBehavior, map[string]continuumFieldSpec{
			"subject":                stringSpec(FactBehavior),
			"exec_count":             numberSpec(FactBehavior),
			"unique_network_targets": numberSpec(FactBehavior),
			"touched_secret_paths":   numberSpec(FactBehavior),
			"rewritten_files":        numberSpec(FactBehavior),
			"entropy_increase_score": numberSpec(FactBehavior),
		}),
	}
}

func continuumFactSchemas() map[string]continuumFieldSpec {
	return map[string]continuumFieldSpec{
		FactAgentContext:   factSpec(FactAgentContext, agentFields()),
		FactFileAccess:     factSpec(FactFileAccess, fileFields()),
		FactNetworkConnect: factSpec(FactNetworkConnect, networkFields()),
		FactProcessExec:    factSpec(FactProcessExec, processFields()),
		FactBehavior: factSpec(FactBehavior, map[string]continuumFieldSpec{
			"subject":                stringSpec(FactBehavior),
			"exec_count":             numberSpec(FactBehavior),
			"unique_network_targets": numberSpec(FactBehavior),
			"touched_secret_paths":   numberSpec(FactBehavior),
			"rewritten_files":        numberSpec(FactBehavior),
			"entropy_increase_score": numberSpec(FactBehavior),
		}),
	}
}

func agentFields() map[string]continuumFieldSpec {
	return map[string]continuumFieldSpec{
		"session":   stringSpec(FactAgentContext),
		"name":      stringSpec(FactAgentContext),
		"repo_root": stringSpec(FactAgentContext),
		"task":      stringSpec(FactAgentContext),
	}
}

func fileFields() map[string]continuumFieldSpec {
	return map[string]continuumFieldSpec{
		"pid":           numberSpec(FactFileAccess),
		"path":          stringSpec(FactFileAccess),
		"op":            stringSpec(FactFileAccess),
		"agent_session": stringSpec(FactFileAccess),
	}
}

func networkFields() map[string]continuumFieldSpec {
	return map[string]continuumFieldSpec{
		"pid":           numberSpec(FactNetworkConnect),
		"host":          stringSpec(FactNetworkConnect),
		"ip":            stringSpec(FactNetworkConnect),
		"port":          numberSpec(FactNetworkConnect),
		"agent_session": stringSpec(FactNetworkConnect),
	}
}

func processFields() map[string]continuumFieldSpec {
	return map[string]continuumFieldSpec{
		"pid":           numberSpec(FactProcessExec),
		"comm":          stringSpec(FactProcessExec),
		"argv_text":     stringSpec(FactProcessExec),
		"cwd":           stringSpec(FactProcessExec),
		"agent_session": stringSpec(FactProcessExec),
	}
}

func objectSpec(source string, children map[string]continuumFieldSpec) continuumFieldSpec {
	return continuumFieldSpec{Type: "object", SourceFact: source, Children: children}
}

func factSpec(source string, children map[string]continuumFieldSpec) continuumFieldSpec {
	withKey := make(map[string]continuumFieldSpec, len(children)+1)
	for key, value := range children {
		withKey[key] = value
	}
	withKey["key"] = stringSpec(source)
	return objectSpec(source, withKey)
}

func stringSpec(source string) continuumFieldSpec {
	return continuumFieldSpec{Type: "string", SourceFact: source}
}

func numberSpec(source string) continuumFieldSpec {
	return continuumFieldSpec{Type: "number", SourceFact: source}
}
