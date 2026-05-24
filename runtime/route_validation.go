package runtime

import (
	"fmt"
	"strings"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/capability"
)

type OutcomeRouteReport struct {
	OK      bool                  `json:"ok"`
	Routes  []OutcomeRoute        `json:"routes,omitempty"`
	Missing []MissingOutcomeRoute `json:"missing,omitempty"`
}

type OutcomeRoute struct {
	Outcome    string          `json:"outcome"`
	Capability string          `json:"capability"`
	Input      string          `json:"input"`
	Kind       capability.Kind `json:"kind"`
}

type MissingOutcomeRoute struct {
	Outcome    string   `json:"outcome"`
	Candidates []string `json:"candidates,omitempty"`
	Reason     string   `json:"reason"`
}

func ValidateOutcomeRoutes(bundle *arbiterx.Bundle, registry *capability.Registry) (OutcomeRouteReport, error) {
	report := OutcomeRouteReport{OK: true}
	if bundle == nil {
		return report, fmt.Errorf("policy bundle is required")
	}
	if registry == nil {
		return report, fmt.Errorf("capability registry is required")
	}
	for _, outcome := range arbiterx.OutcomeNames(bundle) {
		candidates := RouteCandidatesForOutcomeName(outcome)
		if len(candidates) == 0 {
			report.addMissing(outcome, nil, "unsupported outcome")
			continue
		}
		var matched *OutcomeRoute
		for _, candidate := range candidates {
			cap, ok := registry.Get(candidate)
			if !ok || !capabilityAcceptsOutcome(cap, outcome) {
				continue
			}
			matched = &OutcomeRoute{
				Outcome:    outcome,
				Capability: cap.Name,
				Input:      cap.Input,
				Kind:       cap.Kind,
			}
			break
		}
		if matched == nil {
			report.addMissing(outcome, candidates, "no registered capability accepts outcome")
			continue
		}
		report.Routes = append(report.Routes, *matched)
	}
	if len(report.Missing) > 0 {
		return report, report.Err()
	}
	return report, nil
}

func (r OutcomeRouteReport) Err() error {
	if r.OK {
		return nil
	}
	var parts []string
	for _, missing := range r.Missing {
		if len(missing.Candidates) == 0 {
			parts = append(parts, fmt.Sprintf("%s: %s", missing.Outcome, missing.Reason))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s: %s among %s", missing.Outcome, missing.Reason, strings.Join(missing.Candidates, ",")))
	}
	return fmt.Errorf("policy outcome route validation failed: %s", strings.Join(parts, "; "))
}

func (r *OutcomeRouteReport) addMissing(outcome string, candidates []string, reason string) {
	r.OK = false
	r.Missing = append(r.Missing, MissingOutcomeRoute{
		Outcome:    outcome,
		Candidates: append([]string(nil), candidates...),
		Reason:     reason,
	})
}

func capabilityAcceptsOutcome(cap capability.Capability, outcome string) bool {
	switch cap.Input {
	case outcome, "Outcome", "Decision":
		return true
	default:
		return false
	}
}
