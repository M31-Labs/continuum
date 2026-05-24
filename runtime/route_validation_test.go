package runtime

import (
	"path/filepath"
	"testing"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/subject"
)

func TestValidateOutcomeRoutesForExamplePolicies(t *testing.T) {
	registry := registryWithBuiltIns(t, "")
	for _, path := range []string{
		filepath.Join("..", "examples", "agent-workdir", "policies", "main.arb"),
		filepath.Join("..", "examples", "airlock", "policies", "main.arb"),
	} {
		bundle, err := arbiterx.CompileFile(path)
		if err != nil {
			t.Fatalf("CompileFile(%s): %v", path, err)
		}
		report, err := ValidateOutcomeRoutes(bundle, registry)
		if err != nil {
			t.Fatalf("ValidateOutcomeRoutes(%s): %v report=%+v", path, err, report)
		}
		if !report.OK || len(report.Routes) == 0 {
			t.Fatalf("report for %s = %+v", path, report)
		}
	}
}

func TestValidateOutcomeRoutesRejectsMissingCapability(t *testing.T) {
	bundle, err := arbiterx.CompileFile(filepath.Join("..", "examples", "agent-workdir", "policies", "main.arb"))
	if err != nil {
		t.Fatalf("CompileFile: %v", err)
	}
	report, err := ValidateOutcomeRoutes(bundle, registryWithBuiltIns(t, "approval.cli.ask"))
	if err == nil {
		t.Fatalf("ValidateOutcomeRoutes succeeded, report=%+v", report)
	}
	if report.OK || len(report.Missing) != 1 || report.Missing[0].Outcome != arbiterx.OutcomeAskHuman {
		t.Fatalf("report = %+v err=%v", report, err)
	}
}

func TestValidateOutcomeRoutesRejectsUnsupportedOutcome(t *testing.T) {
	bundle, err := arbiterx.Compile([]byte(`
input {
	file: {
		path: string
	}
}

outcome Quarantine {
	reason: string
}

rule UnknownOutcome priority 1 {
	when {
		file.path == "/tmp/x"
	}
	then Quarantine {
		reason: "unsupported",
	}
}
`))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	report, err := ValidateOutcomeRoutes(bundle, registryWithBuiltIns(t, ""))
	if err == nil {
		t.Fatalf("ValidateOutcomeRoutes succeeded, report=%+v", report)
	}
	if report.OK || len(report.Missing) != 1 || report.Missing[0].Outcome != "Quarantine" {
		t.Fatalf("report = %+v err=%v", report, err)
	}
}

func TestBuiltInOutcomesHaveRegisteredRoutes(t *testing.T) {
	registry := registryWithBuiltIns(t, "")
	for _, outcome := range []string{
		arbiterx.OutcomeAllow,
		arbiterx.OutcomeDeny,
		arbiterx.OutcomeAskHuman,
		arbiterx.OutcomeAudit,
		arbiterx.OutcomeGrantNetwork,
		arbiterx.OutcomeKillProcess,
		arbiterx.OutcomeEnterAirlock,
	} {
		found := false
		for _, candidate := range RouteCandidatesForOutcomeName(outcome) {
			cap, ok := registry.Get(candidate)
			if ok && capabilityAcceptsOutcome(cap, outcome) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("outcome %s has no registered route among %+v", outcome, RouteCandidatesForOutcomeName(outcome))
		}
	}
}

func TestRouteCapabilityFallsBackToRegisteredCandidate(t *testing.T) {
	registry := registryWithBuiltIns(t, "kernel.file.open.deny")
	engine := NewEngine(nil, nil)
	engine.Registry = registry
	subj := subject.NewAgent("claude", "s1", "/repo", "", 123)
	got := engine.RouteCapability(event.NewFileAccess(subj, "/etc/passwd", "read"), arbiterx.NewOutcome(arbiterx.OutcomeDeny, "deny", nil))
	if got != "continuum.outcome.deny" {
		t.Fatalf("RouteCapability = %q", got)
	}
}

func registryWithBuiltIns(t *testing.T, exclude string) *capability.Registry {
	t.Helper()
	registry := capability.NewRegistry()
	for _, cap := range capability.BuiltIns() {
		if cap.Name == exclude {
			continue
		}
		if err := registry.Register(cap); err != nil {
			t.Fatalf("Register(%s): %v", cap.Name, err)
		}
	}
	return registry
}
