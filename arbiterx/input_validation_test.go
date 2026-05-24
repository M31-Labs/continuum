package arbiterx

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePolicyInputsForExamplePolicies(t *testing.T) {
	for _, path := range []string{
		filepath.Join("..", "examples", "agent-workdir", "policies", "main.arb"),
		filepath.Join("..", "examples", "airlock", "policies", "main.arb"),
	} {
		bundle, err := CompileFile(path)
		if err != nil {
			t.Fatalf("CompileFile(%s): %v", path, err)
		}
		report, err := ValidatePolicyInputs(bundle)
		if err != nil {
			t.Fatalf("ValidatePolicyInputs(%s): %v report=%+v", path, err, report)
		}
		if !report.OK || len(report.Fields) == 0 {
			t.Fatalf("report for %s = %+v", path, report)
		}
	}
}

func TestValidatePolicyInputsRejectsUnknownInputRoot(t *testing.T) {
	bundle := compilePolicyForInputValidation(t, `
input {
	kernel: {
		raw_pid: number
	}
}

outcome Allow {
	reason: string
}

rule UnknownRoot priority 1 {
	when {
		kernel.raw_pid > 0
	}
	then Allow {
		reason: "ok",
	}
}
`)
	report, err := ValidatePolicyInputs(bundle)
	if err == nil {
		t.Fatalf("ValidatePolicyInputs succeeded, report=%+v", report)
	}
	if report.OK || !strings.Contains(err.Error(), "input.kernel") {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func TestValidatePolicyInputsRejectsUnknownNestedField(t *testing.T) {
	bundle := compilePolicyForInputValidation(t, `
input {
	file: {
		path: string
		mode: string
	}
}

outcome Allow {
	reason: string
}

rule UnknownNested priority 1 {
	when {
		file.path == "/tmp/x"
	}
	then Allow {
		reason: "ok",
	}
}
`)
	report, err := ValidatePolicyInputs(bundle)
	if err == nil {
		t.Fatalf("ValidatePolicyInputs succeeded, report=%+v", report)
	}
	if report.OK || !strings.Contains(err.Error(), "input.file.mode") {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func TestValidatePolicyInputsRejectsTypeMismatch(t *testing.T) {
	bundle := compilePolicyForInputValidation(t, `
input {
	net: {
		port: string
	}
}

outcome Allow {
	reason: string
}

rule WrongType priority 1 {
	when {
		net.port == "443"
	}
	then Allow {
		reason: "ok",
	}
}
`)
	report, err := ValidatePolicyInputs(bundle)
	if err == nil {
		t.Fatalf("ValidatePolicyInputs succeeded, report=%+v", report)
	}
	if report.OK || !strings.Contains(err.Error(), "input.net.port") || !strings.Contains(err.Error(), "number") {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func TestValidatePolicyInputsRejectsUnsupportedFactSchema(t *testing.T) {
	bundle := compilePolicyForInputValidation(t, `
fact KernelRaw {
	pid: number
}

outcome Allow {
	reason: string
}

rule Always priority 1 {
	when {
		true
	}
	then Allow {
		reason: "ok",
	}
}
`)
	report, err := ValidatePolicyInputs(bundle)
	if err == nil {
		t.Fatalf("ValidatePolicyInputs succeeded, report=%+v", report)
	}
	if report.OK || !strings.Contains(err.Error(), "fact.KernelRaw") {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func compilePolicyForInputValidation(t *testing.T, source string) *Bundle {
	t.Helper()
	bundle, err := Compile([]byte(source))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return bundle
}
