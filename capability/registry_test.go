package capability

import "testing"

func TestRegistryRegisterListAndDuplicate(t *testing.T) {
	reg := NewRegistry()
	cap := Capability{Name: "kernel.file.open.observe", Kind: KindSource, Owner: "horizon", Output: "FileEvent", Danger: DangerObserve}
	if err := reg.Register(cap); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := reg.Register(cap); err == nil {
		t.Fatal("expected duplicate error")
	}
	got, ok := reg.Get(cap.Name)
	if !ok || got.Name != cap.Name {
		t.Fatalf("Get = %+v, %v", got, ok)
	}
	if len(reg.ByKind(KindSource)) != 1 {
		t.Fatalf("ByKind source length = %d", len(reg.ByKind(KindSource)))
	}
}

func TestValidateRejectsBroadShape(t *testing.T) {
	err := Validate(Capability{Name: "bad", Kind: Kind("root"), Danger: DangerPrivileged})
	if err == nil {
		t.Fatal("expected invalid kind error")
	}
}

func TestValidateRejectsKindShapeMismatches(t *testing.T) {
	cases := []Capability{
		{Name: "source.no-output", Kind: KindSource, Danger: DangerObserve},
		{Name: "sink.no-input", Kind: KindSink, Danger: DangerObserve},
		{Name: "worker.no-input", Kind: KindWorker, Danger: DangerObserve},
	}
	for _, cap := range cases {
		if err := Validate(cap); err == nil {
			t.Fatalf("Validate(%s) succeeded, expected shape error", cap.Name)
		}
	}
}

func TestValidateRejectsInvalidBackendDanger(t *testing.T) {
	err := Validate(Capability{Name: "approval.bad", Kind: KindSink, Owner: "continuum", Input: "AskHuman", Danger: DangerEnforcement, Backend: "cli"})
	if err == nil {
		t.Fatal("expected cli danger validation error")
	}
}

func TestValidateRequiresOwnerAndRequirementForDangerousCaps(t *testing.T) {
	err := Validate(Capability{Name: "process.kill", Kind: KindWorker, Input: "KillProcess", Danger: DangerDestructive, Backend: "observe"})
	if err == nil {
		t.Fatal("expected destructive owner/requirement validation error")
	}
	err = Validate(Capability{
		Name:    "process.kill",
		Kind:    KindWorker,
		Owner:   "continuum",
		Input:   "KillProcess",
		Danger:  DangerDestructive,
		Backend: "observe",
		Requires: []Requirement{{
			Name: "explicit-enable",
		}},
	})
	if err != nil {
		t.Fatalf("Validate destructive cap with requirement: %v", err)
	}
}
