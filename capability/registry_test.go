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
