package enforcement

import "testing"

func TestObserveAndNoopExposeContainmentInterfaces(t *testing.T) {
	var _ CgroupBackend = ObserveBackend{}
	var _ NetworkNamespaceBackend = ObserveBackend{}
	var _ CgroupBackend = NoopBackend{}
	var _ NetworkNamespaceBackend = NoopBackend{}
}
