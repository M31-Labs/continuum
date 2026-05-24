package horizon

import (
	"path/filepath"
	"testing"
)

func TestInspectHZNSourceRequiresHorizonExport(t *testing.T) {
	inspection, err := InspectPath(filepath.Join("..", "testdata", "horizon-export", "input.hzn"))
	if err != nil {
		t.Fatalf("InspectPath: %v", err)
	}
	if inspection.Kind != ArtifactHZNSource || !inspection.NeedsExport {
		t.Fatalf("inspection = %+v", inspection)
	}
	if len(inspection.Capabilities) != 0 {
		t.Fatalf(".hzn inspection should not register caps: %+v", inspection.Capabilities)
	}
	if len(inspection.Artifacts) != 1 || inspection.Artifacts[0].SHA256 == "" {
		t.Fatalf("artifacts = %+v", inspection.Artifacts)
	}
}

func TestInspectExportedPackageRegistersDeclarationsOnly(t *testing.T) {
	inspection, err := InspectPath(filepath.Join("..", "testdata", "horizon-export"))
	if err != nil {
		t.Fatalf("InspectPath: %v", err)
	}
	if inspection.Kind != ArtifactExportedPackage {
		t.Fatalf("kind = %s", inspection.Kind)
	}
	if len(inspection.Capabilities) != 1 {
		t.Fatalf("capabilities = %+v", inspection.Capabilities)
	}
	cap := inspection.Capabilities[0]
	if cap.Name != "kernel.process.exec.observe" || cap.Owner != "horizon" || cap.Output != "ExecEvent" {
		t.Fatalf("capability = %+v", cap)
	}
	if cap.Metadata["continuum.horizon.boundary"] != "declarations-only" {
		t.Fatalf("metadata = %+v", cap.Metadata)
	}
	if _, ok := cap.Metadata["continuum.horizon.artifacts"]; !ok {
		t.Fatalf("metadata missing artifacts: %+v", cap.Metadata)
	}
	var sawObject bool
	for _, artifact := range inspection.Artifacts {
		if artifact.Kind == ArtifactBPFObject {
			sawObject = true
			if artifact.SHA256 == "" || artifact.Size == 0 {
				t.Fatalf("bad object artifact = %+v", artifact)
			}
		}
	}
	if !sawObject {
		t.Fatalf("no bpf object in artifacts: %+v", inspection.Artifacts)
	}
}

func TestInspectBPFObjectDoesNotRegisterCapabilities(t *testing.T) {
	inspection, err := InspectPath(filepath.Join("..", "testdata", "horizon-export", "output.bpf.o"))
	if err != nil {
		t.Fatalf("InspectPath: %v", err)
	}
	if inspection.Kind != ArtifactBPFObject {
		t.Fatalf("kind = %s", inspection.Kind)
	}
	if len(inspection.Capabilities) != 0 {
		t.Fatalf("compiled object should not register caps: %+v", inspection.Capabilities)
	}
}
