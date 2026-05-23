package horizon

import (
	"path/filepath"
	"testing"

	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/internal/testutil"
)

func TestLoadHorizonManifests(t *testing.T) {
	caps, err := LoadDir(filepath.Join("..", "testdata", "manifests"))
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(caps) != 2 {
		t.Fatalf("caps len = %d", len(caps))
	}
	exec := caps[0]
	if exec.Name != "kernel.network.connect.observe" && exec.Name != "kernel.process.exec.observe" {
		t.Fatalf("unexpected first cap: %+v", exec)
	}
	found := false
	for _, cap := range caps {
		if cap.Name == "kernel.process.exec.observe" {
			found = true
			if cap.Kind != capability.KindSource || cap.Owner != "horizon" || cap.Output != "ExecEvent" {
				t.Fatalf("bad exec cap: %+v", cap)
			}
		}
	}
	if !found {
		t.Fatal("exec capability not loaded")
	}
}

func TestLoadHorizonV0Manifest(t *testing.T) {
	manifest, err := LoadFile(filepath.Join("..", "testdata", "horizon-manifests", "exec.cap.json"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	caps, err := manifest.ContinuumCapabilities()
	if err != nil {
		t.Fatalf("ContinuumCapabilities: %v", err)
	}
	if len(caps) != 1 {
		t.Fatalf("caps len = %d", len(caps))
	}
	cap := caps[0]
	if cap.Name != "kernel.process.exec.observe" || cap.Owner != "horizon" {
		t.Fatalf("cap identity = %+v", cap)
	}
	if cap.Output != "ExecEvent" || cap.Program != "OnExec" || cap.Section != "tracepoint/sched:sched_process_exec" {
		t.Fatalf("cap route = %+v", cap)
	}
	if got := cap.Metadata["horizon.package"]; got != "probes" {
		t.Fatalf("metadata package = %v", got)
	}
	events, ok := cap.Metadata["horizon.maps.events"].([]string)
	if !ok || len(events) != 1 || events[0] != "ExecEvents" {
		t.Fatalf("metadata events = %#v", cap.Metadata["horizon.maps.events"])
	}
}

func TestLoadHorizonV0Dir(t *testing.T) {
	caps, err := LoadDir(filepath.Join("..", "testdata", "horizon-manifests"))
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(caps) != 1 || caps[0].Name != "kernel.process.exec.observe" {
		t.Fatalf("caps = %+v", caps)
	}
}

func TestHorizonManifestToRegistryCapabilityGolden(t *testing.T) {
	caps, err := LoadDir(filepath.Join("..", "testdata", "horizon-manifests"))
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	testutil.EqualGoldenJSON(t, filepath.Join("..", "testdata", "golden", "horizon_exec_capabilities.json"), caps)
}
