package airlock

import (
	"testing"

	"m31labs.dev/continuum/capability"
)

func TestDecoyCapabilitiesAreObserveOnly(t *testing.T) {
	caps := DecoyCapabilities()
	if len(caps) == 0 {
		t.Fatal("no decoy capabilities registered")
	}
	for _, cap := range caps {
		if err := capability.Validate(cap); err != nil {
			t.Fatalf("Validate(%s): %v", cap.Name, err)
		}
		if cap.Danger != capability.DangerObserve || cap.Backend != "observe" {
			t.Fatalf("decoy capability claims enforcement: %+v", cap)
		}
		if got, ok := cap.Metadata["real_enforcement"].(bool); !ok || got {
			t.Fatalf("decoy capability missing real_enforcement=false: %+v", cap)
		}
		if got, ok := cap.Metadata["enforcement"].(string); !ok || got != "none" {
			t.Fatalf("decoy capability missing enforcement=none: %+v", cap)
		}
		if got, ok := cap.Metadata["airlock_decoy"].(bool); !ok || !got {
			t.Fatalf("decoy capability missing airlock_decoy=true: %+v", cap)
		}
	}
}
