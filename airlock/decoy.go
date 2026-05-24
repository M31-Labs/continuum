package airlock

import "m31labs.dev/continuum/capability"

type Decoy struct {
	Capability string         `json:"capability"`
	Fields     map[string]any `json:"fields,omitempty"`
}

func DecoyCapabilities() []capability.Capability {
	return []capability.Capability{
		{
			Name:        "continuum.airlock.decoy.filesystem",
			Kind:        capability.KindWorker,
			Owner:       "continuum",
			Input:       "AirlockDecoyRequest",
			Output:      "AirlockDecoyResponse",
			Danger:      capability.DangerObserve,
			Backend:     "observe",
			Description: "register filesystem decoy responses for airlocked subjects without kernel enforcement",
			Metadata:    decoyCapabilityMetadata("filesystem"),
		},
		{
			Name:        "continuum.airlock.decoy.network",
			Kind:        capability.KindWorker,
			Owner:       "continuum",
			Input:       "AirlockDecoyRequest",
			Output:      "AirlockDecoyResponse",
			Danger:      capability.DangerObserve,
			Backend:     "observe",
			Description: "register network decoy responses for airlocked subjects without network enforcement",
			Metadata:    decoyCapabilityMetadata("network"),
		},
		{
			Name:        "continuum.airlock.decoy.process",
			Kind:        capability.KindWorker,
			Owner:       "continuum",
			Input:       "AirlockDecoyRequest",
			Output:      "AirlockDecoyResponse",
			Danger:      capability.DangerObserve,
			Backend:     "observe",
			Description: "register process decoy responses for airlocked subjects without process enforcement",
			Metadata:    decoyCapabilityMetadata("process"),
		},
	}
}

func decoyCapabilityMetadata(kind string) map[string]any {
	return map[string]any{
		"airlock_decoy":    true,
		"decoy_kind":       kind,
		"real_enforcement": false,
		"enforcement":      "none",
		"scope":            "airlocked-subject",
	}
}
