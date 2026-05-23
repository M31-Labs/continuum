package airlock

import (
	"encoding/json"
	"fmt"
	"os"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/subject"
)

type Behavior struct {
	Subject              string  `json:"subject"`
	ExecCount            int     `json:"exec_count"`
	UniqueNetworkTargets int     `json:"unique_network_targets"`
	TouchedSecretPaths   int     `json:"touched_secret_paths"`
	RewrittenFiles       int     `json:"rewritten_files"`
	EntropyIncreaseScore float64 `json:"entropy_increase_score"`
}

func (b Behavior) Fact() arbiterx.Fact {
	return arbiterx.NewFact(arbiterx.FactBehavior, subject.Subject{}, map[string]any{
		"subject":                b.Subject,
		"exec_count":             b.ExecCount,
		"unique_network_targets": b.UniqueNetworkTargets,
		"touched_secret_paths":   b.TouchedSecretPaths,
		"rewritten_files":        b.RewrittenFiles,
		"entropy_increase_score": b.EntropyIncreaseScore,
	})
}

func LoadBehaviorFixture(path string) (Behavior, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Behavior{}, fmt.Errorf("read behavior fixture %s: %w", path, err)
	}
	var behavior Behavior
	if err := json.Unmarshal(data, &behavior); err != nil {
		return Behavior{}, fmt.Errorf("parse behavior fixture %s: %w", path, err)
	}
	return behavior, nil
}
