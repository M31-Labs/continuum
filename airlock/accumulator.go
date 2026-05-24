package airlock

import (
	"path/filepath"
	"slices"
	"strings"
	"time"

	"m31labs.dev/continuum/event"
)

type Accumulator struct {
	Subject string

	execCount       int
	networkTargets  map[string]struct{}
	secretPaths     map[string]struct{}
	rewrittenFiles  map[string]struct{}
	maxEntropyScore float64
}

type AccumulatorSnapshot struct {
	Subject              string    `json:"subject"`
	ExecCount            int       `json:"exec_count,omitempty"`
	NetworkTargets       []string  `json:"network_targets,omitempty"`
	SecretPaths          []string  `json:"secret_paths,omitempty"`
	RewrittenFiles       []string  `json:"rewritten_files,omitempty"`
	EntropyIncreaseScore float64   `json:"entropy_increase_score,omitempty"`
	UpdatedAt            time.Time `json:"updated_at,omitempty"`
}

func NewAccumulator(subject string) *Accumulator {
	return &Accumulator{
		Subject:        subject,
		networkTargets: map[string]struct{}{},
		secretPaths:    map[string]struct{}{},
		rewrittenFiles: map[string]struct{}{},
	}
}

func NewAccumulatorFromSnapshot(snapshot AccumulatorSnapshot) *Accumulator {
	acc := NewAccumulator(snapshot.Subject)
	acc.execCount = snapshot.ExecCount
	acc.maxEntropyScore = snapshot.EntropyIncreaseScore
	acc.networkTargets = setFromSlice(snapshot.NetworkTargets)
	acc.secretPaths = setFromSlice(snapshot.SecretPaths)
	acc.rewrittenFiles = setFromSlice(snapshot.RewrittenFiles)
	return acc
}

func (a *Accumulator) Observe(evt event.Event) {
	if a == nil {
		return
	}
	if a.Subject == "" {
		a.Subject = evt.Subject.String()
	}
	switch evt.Kind {
	case event.KindProcessExec:
		a.execCount++
	case event.KindNetworkConnect:
		target := stringField(evt.Fields, "host")
		if target == "" {
			target = stringField(evt.Fields, "ip")
		}
		if target != "" {
			a.networkTargets[target] = struct{}{}
		}
	case event.KindFileAccess, event.KindFileOpen:
		path := filepath.ToSlash(stringField(evt.Fields, "path"))
		if hostSecretPath(path) {
			a.secretPaths[path] = struct{}{}
		}
		if stringField(evt.Fields, "op") == "write" && path != "" {
			a.rewrittenFiles[path] = struct{}{}
		}
		if score := floatField(evt.Fields, "entropy_increase_score"); score > a.maxEntropyScore {
			a.maxEntropyScore = score
		}
	}
}

func (a *Accumulator) Snapshot(updatedAt time.Time) AccumulatorSnapshot {
	if a == nil {
		return AccumulatorSnapshot{}
	}
	return AccumulatorSnapshot{
		Subject:              a.Subject,
		ExecCount:            a.execCount,
		NetworkTargets:       sortedKeys(a.networkTargets),
		SecretPaths:          sortedKeys(a.secretPaths),
		RewrittenFiles:       sortedKeys(a.rewrittenFiles),
		EntropyIncreaseScore: a.maxEntropyScore,
		UpdatedAt:            updatedAt,
	}
}

func (a *Accumulator) Behavior() Behavior {
	if a == nil {
		return Behavior{}
	}
	return Behavior{
		Subject:              a.Subject,
		ExecCount:            a.execCount,
		UniqueNetworkTargets: len(a.networkTargets),
		TouchedSecretPaths:   len(a.secretPaths),
		RewrittenFiles:       len(a.rewrittenFiles),
		EntropyIncreaseScore: a.maxEntropyScore,
	}
}

func (s AccumulatorSnapshot) Behavior() Behavior {
	return Behavior{
		Subject:              s.Subject,
		ExecCount:            s.ExecCount,
		UniqueNetworkTargets: len(s.NetworkTargets),
		TouchedSecretPaths:   len(s.SecretPaths),
		RewrittenFiles:       len(s.RewrittenFiles),
		EntropyIncreaseScore: s.EntropyIncreaseScore,
	}
}

func stringField(fields map[string]any, key string) string {
	value, _ := fields[key].(string)
	return value
}

func floatField(fields map[string]any, key string) float64 {
	switch v := fields[key].(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	default:
		return 0
	}
}

func hostSecretPath(path string) bool {
	path = filepath.ToSlash(path)
	return strings.Contains(path, "/.ssh/") || strings.Contains(path, "/.aws/") || strings.Contains(path, "/.kube/")
}

func setFromSlice(values []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}

func sortedKeys(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}
