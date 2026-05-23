package airlock

import (
	"path/filepath"
	"strings"

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

func NewAccumulator(subject string) *Accumulator {
	return &Accumulator{
		Subject:        subject,
		networkTargets: map[string]struct{}{},
		secretPaths:    map[string]struct{}{},
		rewrittenFiles: map[string]struct{}{},
	}
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
