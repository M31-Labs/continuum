package event

import "m31labs.dev/continuum/arbiterx"

func Normalize(evt Event) []arbiterx.Fact {
	facts := make([]arbiterx.Fact, 0, 2)
	if evt.Subject.AgentName != "" || evt.Subject.Session != "" || evt.Subject.RepoRoot != "" {
		facts = append(facts, arbiterx.NewFact(arbiterx.FactAgentContext, evt.Subject, map[string]any{
			"session":   evt.Subject.Session,
			"name":      evt.Subject.AgentName,
			"repo_root": evt.Subject.RepoRoot,
			"task":      evt.Subject.Task,
		}))
	}
	switch evt.Kind {
	case KindFileAccess, KindFileOpen:
		facts = append(facts, arbiterx.NewFact(arbiterx.FactFileAccess, evt.Subject, map[string]any{
			"pid":           pidField(evt),
			"path":          stringField(evt.Fields, "path"),
			"op":            stringField(evt.Fields, "op"),
			"agent_session": evt.Subject.Session,
		}))
	case KindNetworkConnect:
		facts = append(facts, arbiterx.NewFact(arbiterx.FactNetworkConnect, evt.Subject, map[string]any{
			"pid":           pidField(evt),
			"host":          stringField(evt.Fields, "host"),
			"ip":            stringField(evt.Fields, "ip"),
			"port":          numberField(evt.Fields, "port"),
			"agent_session": evt.Subject.Session,
		}))
	case KindProcessExec:
		facts = append(facts, arbiterx.NewFact(arbiterx.FactProcessExec, evt.Subject, map[string]any{
			"pid":           pidField(evt),
			"comm":          stringField(evt.Fields, "comm"),
			"argv_text":     stringField(evt.Fields, "argv_text"),
			"cwd":           stringField(evt.Fields, "cwd"),
			"agent_session": evt.Subject.Session,
		}))
	case KindBehaviorSummary:
		subjectValue := stringField(evt.Fields, "subject")
		if subjectValue == "" {
			subjectValue = evt.Subject.String()
		}
		facts = append(facts, arbiterx.NewFact(arbiterx.FactBehavior, evt.Subject, map[string]any{
			"subject":                subjectValue,
			"exec_count":             numberField(evt.Fields, "exec_count"),
			"unique_network_targets": numberField(evt.Fields, "unique_network_targets"),
			"touched_secret_paths":   numberField(evt.Fields, "touched_secret_paths"),
			"rewritten_files":        numberField(evt.Fields, "rewritten_files"),
			"entropy_increase_score": floatNumberField(evt.Fields, "entropy_increase_score"),
		}))
	}
	return facts
}

func pidField(evt Event) int {
	if pid := numberField(evt.Fields, "pid"); pid != 0 {
		return pid
	}
	return evt.Subject.PID
}

func stringField(fields map[string]any, key string) string {
	value, _ := fields[key].(string)
	return value
}

func numberField(fields map[string]any, key string) int {
	switch v := fields[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

func floatNumberField(fields map[string]any, key string) float64 {
	switch v := fields[key].(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	default:
		return 0
	}
}
