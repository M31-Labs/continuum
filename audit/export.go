package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"m31labs.dev/continuum/subject"
)

const redactedValue = "[REDACTED]"

type RedactionOptions struct {
	FieldNames    []string
	RedactRaw     bool
	RedactSubject bool
}

func (o RedactionOptions) Active() bool {
	return len(normalizedFieldSet(o.FieldNames)) > 0 || o.RedactRaw || o.RedactSubject
}

func RedactEvent(event Event, opts RedactionOptions) Event {
	out := event
	fieldSet := normalizedFieldSet(opts.FieldNames)
	out.InputEvent.Fields = redactMap(event.InputEvent.Fields, fieldSet)
	out.Outcome.Fields = redactMap(event.Outcome.Fields, fieldSet)
	if opts.RedactRaw {
		out.InputEvent.Raw = nil
	} else {
		out.InputEvent.Raw = redactMap(event.InputEvent.Raw, fieldSet)
	}
	if opts.RedactSubject {
		out.Subject = redactSubject(event.Subject)
		out.InputEvent.Subject = redactSubject(event.InputEvent.Subject)
	}
	if opts.Active() {
		out.ChainPrev = ""
		out.ChainHash = ""
	}
	return out
}

func ExportJSONL(w io.Writer, events []Event, opts RedactionOptions) error {
	enc := json.NewEncoder(w)
	for _, event := range events {
		out := RedactEvent(event, opts)
		if err := enc.Encode(out); err != nil {
			return fmt.Errorf("encode audit export event %s: %w", event.ID, err)
		}
	}
	return nil
}

func normalizedFieldSet(names []string) map[string]bool {
	out := make(map[string]bool)
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		out[strings.ToLower(name)] = true
	}
	return out
}

func redactSubject(s subject.Subject) subject.Subject {
	if s.Empty() {
		return subject.Subject{}
	}
	return subject.Subject{Kind: s.Kind}
}

func redactMap(in map[string]any, fieldSet map[string]bool) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		if fieldSet[strings.ToLower(key)] {
			out[key] = redactedValue
			continue
		}
		out[key] = redactValue(value, fieldSet)
	}
	return out
}

func redactValue(value any, fieldSet map[string]bool) any {
	switch v := value.(type) {
	case map[string]any:
		return redactMap(v, fieldSet)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = redactValue(item, fieldSet)
		}
		return out
	default:
		return value
	}
}
