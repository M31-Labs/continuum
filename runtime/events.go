package runtime

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/horizon"
)

// DecodeEvents accepts Continuum events, audit records, JSON arrays, JSONL, and
// Horizon event envelopes. Horizon envelopes require the capability to be
// present in the registry so output types can be mapped to Continuum event
// kinds without Horizon owning policy behavior.
func DecodeEvents(data []byte, registry *capability.Registry) ([]event.Event, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if events, ok, err := decodeSingleJSONDocument(trimmed, registry); ok || err != nil {
		return events, err
	}
	var events []event.Event
	scanner := bufio.NewScanner(bytes.NewReader(trimmed))
	line := 0
	for scanner.Scan() {
		line++
		item := bytes.TrimSpace(scanner.Bytes())
		if len(item) == 0 {
			continue
		}
		evt, err := decodeEventJSON(item, registry)
		if err != nil {
			return nil, fmt.Errorf("decode event line %d: %w", line, err)
		}
		events = append(events, evt)
	}
	return events, scanner.Err()
}

func decodeSingleJSONDocument(data []byte, registry *capability.Registry) ([]event.Event, bool, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, false, nil
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, false, nil
	}
	if len(raw) == 0 {
		return nil, true, nil
	}
	if raw[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, true, err
		}
		events := make([]event.Event, 0, len(items))
		for i, item := range items {
			evt, err := decodeEventJSON(item, registry)
			if err != nil {
				return nil, true, fmt.Errorf("decode event %d: %w", i, err)
			}
			events = append(events, evt)
		}
		return events, true, nil
	}
	evt, err := decodeEventJSON(raw, registry)
	if err != nil {
		return nil, true, err
	}
	return []event.Event{evt}, true, nil
}

func decodeEventJSON(data []byte, registry *capability.Registry) (event.Event, error) {
	var evt event.Event
	if err := json.Unmarshal(data, &evt); err != nil {
		return event.Event{}, err
	}
	if strings.TrimSpace(evt.Kind) != "" {
		return evt, nil
	}
	var auditEvent audit.Event
	if err := json.Unmarshal(data, &auditEvent); err == nil && auditEvent.InputEvent.Kind != "" {
		evt = auditEvent.InputEvent
		if evt.ID == "" {
			evt.ID = auditEvent.ID
		}
		return evt, nil
	}
	if envelope, ok, err := horizon.ParseEventEnvelope(data); err != nil {
		return event.Event{}, err
	} else if ok {
		if registry == nil {
			return event.Event{}, fmt.Errorf("horizon capability %q is not registered", envelope.Capability)
		}
		cap, exists := registry.Get(envelope.Capability)
		if !exists {
			return event.Event{}, fmt.Errorf("horizon capability %q is not registered", envelope.Capability)
		}
		return horizon.ConvertEventEnvelope(envelope, cap)
	}
	return event.Event{}, fmt.Errorf("event kind is required")
}
