package horizon

import (
	"encoding/json"
	"fmt"
	"time"

	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/subject"
)

type EventEnvelope struct {
	ID         string          `json:"id,omitempty"`
	Time       time.Time       `json:"time,omitempty"`
	Capability string          `json:"capability"`
	Output     string          `json:"output,omitempty"`
	Subject    subject.Subject `json:"subject,omitempty"`
	Fields     map[string]any  `json:"fields,omitempty"`
	Raw        map[string]any  `json:"raw,omitempty"`
}

func ParseEventEnvelope(data []byte) (EventEnvelope, bool, error) {
	var probe struct {
		Capability string `json:"capability"`
	}
	if err := json.Unmarshal(data, &probe); err != nil || probe.Capability == "" {
		return EventEnvelope{}, false, err
	}
	var envelope EventEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return EventEnvelope{}, true, err
	}
	return envelope, true, nil
}

func ConvertEventEnvelope(envelope EventEnvelope, cap capability.Capability) (event.Event, error) {
	if envelope.Capability == "" {
		return event.Event{}, fmt.Errorf("horizon event capability is required")
	}
	if cap.Name == "" {
		return event.Event{}, fmt.Errorf("horizon capability %q is not registered", envelope.Capability)
	}
	output := envelope.Output
	if output == "" {
		output = cap.Output
	}
	raw := envelope.Raw
	if raw == nil {
		raw = map[string]any{}
	}
	raw["horizon.capability"] = envelope.Capability
	raw["horizon.output"] = output
	return event.Event{
		ID:      envelope.ID,
		Time:    envelope.Time,
		Source:  envelope.Capability,
		Subject: envelope.Subject,
		Kind:    eventKindForOutput(output),
		Fields:  envelope.Fields,
		Raw:     raw,
	}, nil
}

func eventKindForOutput(output string) string {
	switch output {
	case "ExecEvent", "ProcessExecEvent":
		return event.KindProcessExec
	case "ExitEvent", "ProcessExitEvent":
		return event.KindProcessExit
	case "FileAccessEvent", "FileEvent":
		return event.KindFileAccess
	case "NetworkConnectEvent", "ConnectEvent":
		return event.KindNetworkConnect
	default:
		if output == "" {
			return "horizon.event"
		}
		return "horizon." + output
	}
}
