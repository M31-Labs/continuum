package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/horizon"
	creplay "m31labs.dev/continuum/replay"
)

func runReplay(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "config path")
	policyPath := fs.String("policy", "", "policy path")
	policyStorePath := fs.String("policy-store", ".continuum/policies.json", "policy store")
	baselinePolicyPath := fs.String("baseline-policy", "", "baseline policy path for diff")
	eventsPath := fs.String("events", "", "events JSON or JSONL path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *eventsPath == "" {
		return usageError("Usage: continuum replay [--policy candidate.arb] [--baseline-policy base.arb] --events events.jsonl")
	}
	cfg, err := loadOptionalConfig(*configPath)
	if err != nil {
		return err
	}
	resolvedPolicy, err := resolvePolicyPath(*policyPath, *policyStorePath, cfg)
	if err != nil {
		return err
	}
	bundle, err := arbiterx.CompileFile(resolvedPolicy)
	if err != nil {
		return err
	}
	events, err := loadEvents(*eventsPath)
	if err != nil {
		return err
	}
	results, err := creplay.Events(context.Background(), bundle, events)
	if err != nil {
		return err
	}
	if *baselinePolicyPath != "" {
		baseBundle, err := arbiterx.CompileFile(*baselinePolicyPath)
		if err != nil {
			return err
		}
		baseResults, err := creplay.Events(context.Background(), baseBundle, events)
		if err != nil {
			return err
		}
		for _, diff := range creplay.Compare(baseResults, results) {
			fmt.Fprintf(stdout, "%s\t%s\t%s\n", diff.EventID, diff.Before, diff.After)
		}
		return nil
	}
	for _, result := range results {
		if result.Decision.Selected == nil {
			continue
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\n", result.Event.ID, result.Decision.Selected.Decision(), result.Decision.Selected.Reason())
	}
	return nil
}

func loadEvents(path string) ([]event.Event, error) {
	return loadEventsWithHorizon(path, "")
}

func loadEventsWithHorizon(path string, manifestDir string) ([]event.Event, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	caps, err := loadHorizonCaps(manifestDir)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}
	if events, ok, err := loadSingleJSONDocument(trimmed, caps); ok || err != nil {
		return events, err
	}
	var events []event.Event
	scanner := bufio.NewScanner(strings.NewReader(trimmed))
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		evt, err := eventFromRawJSON(scanner.Bytes(), caps)
		if err != nil {
			return nil, err
		}
		events = append(events, evt)
	}
	return events, scanner.Err()
}

func loadSingleJSONDocument(trimmed string, caps map[string]capability.Capability) ([]event.Event, bool, error) {
	dec := json.NewDecoder(strings.NewReader(trimmed))
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
		for _, item := range items {
			evt, err := eventFromRawJSON(item, caps)
			if err != nil {
				return nil, true, err
			}
			events = append(events, evt)
		}
		return events, true, nil
	}
	evt, err := eventFromRawJSON(raw, caps)
	if err != nil {
		return nil, true, err
	}
	return []event.Event{evt}, true, nil
}

func eventFromRawJSON(data []byte, caps map[string]capability.Capability) (event.Event, error) {
	var evt event.Event
	if err := json.Unmarshal(data, &evt); err != nil {
		return event.Event{}, err
	}
	if evt.Kind != "" {
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
		cap, exists := caps[envelope.Capability]
		if !exists {
			return event.Event{}, fmt.Errorf("horizon capability %q is not registered", envelope.Capability)
		}
		return horizon.ConvertEventEnvelope(envelope, cap)
	}
	return event.Event{}, fmt.Errorf("event kind is required")
}

func loadHorizonCaps(manifestDir string) (map[string]capability.Capability, error) {
	out := map[string]capability.Capability{}
	if manifestDir == "" {
		return out, nil
	}
	caps, err := horizon.LoadDir(manifestDir)
	if err != nil {
		return nil, err
	}
	for _, cap := range caps {
		out[cap.Name] = cap
	}
	return out, nil
}
