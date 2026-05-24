package audit

import (
	"bytes"
	"fmt"
	"time"

	"m31labs.dev/continuum/internal/statefile"
)

type CompactOptions struct {
	Retain    int
	OlderThan time.Duration
	Now       time.Time
}

type CompactReport struct {
	Before  int `json:"before"`
	After   int `json:"after"`
	Removed int `json:"removed"`
}

func (o CompactOptions) Validate() error {
	if o.Retain < 0 {
		return fmt.Errorf("retain must be >= 0")
	}
	if o.OlderThan < 0 {
		return fmt.Errorf("older-than must be >= 0")
	}
	if o.Retain == 0 && o.OlderThan == 0 {
		return fmt.Errorf("retain or older-than is required")
	}
	return nil
}

func CompactJSONL(path string, opts CompactOptions) (CompactReport, error) {
	events, err := ReadJSONL(path)
	if err != nil {
		return CompactReport{}, err
	}
	kept, report, err := CompactEvents(events, opts)
	if err != nil {
		return CompactReport{}, err
	}
	kept, err = Rechain(kept)
	if err != nil {
		return CompactReport{}, err
	}
	var buf bytes.Buffer
	if err := ExportJSONL(&buf, kept, RedactionOptions{}); err != nil {
		return CompactReport{}, err
	}
	if err := statefile.WriteMode(path, buf.Bytes(), statefile.FileMode); err != nil {
		return CompactReport{}, err
	}
	return report, nil
}

func CompactEvents(events []Event, opts CompactOptions) ([]Event, CompactReport, error) {
	if err := opts.Validate(); err != nil {
		return nil, CompactReport{}, err
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	cutoff := now.Add(-opts.OlderThan)
	report := CompactReport{Before: len(events)}
	retainStart := len(events)
	if opts.Retain > 0 && opts.Retain < len(events) {
		retainStart = len(events) - opts.Retain
	} else if opts.Retain > 0 {
		retainStart = 0
	}
	kept := make([]Event, 0, len(events))
	for i, event := range events {
		if i >= retainStart || !auditExpiredForRetention(event, opts, cutoff) {
			kept = append(kept, event)
		}
	}
	report.After = len(kept)
	report.Removed = report.Before - report.After
	return kept, report, nil
}

func Rechain(events []Event) ([]Event, error) {
	out := make([]Event, len(events))
	prev := ""
	for i, event := range events {
		event.ChainPrev = prev
		hash, err := HashEvent(event)
		if err != nil {
			return nil, err
		}
		event.ChainHash = hash
		out[i] = event
		prev = hash
	}
	return out, nil
}

func auditExpiredForRetention(event Event, opts CompactOptions, cutoff time.Time) bool {
	if opts.OlderThan == 0 {
		return true
	}
	return !event.Time.IsZero() && event.Time.Before(cutoff)
}
