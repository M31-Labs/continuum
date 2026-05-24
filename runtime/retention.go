package runtime

import (
	"fmt"
	"time"
)

type RetentionOptions struct {
	Retain            int
	OlderThan         time.Duration
	MaxProcessRecords int
	Now               time.Time
}

type RetentionReport struct {
	Before           int `json:"before"`
	After            int `json:"after"`
	Removed          int `json:"removed"`
	ProcessesBefore  int `json:"processes_before,omitempty"`
	ProcessesAfter   int `json:"processes_after,omitempty"`
	ProcessesRemoved int `json:"processes_removed,omitempty"`
}

func (o RetentionOptions) Validate() error {
	if o.Retain < 0 {
		return fmt.Errorf("retain must be >= 0")
	}
	if o.OlderThan < 0 {
		return fmt.Errorf("older-than must be >= 0")
	}
	if o.MaxProcessRecords < 0 {
		return fmt.Errorf("max-processes must be >= 0")
	}
	if o.Retain == 0 && o.OlderThan == 0 && o.MaxProcessRecords == 0 {
		return fmt.Errorf("retain, older-than, or max-processes is required")
	}
	return nil
}

func retentionNow(opts RetentionOptions) time.Time {
	if !opts.Now.IsZero() {
		return opts.Now
	}
	return time.Now().UTC()
}
