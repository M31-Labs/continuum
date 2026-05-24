package runtime

import (
	"fmt"
	"time"
)

type RetentionOptions struct {
	Retain    int
	OlderThan time.Duration
	Now       time.Time
}

type RetentionReport struct {
	Before  int `json:"before"`
	After   int `json:"after"`
	Removed int `json:"removed"`
}

func (o RetentionOptions) Validate() error {
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

func retentionNow(opts RetentionOptions) time.Time {
	if !opts.Now.IsZero() {
		return opts.Now
	}
	return time.Now().UTC()
}
