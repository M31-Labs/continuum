package policy

import "time"

type Override struct {
	Rule      string    `json:"rule"`
	Disabled  bool      `json:"disabled,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}
