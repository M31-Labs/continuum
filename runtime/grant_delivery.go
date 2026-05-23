package runtime

import (
	"fmt"
	"time"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/subject"
)

const GrantRevocationCapability = "continuum.grant.revoke"

func EnqueueGrantRevocation(path string, grant capability.Grant, reason string, now time.Time) (DeliveryItem, error) {
	if path == "" {
		return DeliveryItem{}, fmt.Errorf("delivery store path is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	queue, err := LoadDeliveryStore(path)
	if err != nil {
		return DeliveryItem{}, err
	}
	subj := subject.Subject{Kind: string(subject.KindAgent), Session: grant.Session}
	fields := map[string]any{
		"grant_id":   grant.ID,
		"session":    grant.Session,
		"capability": grant.Capability,
		"reason":     reason,
	}
	item, err := queue.Enqueue(DeliveryItem{
		AuditID:     grant.ID,
		EventID:     "evt_" + grant.ID + "_revoke",
		Capability:  GrantRevocationCapability,
		Enforcement: "observe",
		Delivery: capability.Delivery{
			Subject: subj,
			Event: event.Event{
				ID:      "evt_" + grant.ID + "_revoke",
				Time:    now,
				Kind:    "grant.revoke",
				Subject: subj,
				Fields:  fields,
			},
			Outcome: arbiterx.NewOutcome(arbiterx.OutcomeAudit, "GrantRevocation", fields),
		},
		Status:    DeliveryPending,
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		return DeliveryItem{}, err
	}
	if err := queue.Save(); err != nil {
		return DeliveryItem{}, err
	}
	return item, nil
}
