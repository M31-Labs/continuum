package runtime

import (
	"context"
	"fmt"
	"time"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/subject"
)

const GrantRevocationCapability = "continuum.grant.revoke"

type DeliveryHandler func(context.Context, DeliveryItem) error

type GrantRevocationRetryOptions struct {
	FailedOnly bool
	DryRun     bool
	Now        func() time.Time
}

type GrantRevocationRetryReport struct {
	Matched   int `json:"matched"`
	Attempted int `json:"attempted"`
	Delivered int `json:"delivered"`
	Failed    int `json:"failed"`
}

func EnqueueGrantRevocation(path string, grant capability.Grant, reason string, now time.Time) (DeliveryItem, error) {
	if path == "" {
		return DeliveryItem{}, fmt.Errorf("delivery store path is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	subj := subject.Subject{Kind: string(subject.KindAgent), Session: grant.Session}
	fields := map[string]any{
		"grant_id":   grant.ID,
		"session":    grant.Session,
		"capability": grant.Capability,
		"reason":     reason,
	}
	var item DeliveryItem
	err := UpdateDeliveryStore(path, func(queue *DeliveryStore) error {
		var err error
		item, err = queue.Enqueue(DeliveryItem{
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
		return err
	})
	if err != nil {
		return DeliveryItem{}, err
	}
	return item, nil
}

func RetryGrantRevocationDeliveries(ctx context.Context, path string, opts GrantRevocationRetryOptions, deliver DeliveryHandler) (GrantRevocationRetryReport, error) {
	if path == "" {
		return GrantRevocationRetryReport{}, fmt.Errorf("delivery store path is required")
	}
	if deliver == nil {
		deliver = ObserveGrantRevocationDelivery
	}
	store, err := LoadDeliveryStore(path)
	if err != nil {
		return GrantRevocationRetryReport{}, err
	}
	var candidates []DeliveryItem
	for _, item := range store.List() {
		if retryableGrantRevocation(item, opts) {
			candidates = append(candidates, item)
		}
	}
	report := GrantRevocationRetryReport{Matched: len(candidates)}
	if opts.DryRun {
		return report, nil
	}
	var firstErr error
	for _, item := range candidates {
		report.Attempted++
		attempt := audit.DeliveryAttempt{
			DeliveryID:  item.ID,
			Time:        retryNow(opts),
			Capability:  item.Capability,
			Enforcement: item.Enforcement,
			Status:      string(DeliveryDelivered),
		}
		if err := deliver(ctx, item); err != nil {
			attempt.Status = string(DeliveryFailed)
			attempt.Error = err.Error()
			report.Failed++
			if firstErr == nil {
				firstErr = err
			}
		} else {
			report.Delivered++
		}
		if err := UpdateDeliveryStore(path, func(queue *DeliveryStore) error {
			_, err := queue.RecordAttempt(item.ID, attempt)
			return err
		}); err != nil {
			return report, err
		}
	}
	if firstErr != nil {
		return report, fmt.Errorf("retry grant revocation deliveries: %d failed: %w", report.Failed, firstErr)
	}
	return report, nil
}

func ObserveGrantRevocationDelivery(_ context.Context, item DeliveryItem) error {
	if item.Capability != GrantRevocationCapability {
		return fmt.Errorf("delivery %s is %s, not %s", item.ID, item.Capability, GrantRevocationCapability)
	}
	return nil
}

func retryableGrantRevocation(item DeliveryItem, opts GrantRevocationRetryOptions) bool {
	if item.Capability != GrantRevocationCapability {
		return false
	}
	status := item.Status
	if status == "" {
		status = DeliveryPending
	}
	if opts.FailedOnly {
		return status == DeliveryFailed
	}
	return status == DeliveryPending || status == DeliveryFailed
}

func retryNow(opts GrantRevocationRetryOptions) time.Time {
	if opts.Now != nil {
		return opts.Now()
	}
	return time.Now().UTC()
}
