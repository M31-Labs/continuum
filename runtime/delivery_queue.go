package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/internal/statefile"
)

type DeliveryStatus string

const (
	DeliveryPending   DeliveryStatus = "pending"
	DeliveryDelivered DeliveryStatus = "delivered"
	DeliveryFailed    DeliveryStatus = "failed"
)

type DeliveryItem struct {
	ID          string                  `json:"id"`
	AuditID     string                  `json:"audit_id"`
	EventID     string                  `json:"event_id,omitempty"`
	Capability  string                  `json:"capability"`
	Enforcement string                  `json:"enforcement,omitempty"`
	Delivery    capability.Delivery     `json:"delivery"`
	Status      DeliveryStatus          `json:"status"`
	Attempts    []audit.DeliveryAttempt `json:"attempts,omitempty"`
	CreatedAt   time.Time               `json:"created_at"`
	UpdatedAt   time.Time               `json:"updated_at"`
}

type DeliveryStore struct {
	mu    sync.Mutex
	Path  string         `json:"-"`
	Items []DeliveryItem `json:"items"`
}

func LoadDeliveryStore(path string) (*DeliveryStore, error) {
	store := &DeliveryStore{Path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, fmt.Errorf("read delivery store %s: %w", path, err)
	}
	if err := json.Unmarshal(data, store); err != nil {
		return nil, fmt.Errorf("parse delivery store %s: %w", path, err)
	}
	store.Path = path
	return store, nil
}

func (s *DeliveryStore) Save() error {
	if s == nil {
		return fmt.Errorf("nil delivery store")
	}
	return statefile.WriteJSON(s.Path, s)
}

func UpdateDeliveryStore(path string, mutate func(*DeliveryStore) error) error {
	if mutate == nil {
		return fmt.Errorf("delivery store mutation callback is required")
	}
	return statefile.WithLock(path, func() error {
		store, err := LoadDeliveryStore(path)
		if err != nil {
			return err
		}
		if err := mutate(store); err != nil {
			return err
		}
		return statefile.WriteJSONWithoutLock(path, store)
	})
}

func (s *DeliveryStore) Enqueue(item DeliveryItem) (DeliveryItem, error) {
	if s == nil {
		return DeliveryItem{}, fmt.Errorf("nil delivery store")
	}
	now := item.CreatedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	item.CreatedAt = now
	item.UpdatedAt = now
	if item.Status == "" {
		item.Status = DeliveryPending
	}
	if item.ID == "" {
		item.ID = s.nextID(item.AuditID, item.Capability)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.Items {
		if existing.ID == item.ID {
			return DeliveryItem{}, fmt.Errorf("delivery %q already exists", item.ID)
		}
	}
	s.Items = append(s.Items, item)
	return item, nil
}

func (s *DeliveryStore) RecordAttempt(id string, attempt audit.DeliveryAttempt) (DeliveryItem, error) {
	if s == nil {
		return DeliveryItem{}, fmt.Errorf("nil delivery store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Items {
		if s.Items[i].ID != id {
			continue
		}
		if attempt.Time.IsZero() {
			attempt.Time = time.Now().UTC()
		}
		switch attempt.Status {
		case string(DeliveryDelivered):
			s.Items[i].Status = DeliveryDelivered
		case string(DeliveryFailed):
			s.Items[i].Status = DeliveryFailed
		default:
			s.Items[i].Status = DeliveryPending
		}
		s.Items[i].Attempts = append(s.Items[i].Attempts, attempt)
		s.Items[i].UpdatedAt = attempt.Time
		return s.Items[i], nil
	}
	return DeliveryItem{}, fmt.Errorf("delivery %q not found", id)
}

func (s *DeliveryStore) List() []DeliveryItem {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]DeliveryItem(nil), s.Items...)
	slices.SortFunc(out, func(a, b DeliveryItem) int {
		if a.CreatedAt.Equal(b.CreatedAt) {
			return strings.Compare(a.ID, b.ID)
		}
		if a.CreatedAt.Before(b.CreatedAt) {
			return -1
		}
		return 1
	})
	return out
}

func (s *DeliveryStore) ByStatus(status DeliveryStatus) []DeliveryItem {
	var out []DeliveryItem
	for _, item := range s.List() {
		if item.Status == status {
			out = append(out, item)
		}
	}
	return out
}

func (s *DeliveryStore) nextID(auditID, cap string) string {
	base := sanitizeDeliveryID(auditID)
	if base == "" {
		base = "delivery"
	}
	capPart := sanitizeDeliveryID(cap)
	if capPart != "" {
		base += "_" + capPart
	}
	return fmt.Sprintf("dlv_%s_%d", base, len(s.Items)+1)
}

func sanitizeDeliveryID(value string) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}
