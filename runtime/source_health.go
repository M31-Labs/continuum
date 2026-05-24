package runtime

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"m31labs.dev/continuum/capability"
)

type SourceLifecycleStatus string

const (
	SourceStatusRegistered SourceLifecycleStatus = "registered"
	SourceStatusStarting   SourceLifecycleStatus = "starting"
	SourceStatusRunning    SourceLifecycleStatus = "running"
	SourceStatusStopped    SourceLifecycleStatus = "stopped"
	SourceStatusFailed     SourceLifecycleStatus = "failed"
)

type SourceHealth struct {
	Name               string                `json:"name"`
	Status             SourceLifecycleStatus `json:"status"`
	Events             uint64                `json:"events"`
	BackpressureEvents uint64                `json:"backpressure_events,omitempty"`
	QueueCapacity      int                   `json:"queue_capacity"`
	StartedAt          *time.Time            `json:"started_at,omitempty"`
	StoppedAt          *time.Time            `json:"stopped_at,omitempty"`
	LastEventAt        *time.Time            `json:"last_event_at,omitempty"`
	UpdatedAt          time.Time             `json:"updated_at"`
	LastError          string                `json:"last_error,omitempty"`
}

type SourceHealthStore struct {
	mu    sync.Mutex
	now   func() time.Time
	items map[string]SourceHealth
}

func NewSourceHealthStore() *SourceHealthStore {
	return &SourceHealthStore{
		now:   time.Now,
		items: map[string]SourceHealth{},
	}
}

func (s *SourceHealthStore) RegisterCapabilities(caps []capability.Capability) {
	for _, cap := range caps {
		if cap.Kind == capability.KindSource {
			s.Register(cap.Name)
		}
	}
}

func (s *SourceHealthStore) Register(name string) {
	s.update(name, func(health SourceHealth, now time.Time) SourceHealth {
		if health.Status == "" {
			health.Status = SourceStatusRegistered
		}
		health.UpdatedAt = now
		return health
	})
}

func (s *SourceHealthStore) MarkStarting(name string, queueCapacity int) {
	s.update(name, func(health SourceHealth, now time.Time) SourceHealth {
		health.Status = SourceStatusStarting
		health.QueueCapacity = queueCapacity
		health.StartedAt = timePtr(now)
		health.StoppedAt = nil
		health.LastError = ""
		health.UpdatedAt = now
		return health
	})
}

func (s *SourceHealthStore) MarkRunning(name string) {
	s.update(name, func(health SourceHealth, now time.Time) SourceHealth {
		health.Status = SourceStatusRunning
		health.UpdatedAt = now
		return health
	})
}

func (s *SourceHealthStore) RecordEvent(name string) {
	s.update(name, func(health SourceHealth, now time.Time) SourceHealth {
		health.Events++
		health.LastEventAt = timePtr(now)
		health.UpdatedAt = now
		return health
	})
}

func (s *SourceHealthStore) RecordBackpressure(name string) {
	s.update(name, func(health SourceHealth, now time.Time) SourceHealth {
		health.BackpressureEvents++
		health.UpdatedAt = now
		return health
	})
}

func (s *SourceHealthStore) MarkStopped(name string) {
	s.update(name, func(health SourceHealth, now time.Time) SourceHealth {
		health.Status = SourceStatusStopped
		health.StoppedAt = timePtr(now)
		health.UpdatedAt = now
		return health
	})
}

func (s *SourceHealthStore) MarkFailed(name string, err error) {
	s.update(name, func(health SourceHealth, now time.Time) SourceHealth {
		health.Status = SourceStatusFailed
		health.StoppedAt = timePtr(now)
		health.UpdatedAt = now
		if err != nil {
			health.LastError = err.Error()
		}
		return health
	})
}

func (s *SourceHealthStore) List() []SourceHealth {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SourceHealth, 0, len(s.items))
	for _, health := range s.items {
		out = append(out, health)
	}
	slices.SortFunc(out, func(a, b SourceHealth) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

func (s *SourceHealthStore) Get(name string) (SourceHealth, bool) {
	if s == nil {
		return SourceHealth{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	health, ok := s.items[name]
	return health, ok
}

func (s *SourceHealthStore) update(name string, mutate func(SourceHealth, time.Time) SourceHealth) {
	if s == nil {
		return
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items == nil {
		s.items = map[string]SourceHealth{}
	}
	now := s.clock()
	health := s.items[name]
	health.Name = name
	s.items[name] = mutate(health, now)
}

func (s *SourceHealthStore) clock() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

func sourceHealthIssue(health SourceHealth) string {
	if health.LastError != "" {
		return fmt.Sprintf("source %s failed: %s", health.Name, health.LastError)
	}
	return fmt.Sprintf("source %s failed", health.Name)
}

func timePtr(value time.Time) *time.Time {
	copy := value
	return &copy
}
