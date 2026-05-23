package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type JSONLSink struct {
	mu sync.Mutex
	f  *os.File
}

func NewJSONLSink(path string) (*JSONLSink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open audit sink %s: %w", path, err)
	}
	return &JSONLSink{f: f}, nil
}

func (s *JSONLSink) Write(_ context.Context, event Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return fmt.Errorf("audit sink is closed")
	}
	return json.NewEncoder(s.f).Encode(event)
}

func (s *JSONLSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

func ReadJSONL(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", path, err)
	}
	defer f.Close()

	var events []Event
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		var evt Event
		if err := json.Unmarshal(scanner.Bytes(), &evt); err != nil {
			return nil, fmt.Errorf("parse audit line %d: %w", lineNo, err)
		}
		events = append(events, evt)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return events, nil
}
