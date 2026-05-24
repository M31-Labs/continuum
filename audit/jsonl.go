package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"m31labs.dev/continuum/internal/statefile"
)

const MaxEventBytes = 1 << 20

type JSONLSink struct {
	mu       sync.Mutex
	f        *os.File
	prevHash string
}

func NewJSONLSink(path string) (*JSONLSink, error) {
	prevHash, err := LastChainHash(path)
	if err != nil {
		return nil, err
	}
	f, err := statefile.OpenAppend(path)
	if err != nil {
		return nil, fmt.Errorf("open audit sink %s: %w", path, err)
	}
	return &JSONLSink{f: f, prevHash: prevHash}, nil
}

func (s *JSONLSink) Write(_ context.Context, event Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return fmt.Errorf("audit sink is closed")
	}
	event.ChainPrev = s.prevHash
	hash, err := HashEvent(event)
	if err != nil {
		return err
	}
	event.ChainHash = hash
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if len(data) > MaxEventBytes {
		return fmt.Errorf("audit event %s is %d bytes, exceeds max %d", event.ID, len(data), MaxEventBytes)
	}
	if _, err := s.f.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := s.f.Sync(); err != nil {
		return err
	}
	s.prevHash = hash
	return nil
}

func (s *JSONLSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	if err := s.f.Sync(); err != nil {
		_ = s.f.Close()
		s.f = nil
		return err
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
	scanner := newScanner(f)
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
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("audit line exceeds max %d bytes", MaxEventBytes)
		}
		return nil, err
	}
	return events, nil
}

func newScanner(f *os.File) *bufio.Scanner {
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), MaxEventBytes+1)
	return scanner
}
