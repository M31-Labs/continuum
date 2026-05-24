package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

type ChainReport struct {
	OK       bool   `json:"ok"`
	Events   int    `json:"events"`
	LastHash string `json:"last_hash,omitempty"`
	Error    string `json:"error,omitempty"`
	Line     int    `json:"line,omitempty"`
	EventID  string `json:"event_id,omitempty"`
}

func HashEvent(evt Event) (string, error) {
	evt.ChainHash = ""
	data, err := json.Marshal(evt)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func VerifyJSONL(path string) (ChainReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return ChainReport{}, fmt.Errorf("open audit log %s: %w", path, err)
	}
	defer f.Close()
	return VerifyJSONLReader(f)
}

func VerifyJSONLReader(r io.Reader) (ChainReport, error) {
	report := ChainReport{OK: true}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), MaxEventBytes+1)
	lineNo := 0
	prevHash := ""
	for scanner.Scan() {
		lineNo++
		var evt Event
		if err := json.Unmarshal(scanner.Bytes(), &evt); err != nil {
			return ChainReport{}, fmt.Errorf("parse audit line %d: %w", lineNo, err)
		}
		if evt.ChainHash == "" {
			return chainFail(report, lineNo, evt.ID, "missing chain_hash"), nil
		}
		if evt.ChainPrev != prevHash {
			return chainFail(report, lineNo, evt.ID, "chain_prev does not match previous event hash"), nil
		}
		got := evt.ChainHash
		want, err := HashEvent(evt)
		if err != nil {
			return ChainReport{}, fmt.Errorf("hash audit line %d: %w", lineNo, err)
		}
		if got != want {
			return chainFail(report, lineNo, evt.ID, "chain_hash does not match event contents"), nil
		}
		report.Events++
		report.LastHash = got
		prevHash = got
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return ChainReport{}, fmt.Errorf("audit line exceeds max %d bytes", MaxEventBytes)
		}
		return ChainReport{}, err
	}
	return report, nil
}

func LastChainHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("open audit log %s: %w", path, err)
	}
	defer f.Close()
	report, err := VerifyJSONLReader(f)
	if err != nil {
		return "", err
	}
	if !report.OK {
		return "", fmt.Errorf("audit chain is invalid at line %d: %s", report.Line, report.Error)
	}
	return report.LastHash, nil
}

func chainFail(report ChainReport, line int, eventID, message string) ChainReport {
	report.OK = false
	report.Line = line
	report.EventID = eventID
	report.Error = message
	return report
}
