package arbiterx

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	arbiter "github.com/odvcencio/arbiter"
	"github.com/odvcencio/arbiter/expert"
)

type Bundle struct {
	ID      string           `json:"id"`
	Path    string           `json:"path,omitempty"`
	Kind    string           `json:"kind"`
	Source  string           `json:"source,omitempty"`
	Program *arbiter.Program `json:"-"`
	Expert  *expert.Program  `json:"-"`
}

func Compile(source []byte) (*Bundle, error) {
	if len(strings.TrimSpace(string(source))) == 0 {
		return nil, fmt.Errorf("empty policy source")
	}
	program, err := arbiter.Compile(source)
	if err != nil {
		return nil, err
	}
	expertProgram, err := expert.Compile(source)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(source)
	kind := "agent-workdir"
	if strings.Contains(string(source), "DetectWormLikeFanout") || strings.Contains(string(source), "fact Behavior") {
		kind = "airlock"
	}
	return &Bundle{
		ID:      "arb_" + hex.EncodeToString(sum[:])[:12],
		Kind:    kind,
		Source:  string(source),
		Program: program,
		Expert:  expertProgram,
	}, nil
}

func CompileFile(path string) (*Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy %s: %w", path, err)
	}
	program, err := arbiter.CompileFile(path)
	if err != nil {
		return nil, err
	}
	expertProgram, err := expert.CompileFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	kind := "agent-workdir"
	if strings.Contains(string(data), "DetectWormLikeFanout") || strings.Contains(string(data), "fact Behavior") {
		kind = "airlock"
	}
	return &Bundle{
		ID:      "arb_" + hex.EncodeToString(sum[:])[:12],
		Path:    path,
		Kind:    kind,
		Source:  string(data),
		Program: program,
		Expert:  expertProgram,
	}, nil
}
