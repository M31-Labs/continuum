package arbiterx

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

type Bundle struct {
	ID     string `json:"id"`
	Path   string `json:"path,omitempty"`
	Kind   string `json:"kind"`
	Source string `json:"source,omitempty"`
}

func Compile(source []byte) (*Bundle, error) {
	if len(strings.TrimSpace(string(source))) == 0 {
		return nil, fmt.Errorf("empty policy source")
	}
	sum := sha256.Sum256(source)
	kind := "agent-workdir"
	if strings.Contains(string(source), "DetectWormLikeFanout") || strings.Contains(string(source), "fact Behavior") {
		kind = "airlock"
	}
	return &Bundle{
		ID:     "arb_" + hex.EncodeToString(sum[:])[:12],
		Kind:   kind,
		Source: string(source),
	}, nil
}

func CompileFile(path string) (*Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy %s: %w", path, err)
	}
	bundle, err := Compile(data)
	if err != nil {
		return nil, err
	}
	bundle.Path = path
	return bundle, nil
}
