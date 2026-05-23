package horizon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"m31labs.dev/continuum/capability"
)

func LoadFile(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest %s: %w", path, err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest %s: %w", path, err)
	}
	if _, err := manifest.ContinuumCapabilities(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func LoadDir(dir string) ([]capability.Capability, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read manifest dir %s: %w", dir, err)
	}
	var caps []capability.Capability
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".cap.json") {
			continue
		}
		manifest, err := LoadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		manifestCaps, err := manifest.ContinuumCapabilities()
		if err != nil {
			return nil, err
		}
		caps = append(caps, manifestCaps...)
	}
	slices.SortFunc(caps, func(a, b capability.Capability) int {
		return strings.Compare(a.Name, b.Name)
	})
	return caps, nil
}
