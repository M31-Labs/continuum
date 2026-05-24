package horizon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"m31labs.dev/continuum/capability"
)

type ArtifactKind string

const (
	ArtifactHZNSource          ArtifactKind = "hzn-source"
	ArtifactCapabilityManifest ArtifactKind = "capability-manifest"
	ArtifactExportedPackage    ArtifactKind = "exported-package"
	ArtifactBPFObject          ArtifactKind = "bpf-object"
	ArtifactBPFSource          ArtifactKind = "bpf-source"
	ArtifactGoBinding          ArtifactKind = "go-binding"
	ArtifactUnknown            ArtifactKind = "unknown"
)

type ArtifactRef struct {
	Path   string       `json:"path"`
	Kind   ArtifactKind `json:"kind"`
	SHA256 string       `json:"sha256,omitempty"`
	Size   int64        `json:"size,omitempty"`
}

type ArtifactInspection struct {
	Path         string                  `json:"path"`
	Kind         ArtifactKind            `json:"kind"`
	NeedsExport  bool                    `json:"needs_export,omitempty"`
	Message      string                  `json:"message,omitempty"`
	Artifacts    []ArtifactRef           `json:"artifacts,omitempty"`
	Capabilities []capability.Capability `json:"capabilities,omitempty"`
}

func InspectPath(path string) (ArtifactInspection, error) {
	if strings.TrimSpace(path) == "" {
		return ArtifactInspection{}, fmt.Errorf("artifact path is required")
	}
	clean := filepath.Clean(path)
	info, err := os.Stat(clean)
	if err != nil {
		return ArtifactInspection{}, err
	}
	if info.IsDir() {
		return inspectPackageDir(clean)
	}
	kind := artifactKindForPath(clean)
	switch kind {
	case ArtifactHZNSource:
		ref, err := artifactRef(clean, kind)
		if err != nil {
			return ArtifactInspection{}, err
		}
		return ArtifactInspection{
			Path:        clean,
			Kind:        kind,
			NeedsExport: true,
			Message:     ".hzn source must be exported by Horizon before Continuum can register capabilities",
			Artifacts:   []ArtifactRef{ref},
		}, nil
	case ArtifactCapabilityManifest:
		return inspectManifestFile(clean, nil)
	case ArtifactBPFObject, ArtifactBPFSource, ArtifactGoBinding:
		ref, err := artifactRef(clean, kind)
		if err != nil {
			return ArtifactInspection{}, err
		}
		return ArtifactInspection{
			Path:      clean,
			Kind:      kind,
			Message:   "compiled/exported artifact recorded as metadata; Continuum does not load eBPF programs",
			Artifacts: []ArtifactRef{ref},
		}, nil
	default:
		ref, err := artifactRef(clean, kind)
		if err != nil {
			return ArtifactInspection{}, err
		}
		return ArtifactInspection{Path: clean, Kind: kind, Artifacts: []ArtifactRef{ref}}, nil
	}
}

func inspectPackageDir(dir string) (ArtifactInspection, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ArtifactInspection{}, err
	}
	var artifacts []ArtifactRef
	var caps []capability.Capability
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		kind := artifactKindForPath(path)
		switch kind {
		case ArtifactCapabilityManifest:
			inspection, err := inspectManifestFile(path, nil)
			if err != nil {
				return ArtifactInspection{}, err
			}
			artifacts = append(artifacts, inspection.Artifacts...)
			caps = append(caps, annotateCapabilities(inspection.Capabilities, dir, inspection.Artifacts)...)
		case ArtifactHZNSource, ArtifactBPFObject, ArtifactBPFSource, ArtifactGoBinding:
			ref, err := artifactRef(path, kind)
			if err != nil {
				return ArtifactInspection{}, err
			}
			artifacts = append(artifacts, ref)
		}
	}
	if len(caps) == 0 && len(artifacts) == 0 {
		return ArtifactInspection{}, fmt.Errorf("no Horizon capability artifacts found in %s", dir)
	}
	slices.SortFunc(artifacts, func(a, b ArtifactRef) int {
		return strings.Compare(a.Path, b.Path)
	})
	caps = annotateCapabilities(caps, dir, artifacts)
	return ArtifactInspection{
		Path:         dir,
		Kind:         ArtifactExportedPackage,
		Message:      "Horizon exported package inspected; Continuum registers declarations and records artifacts only",
		Artifacts:    artifacts,
		Capabilities: caps,
	}, nil
}

func inspectManifestFile(path string, packageArtifacts []ArtifactRef) (ArtifactInspection, error) {
	ref, err := artifactRef(path, ArtifactCapabilityManifest)
	if err != nil {
		return ArtifactInspection{}, err
	}
	manifest, err := LoadFile(path)
	if err != nil {
		return ArtifactInspection{}, err
	}
	caps, err := manifest.ContinuumCapabilities()
	if err != nil {
		return ArtifactInspection{}, err
	}
	artifacts := append([]ArtifactRef{ref}, packageArtifacts...)
	caps = annotateCapabilities(caps, filepath.Dir(path), artifacts)
	return ArtifactInspection{
		Path:         path,
		Kind:         ArtifactCapabilityManifest,
		Message:      "Horizon capability manifest inspected; Continuum registers declarations only",
		Artifacts:    artifacts,
		Capabilities: caps,
	}, nil
}

func annotateCapabilities(caps []capability.Capability, packageDir string, artifacts []ArtifactRef) []capability.Capability {
	out := make([]capability.Capability, len(caps))
	for i, cap := range caps {
		out[i] = cap
		metadata := map[string]any{}
		for key, value := range cap.Metadata {
			metadata[key] = value
		}
		if packageDir != "" {
			metadata["continuum.horizon.package_dir"] = packageDir
		}
		metadata["continuum.horizon.artifacts"] = artifacts
		metadata["continuum.horizon.boundary"] = "declarations-only"
		out[i].Metadata = metadata
	}
	return out
}

func artifactKindForPath(path string) ArtifactKind {
	switch {
	case strings.HasSuffix(path, ".hzn"):
		return ArtifactHZNSource
	case strings.HasSuffix(path, ".cap.json"):
		return ArtifactCapabilityManifest
	case strings.HasSuffix(path, ".bpf.o"):
		return ArtifactBPFObject
	case strings.HasSuffix(path, ".bpf.c"):
		return ArtifactBPFSource
	case strings.HasSuffix(path, ".go"):
		return ArtifactGoBinding
	default:
		return ArtifactUnknown
	}
}

func artifactRef(path string, kind ArtifactKind) (ArtifactRef, error) {
	f, err := os.Open(path)
	if err != nil {
		return ArtifactRef{}, err
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return ArtifactRef{}, err
	}
	return ArtifactRef{
		Path:   filepath.Clean(path),
		Kind:   kind,
		SHA256: hex.EncodeToString(h.Sum(nil)),
		Size:   size,
	}, nil
}
