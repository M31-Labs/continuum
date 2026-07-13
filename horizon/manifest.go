package horizon

import (
	"encoding/json"
	"fmt"

	"m31labs.dev/continuum/capability"
)

const SchemaV0 = "m31labs.dev/horizon/capability/v0"
const SchemaV1 = "m31labs.dev/horizon/capability/v1"

type Manifest struct {
	Schema       string               `json:"schema,omitempty"`
	Package      string               `json:"package,omitempty"`
	Programs     []Program            `json:"programs,omitempty"`
	Capabilities []DeclaredCapability `json:"capabilities,omitempty"`
	Maps         []Map                `json:"maps,omitempty"`

	Name        string                   `json:"name,omitempty"`
	Kind        capability.Kind          `json:"kind,omitempty"`
	Danger      capability.Danger        `json:"danger,omitempty"`
	Program     string                   `json:"program,omitempty"`
	Section     string                   `json:"section,omitempty"`
	Emits       string                   `json:"emits,omitempty"`
	Consumes    string                   `json:"consumes,omitempty"`
	Backend     string                   `json:"backend,omitempty"`
	Description string                   `json:"description,omitempty"`
	Requires    []capability.Requirement `json:"requires,omitempty"`
}

type Program struct {
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	Attach       string   `json:"attach"`
	Section      string   `json:"section"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type DeclaredCapability struct {
	Name         string            `json:"name"`
	Kind         capability.Kind   `json:"kind"`
	Danger       capability.Danger `json:"danger"`
	Program      string            `json:"program"`
	Section      string            `json:"section"`
	Emits        string            `json:"emits,omitempty"`
	Maps         MapAccess         `json:"maps"`
	Axes         *DangerAxes       `json:"-"`
	Requirements Requirements      `json:"requirements,omitempty"`
}

type DangerAxes struct {
	Mode          string `json:"mode"`
	Scope         string `json:"scope"`
	Reversibility string `json:"reversibility"`
}

type Requirements struct {
	MinKernel   string               `json:"min_kernel,omitempty"`
	Programs    []FeatureRequirement `json:"programs,omitempty"`
	Maps        []FeatureRequirement `json:"maps,omitempty"`
	Helpers     []FeatureRequirement `json:"helpers,omitempty"`
	Permissions []string             `json:"permissions,omitempty"`
	Features    []string             `json:"features,omitempty"`
}

type FeatureRequirement struct {
	Name      string `json:"name"`
	MinKernel string `json:"min_kernel,omitempty"`
}

func (c *DeclaredCapability) UnmarshalJSON(data []byte) error {
	type wire struct {
		Name         string          `json:"name"`
		Kind         capability.Kind `json:"kind"`
		Danger       json.RawMessage `json:"danger"`
		Program      string          `json:"program"`
		Section      string          `json:"section"`
		Emits        string          `json:"emits,omitempty"`
		Maps         MapAccess       `json:"maps"`
		Requirements Requirements    `json:"requirements,omitempty"`
	}
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*c = DeclaredCapability{Name: decoded.Name, Kind: decoded.Kind, Program: decoded.Program, Section: decoded.Section, Emits: decoded.Emits, Maps: decoded.Maps, Requirements: decoded.Requirements}
	if len(decoded.Danger) == 0 {
		return nil
	}
	if decoded.Danger[0] == '"' {
		return json.Unmarshal(decoded.Danger, &c.Danger)
	}
	var axes DangerAxes
	if err := json.Unmarshal(decoded.Danger, &axes); err != nil {
		return fmt.Errorf("decode capability %s danger: %w", decoded.Name, err)
	}
	c.Axes = &axes
	c.Danger = continuumDanger(axes)
	return nil
}

type MapAccess struct {
	Read   []string `json:"read"`
	Write  []string `json:"write"`
	Events []string `json:"events"`
}

type Map struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Value string `json:"value,omitempty"`
}

func (m Manifest) ContinuumCapabilities() ([]capability.Capability, error) {
	if m.Schema == "" {
		cap := m.legacyCapability()
		if err := capability.Validate(cap); err != nil {
			return nil, err
		}
		return []capability.Capability{cap}, nil
	}
	if m.Schema != SchemaV0 && m.Schema != SchemaV1 {
		return nil, fmt.Errorf("unsupported horizon capability schema %q", m.Schema)
	}
	if m.Package == "" {
		return nil, fmt.Errorf("horizon capability manifest package is required")
	}
	caps := make([]capability.Capability, 0, len(m.Capabilities))
	for _, declared := range m.Capabilities {
		cap := declared.ContinuumCapability(m)
		if err := capability.Validate(cap); err != nil {
			return nil, err
		}
		caps = append(caps, cap)
	}
	return caps, nil
}

func (m Manifest) Capability() capability.Capability {
	return m.legacyCapability()
}

func (m Manifest) legacyCapability() capability.Capability {
	cap := capability.Capability{
		Name:        m.Name,
		Kind:        m.Kind,
		Owner:       "horizon",
		Danger:      m.Danger,
		Program:     m.Program,
		Section:     m.Section,
		Backend:     m.Backend,
		Description: m.Description,
		Requires:    append([]capability.Requirement(nil), m.Requires...),
	}
	switch m.Kind {
	case capability.KindSource:
		cap.Output = m.Emits
	case capability.KindSink, capability.KindWorker:
		cap.Input = m.Consumes
	}
	return cap
}

func (c DeclaredCapability) ContinuumCapability(manifest Manifest) capability.Capability {
	output := c.Emits
	if output == "" && c.Kind == capability.KindSource {
		output = "KernelEvent"
	}
	cap := capability.Capability{
		Name:    c.Name,
		Kind:    c.Kind,
		Owner:   "horizon",
		Danger:  c.Danger,
		Program: c.Program,
		Section: c.Section,
		Metadata: map[string]any{
			"horizon.schema":         manifest.Schema,
			"horizon.package":        manifest.Package,
			"horizon.maps.read":      cloneStrings(c.Maps.Read),
			"horizon.maps.write":     cloneStrings(c.Maps.Write),
			"horizon.maps.events":    cloneStrings(c.Maps.Events),
			"horizon.program.attach": programAttach(manifest, c.Program),
		},
	}
	if c.Axes != nil {
		cap.Metadata["horizon.danger.mode"] = c.Axes.Mode
		cap.Metadata["horizon.danger.scope"] = c.Axes.Scope
		cap.Metadata["horizon.danger.reversibility"] = c.Axes.Reversibility
	}
	cap.Requires = continuumRequirements(c.Requirements)
	switch c.Kind {
	case capability.KindSource:
		cap.Output = output
	case capability.KindSink, capability.KindWorker:
		cap.Input = c.Emits
	}
	return cap
}

func continuumDanger(axes DangerAxes) capability.Danger {
	switch axes.Mode {
	case "observe":
		return capability.DangerObserve
	case "mutate":
		return capability.DangerSoftControl
	case "control":
		return capability.DangerEnforcement
	default:
		return capability.DangerPrivileged
	}
}

func continuumRequirements(requirements Requirements) []capability.Requirement {
	var out []capability.Requirement
	add := func(name, reason string) {
		if name != "" {
			out = append(out, capability.Requirement{Name: name, Reason: reason})
		}
	}
	if requirements.MinKernel != "" {
		add("kernel>="+requirements.MinKernel, "Horizon minimum kernel")
	}
	for _, item := range requirements.Programs {
		add("program:"+item.Name, item.MinKernel)
	}
	for _, item := range requirements.Maps {
		add("map:"+item.Name, item.MinKernel)
	}
	for _, item := range requirements.Helpers {
		add("helper:"+item.Name, item.MinKernel)
	}
	for _, item := range requirements.Permissions {
		add("permission:"+item, "Horizon load permission")
	}
	for _, item := range requirements.Features {
		add("feature:"+item, "Horizon kernel feature")
	}
	return out
}

func programAttach(manifest Manifest, name string) string {
	for _, program := range manifest.Programs {
		if program.Name == name {
			return program.Attach
		}
	}
	return ""
}

func cloneStrings(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	return out
}
