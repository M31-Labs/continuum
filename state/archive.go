package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"m31labs.dev/continuum/airlock"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/internal/statefile"
	"m31labs.dev/continuum/policy"
	cruntime "m31labs.dev/continuum/runtime"
)

const ArchiveSchemaVersion = 1

const (
	ItemPolicyStore             = "policy_store"
	ItemGrantStore              = "grant_store"
	ItemDeliveryStore           = "delivery_store"
	ItemSessionStore            = "session_store"
	ItemAirlockStore            = "airlock_store"
	ItemAirlockAccumulatorStore = "airlock_accumulator_store"
	ItemIDStore                 = "id_store"
	ItemAuditLog                = "audit_log"
)

const (
	KindJSON  = "json"
	KindJSONL = "jsonl"
)

type Paths struct {
	PolicyStore             string
	GrantStore              string
	DeliveryStore           string
	SessionStore            string
	AirlockStore            string
	AirlockAccumulatorStore string
	IDStore                 string
	AuditLog                string
}

type Archive struct {
	SchemaVersion int       `json:"schema_version"`
	CreatedAt     time.Time `json:"created_at"`
	Tool          string    `json:"tool,omitempty"`
	Items         []Item    `json:"items"`
}

type Item struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Path   string `json:"path,omitempty"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
	Data   []byte `json:"data"`
}

type ExportOptions struct {
	Paths     Paths
	CreatedAt time.Time
	Strict    bool
}

type ExportReport struct {
	Items   int      `json:"items"`
	Bytes   int      `json:"bytes"`
	Missing []string `json:"missing,omitempty"`
}

type ImportOptions struct {
	Paths  Paths
	Now    time.Time
	Force  bool
	DryRun bool
}

type ImportReport struct {
	Items       []ImportItemReport `json:"items"`
	Imported    int                `json:"imported"`
	WouldImport int                `json:"would_import,omitempty"`
	Overwritten int                `json:"overwritten,omitempty"`
	DryRun      bool               `json:"dry_run,omitempty"`
}

type ImportItemReport struct {
	Name           string `json:"name"`
	Destination    string `json:"destination"`
	Bytes          int    `json:"bytes"`
	SHA256         string `json:"sha256"`
	WouldOverwrite bool   `json:"would_overwrite,omitempty"`
	Overwritten    bool   `json:"overwritten,omitempty"`
	BackupPath     string `json:"backup_path,omitempty"`
	Imported       bool   `json:"imported,omitempty"`
}

type itemSpec struct {
	name string
	kind string
	path string
}

func ExportArchive(opts ExportOptions) (Archive, ExportReport, error) {
	now := opts.CreatedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	archive := Archive{
		SchemaVersion: ArchiveSchemaVersion,
		CreatedAt:     now,
		Tool:          "continuum",
	}
	var report ExportReport
	for _, spec := range itemSpecs(opts.Paths) {
		if spec.path == "" {
			return Archive{}, ExportReport{}, fmt.Errorf("%s path is required", spec.name)
		}
		data, err := os.ReadFile(spec.path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				report.Missing = append(report.Missing, spec.name)
				if opts.Strict {
					return Archive{}, ExportReport{}, fmt.Errorf("%s state file %s does not exist", spec.name, spec.path)
				}
				continue
			}
			return Archive{}, ExportReport{}, fmt.Errorf("read %s state file %s: %w", spec.name, spec.path, err)
		}
		if err := validateItemBytes(spec.name, data); err != nil {
			return Archive{}, ExportReport{}, err
		}
		sum := sha256.Sum256(data)
		item := Item{
			Name:   spec.name,
			Kind:   spec.kind,
			Path:   spec.path,
			SHA256: hex.EncodeToString(sum[:]),
			Bytes:  len(data),
			Data:   append([]byte(nil), data...),
		}
		archive.Items = append(archive.Items, item)
		report.Items++
		report.Bytes += len(data)
	}
	if len(archive.Items) == 0 {
		return Archive{}, ExportReport{}, fmt.Errorf("no state files found to export")
	}
	return archive, report, nil
}

func ImportArchive(archive Archive, opts ImportOptions) (ImportReport, error) {
	if err := validateArchiveHeader(archive); err != nil {
		return ImportReport{}, err
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	destinations := itemDestinationMap(opts.Paths)
	report := ImportReport{DryRun: opts.DryRun}
	seen := map[string]bool{}
	for _, item := range archive.Items {
		if seen[item.Name] {
			return ImportReport{}, fmt.Errorf("archive contains duplicate item %q", item.Name)
		}
		seen[item.Name] = true
		spec, ok := itemSpecByName(opts.Paths, item.Name)
		if !ok {
			return ImportReport{}, fmt.Errorf("archive contains unknown item %q", item.Name)
		}
		if item.Kind != spec.kind {
			return ImportReport{}, fmt.Errorf("archive item %s has kind %q, expected %q", item.Name, item.Kind, spec.kind)
		}
		if err := verifyItem(item); err != nil {
			return ImportReport{}, err
		}
		if err := validateItemBytes(item.Name, item.Data); err != nil {
			return ImportReport{}, err
		}
		destination := destinations[item.Name]
		if destination == "" {
			return ImportReport{}, fmt.Errorf("%s destination path is required", item.Name)
		}
		exists, existing, err := readExisting(destination)
		if err != nil {
			return ImportReport{}, err
		}
		itemReport := ImportItemReport{
			Name:           item.Name,
			Destination:    destination,
			Bytes:          item.Bytes,
			SHA256:         item.SHA256,
			WouldOverwrite: exists,
		}
		if opts.DryRun {
			report.WouldImport++
			report.Items = append(report.Items, itemReport)
			continue
		}
		if exists && !opts.Force {
			return ImportReport{}, fmt.Errorf("%s destination %s exists; use --force to overwrite", item.Name, destination)
		}
		if exists {
			backupPath := preImportBackupPath(destination, now)
			if err := statefile.WriteMode(backupPath, existing, statefile.FileMode); err != nil {
				return ImportReport{}, fmt.Errorf("write pre-import backup %s: %w", backupPath, err)
			}
			itemReport.BackupPath = backupPath
			itemReport.Overwritten = true
			report.Overwritten++
		}
		if err := statefile.WriteMode(destination, item.Data, statefile.FileMode); err != nil {
			return ImportReport{}, fmt.Errorf("write %s destination %s: %w", item.Name, destination, err)
		}
		itemReport.Imported = true
		report.Imported++
		report.Items = append(report.Items, itemReport)
	}
	return report, nil
}

func WriteArchive(path string, archive Archive) error {
	if err := validateArchiveHeader(archive); err != nil {
		return err
	}
	return statefile.WriteJSON(path, archive)
}

func ReadArchive(path string) (Archive, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Archive{}, fmt.Errorf("read state archive %s: %w", path, err)
	}
	var archive Archive
	if err := json.Unmarshal(data, &archive); err != nil {
		return Archive{}, fmt.Errorf("parse state archive %s: %w", path, err)
	}
	if err := validateArchiveHeader(archive); err != nil {
		return Archive{}, fmt.Errorf("parse state archive %s: %w", path, err)
	}
	return archive, nil
}

func KnownItemNames() []string {
	names := []string{
		ItemPolicyStore,
		ItemGrantStore,
		ItemDeliveryStore,
		ItemSessionStore,
		ItemAirlockStore,
		ItemAirlockAccumulatorStore,
		ItemIDStore,
		ItemAuditLog,
	}
	slices.Sort(names)
	return names
}

func itemSpecs(paths Paths) []itemSpec {
	return []itemSpec{
		{name: ItemPolicyStore, kind: KindJSON, path: paths.PolicyStore},
		{name: ItemGrantStore, kind: KindJSON, path: paths.GrantStore},
		{name: ItemDeliveryStore, kind: KindJSON, path: paths.DeliveryStore},
		{name: ItemSessionStore, kind: KindJSON, path: paths.SessionStore},
		{name: ItemAirlockStore, kind: KindJSON, path: paths.AirlockStore},
		{name: ItemAirlockAccumulatorStore, kind: KindJSON, path: paths.AirlockAccumulatorStore},
		{name: ItemIDStore, kind: KindJSON, path: paths.IDStore},
		{name: ItemAuditLog, kind: KindJSONL, path: paths.AuditLog},
	}
}

func itemSpecByName(paths Paths, name string) (itemSpec, bool) {
	for _, spec := range itemSpecs(paths) {
		if spec.name == name {
			return spec, true
		}
	}
	return itemSpec{}, false
}

func itemDestinationMap(paths Paths) map[string]string {
	out := map[string]string{}
	for _, spec := range itemSpecs(paths) {
		out[spec.name] = spec.path
	}
	return out
}

func validateArchiveHeader(archive Archive) error {
	if archive.SchemaVersion <= 0 {
		return fmt.Errorf("state archive schema_version is required")
	}
	if archive.SchemaVersion > ArchiveSchemaVersion {
		return fmt.Errorf("state archive schema version %d is newer than supported version %d", archive.SchemaVersion, ArchiveSchemaVersion)
	}
	if len(archive.Items) == 0 {
		return fmt.Errorf("state archive contains no items")
	}
	return nil
}

func verifyItem(item Item) error {
	if item.Name == "" {
		return fmt.Errorf("archive item name is required")
	}
	if item.Kind == "" {
		return fmt.Errorf("archive item %s kind is required", item.Name)
	}
	if item.Bytes != len(item.Data) {
		return fmt.Errorf("archive item %s byte count %d does not match data length %d", item.Name, item.Bytes, len(item.Data))
	}
	sum := sha256.Sum256(item.Data)
	actual := hex.EncodeToString(sum[:])
	if item.SHA256 != actual {
		return fmt.Errorf("archive item %s sha256 mismatch: got %s expected %s", item.Name, actual, item.SHA256)
	}
	return nil
}

func validateItemBytes(name string, data []byte) error {
	dir, err := os.MkdirTemp("", "continuum-state-validate-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "state")
	if err := os.WriteFile(path, data, statefile.FileMode); err != nil {
		return err
	}
	switch name {
	case ItemPolicyStore:
		_, err = policy.LoadStore(path)
	case ItemGrantStore:
		_, err = capability.LoadGrantStore(path)
	case ItemDeliveryStore:
		_, err = cruntime.LoadDeliveryStore(path)
	case ItemSessionStore:
		_, err = cruntime.LoadSessionStore(path)
	case ItemAirlockStore:
		_, err = airlock.LoadStore(path)
	case ItemAirlockAccumulatorStore:
		_, err = airlock.LoadAccumulatorStore(path)
	case ItemIDStore:
		_, err = cruntime.LoadIDStore(path)
	case ItemAuditLog:
		_, err = audit.ReadJSONL(path)
	default:
		err = fmt.Errorf("unknown state item %q", name)
	}
	if err != nil {
		return fmt.Errorf("validate %s state bytes: %w", name, err)
	}
	return nil
}

func readExisting(path string) (bool, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("read existing state file %s: %w", path, err)
	}
	return true, data, nil
}

func preImportBackupPath(path string, now time.Time) string {
	return fmt.Sprintf("%s.preimport.%s", path, now.UTC().Format("20060102T150405.000000000Z"))
}
