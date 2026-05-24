package state

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"m31labs.dev/continuum/airlock"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/policy"
	cruntime "m31labs.dev/continuum/runtime"
	"m31labs.dev/continuum/subject"
)

func TestExportImportArchive(t *testing.T) {
	now := time.Date(2026, 5, 24, 3, 0, 0, 0, time.UTC)
	src := testPaths(t.TempDir())
	writeStateFixtures(t, src, now)

	archive, exported, err := ExportArchive(ExportOptions{Paths: src, CreatedAt: now})
	if err != nil {
		t.Fatalf("ExportArchive: %v", err)
	}
	if exported.Items != 7 || exported.Bytes == 0 || len(exported.Missing) != 0 {
		t.Fatalf("exported report = %+v", exported)
	}

	dst := testPaths(t.TempDir())
	dryRun, err := ImportArchive(archive, ImportOptions{Paths: dst, DryRun: true})
	if err != nil {
		t.Fatalf("ImportArchive dry-run: %v", err)
	}
	if dryRun.WouldImport != 7 || dryRun.Imported != 0 {
		t.Fatalf("dry-run report = %+v", dryRun)
	}
	if _, err := os.Stat(dst.GrantStore); !os.IsNotExist(err) {
		t.Fatalf("dry-run created grant store: %v", err)
	}

	imported, err := ImportArchive(archive, ImportOptions{Paths: dst, Now: now})
	if err != nil {
		t.Fatalf("ImportArchive: %v", err)
	}
	if imported.Imported != 7 || imported.Overwritten != 0 {
		t.Fatalf("imported report = %+v", imported)
	}
	grants, err := capability.LoadGrantStore(dst.GrantStore)
	if err != nil {
		t.Fatalf("LoadGrantStore dst: %v", err)
	}
	if len(grants.Grants) != 1 || grants.Grants[0].ID != "grant_1" {
		t.Fatalf("imported grants = %+v", grants.Grants)
	}
	events, err := audit.ReadJSONL(dst.AuditLog)
	if err != nil {
		t.Fatalf("ReadJSONL dst: %v", err)
	}
	if len(events) != 1 || events[0].ID != "evt_1" {
		t.Fatalf("imported audit events = %+v", events)
	}

	if _, err := ImportArchive(archive, ImportOptions{Paths: dst, Now: now}); err == nil || !strings.Contains(err.Error(), "use --force") {
		t.Fatalf("ImportArchive without force error = %v", err)
	}
	forced, err := ImportArchive(archive, ImportOptions{Paths: dst, Now: now, Force: true})
	if err != nil {
		t.Fatalf("ImportArchive force: %v", err)
	}
	if forced.Imported != 7 || forced.Overwritten != 7 {
		t.Fatalf("forced report = %+v", forced)
	}
	if forced.Items[0].BackupPath == "" {
		t.Fatalf("forced report missing backup path: %+v", forced.Items)
	}
}

func TestImportArchiveRejectsTamperedItem(t *testing.T) {
	now := time.Date(2026, 5, 24, 3, 0, 0, 0, time.UTC)
	src := testPaths(t.TempDir())
	writeStateFixtures(t, src, now)
	archive, _, err := ExportArchive(ExportOptions{Paths: src, CreatedAt: now})
	if err != nil {
		t.Fatalf("ExportArchive: %v", err)
	}
	archive.Items[0].Data[0] ^= 1
	if _, err := ImportArchive(archive, ImportOptions{Paths: testPaths(t.TempDir())}); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("ImportArchive tampered error = %v", err)
	}
}

func testPaths(dir string) Paths {
	return Paths{
		PolicyStore:   filepath.Join(dir, "policies.json"),
		GrantStore:    filepath.Join(dir, "grants.json"),
		DeliveryStore: filepath.Join(dir, "deliveries.json"),
		SessionStore:  filepath.Join(dir, "sessions.json"),
		AirlockStore:  filepath.Join(dir, "airlock.json"),
		IDStore:       filepath.Join(dir, "ids.json"),
		AuditLog:      filepath.Join(dir, "audit.jsonl"),
	}
}

func writeStateFixtures(t *testing.T, paths Paths, now time.Time) {
	t.Helper()
	policies := &policy.Store{
		SchemaVersion: policy.StoreSchemaVersion,
		Path:          paths.PolicyStore,
		Active:        "agent-workdir",
		Bundles: map[string]policy.StoredBundle{
			"agent-workdir": {
				Name:      "agent-workdir",
				ID:        "policy_1",
				Kind:      "policy",
				Path:      "policies/main.arb",
				Published: now,
			},
		},
	}
	if err := policies.Save(); err != nil {
		t.Fatalf("policy Save: %v", err)
	}
	grants := &capability.GrantStore{
		SchemaVersion: capability.GrantStoreSchemaVersion,
		Grants: []capability.Grant{{
			ID:         "grant_1",
			Session:    "agent-session-1",
			Capability: "network.connect",
			Scope:      map[string]any{"host": "github.com", "port": 443},
			Reason:     "fetch dependency",
			CreatedAt:  now,
			ExpiresAt:  now.Add(time.Hour),
		}},
	}
	if err := grants.Save(paths.GrantStore); err != nil {
		t.Fatalf("grant Save: %v", err)
	}
	deliveries, err := cruntime.LoadDeliveryStore(paths.DeliveryStore)
	if err != nil {
		t.Fatalf("LoadDeliveryStore: %v", err)
	}
	if _, err := deliveries.Enqueue(cruntime.DeliveryItem{ID: "delivery_1", AuditID: "evt_1", Capability: "observe.audit", Status: cruntime.DeliveryPending, CreatedAt: now}); err != nil {
		t.Fatalf("delivery Enqueue: %v", err)
	}
	if err := deliveries.Save(); err != nil {
		t.Fatalf("delivery Save: %v", err)
	}
	sessions := &cruntime.SessionStore{
		SchemaVersion: cruntime.SessionStoreSchemaVersion,
		Sessions: []cruntime.Session{{
			ID:        "agent-session-1",
			Subject:   subject.Subject{Kind: "agent", Session: "agent-session-1", AgentName: "claude"},
			State:     cruntime.SessionRunning,
			StartedAt: now,
		}},
	}
	if err := sessions.Save(paths.SessionStore); err != nil {
		t.Fatalf("session Save: %v", err)
	}
	airlocks := airlock.NewStore()
	if _, err := airlocks.Enter("airlock-1", subject.Subject{Kind: "process", ID: "demo"}, "worm-like fanout", now); err != nil {
		t.Fatalf("airlock Enter: %v", err)
	}
	if err := airlocks.Save(paths.AirlockStore); err != nil {
		t.Fatalf("airlock Save: %v", err)
	}
	ids := &cruntime.IDStore{SchemaVersion: cruntime.IDStoreSchemaVersion, Counters: map[string]uint64{"evt": 3, "grant": 1}}
	if err := ids.Save(paths.IDStore); err != nil {
		t.Fatalf("id Save: %v", err)
	}
	sink, err := audit.NewJSONLSink(paths.AuditLog)
	if err != nil {
		t.Fatalf("NewJSONLSink: %v", err)
	}
	if err := sink.Write(context.Background(), audit.Event{ID: "evt_1", Time: now, Decision: "allow", Reason: "fixture"}); err != nil {
		t.Fatalf("audit Write: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("audit Close: %v", err)
	}
}
