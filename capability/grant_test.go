package capability

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"m31labs.dev/continuum/subject"
)

func TestGrantExpiryAndRevocation(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	grant := Grant{CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if !grant.Active(now.Add(30 * time.Second)) {
		t.Fatal("grant should be active before expiry")
	}
	if grant.Active(now.Add(time.Minute)) {
		t.Fatal("grant should not be active at expiry")
	}
	grant.ExpiresAt = now.Add(time.Hour)
	grant.RevokedAt = now.Add(time.Second)
	if grant.Active(now.Add(2 * time.Second)) {
		t.Fatal("revoked grant should not be active")
	}
}

func TestGrantStorePersistsAndFilters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.json")
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	store := &GrantStore{}
	active := Grant{ID: "grant_1", Session: "s1", Capability: "network.connect", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	expired := Grant{ID: "grant_2", Session: "s1", Capability: "network.connect", CreatedAt: now, ExpiresAt: now.Add(-time.Hour)}
	if err := store.Add(active); err != nil {
		t.Fatalf("Add active: %v", err)
	}
	if err := store.Add(expired); err != nil {
		t.Fatalf("Add expired: %v", err)
	}
	if got := store.Active(now); len(got) != 1 || got[0].ID != "grant_1" {
		t.Fatalf("active grants = %+v", got)
	}
	if _, err := store.Revoke("grant_1", now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got := store.Active(now); len(got) != 0 {
		t.Fatalf("active after revoke = %+v", got)
	}
	if err := store.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	reloaded, err := LoadGrantStore(path)
	if err != nil {
		t.Fatalf("LoadGrantStore: %v", err)
	}
	if len(reloaded.Grants) != 2 {
		t.Fatalf("reloaded grants = %+v", reloaded.Grants)
	}
	if removed := reloaded.PruneExpired(now); removed != 1 {
		t.Fatalf("removed = %d", removed)
	}
}

func TestGrantStoreSchemaMigration(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "legacy-grants.json")
	if err := os.WriteFile(legacyPath, []byte(`{"grants":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	legacy, err := LoadGrantStore(legacyPath)
	if err != nil {
		t.Fatalf("LoadGrantStore legacy: %v", err)
	}
	if legacy.SchemaVersion != GrantStoreSchemaVersion {
		t.Fatalf("legacy schema version = %d", legacy.SchemaVersion)
	}
	futurePath := filepath.Join(dir, "future-grants.json")
	if err := os.WriteFile(futurePath, []byte(`{"schema_version":99,"grants":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGrantStore(futurePath); err == nil {
		t.Fatal("future grant store schema loaded without error")
	}
}

func TestGrantStoreRenewExtendsActiveGrant(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	store := &GrantStore{}
	grant := Grant{ID: "grant_1", Session: "s1", Capability: "network.connect", Reason: "fetch", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err := store.Add(grant); err != nil {
		t.Fatalf("Add: %v", err)
	}
	renewed, err := store.Renew("grant_1", 5*time.Minute, "dependency update still running", now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if !renewed.ExpiresAt.Equal(now.Add(30*time.Second).Add(5*time.Minute)) || len(renewed.Renewals) != 1 {
		t.Fatalf("renewed grant = %+v", renewed)
	}
	if renewed.Renewals[0].Reason != "dependency update still running" || !renewed.Renewals[0].PreviousExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("renewal = %+v", renewed.Renewals[0])
	}
	if _, err := store.Renew("grant_1", time.Second, "too short", now.Add(time.Minute)); err == nil {
		t.Fatal("short renewal succeeded")
	}
	if _, err := store.Revoke("grant_1", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := store.Renew("grant_1", time.Hour, "revoked", now.Add(3*time.Minute)); err == nil {
		t.Fatal("revoked grant renewal succeeded")
	}
}

func TestUpdateGrantStoreSerializesMutations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.json")
	started := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- UpdateGrantStore(path, func(store *GrantStore) error {
			if err := store.Add(Grant{ID: "grant_1", Session: "s1", Capability: "network.connect"}); err != nil {
				return err
			}
			close(started)
			<-release
			return nil
		})
	}()
	<-started

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- UpdateGrantStore(path, func(store *GrantStore) error {
			return store.Add(Grant{ID: "grant_2", Session: "s2", Capability: "file.read"})
		})
	}()

	select {
	case err := <-secondDone:
		t.Fatalf("second update completed while first held lock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first update: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second update: %v", err)
	}
	reloaded, err := LoadGrantStore(path)
	if err != nil {
		t.Fatalf("LoadGrantStore: %v", err)
	}
	if len(reloaded.Grants) != 2 {
		t.Fatalf("grants = %+v", reloaded.Grants)
	}
}

func TestGrantFactAndNetworkMatch(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	grant := Grant{
		ID:         "grant_1",
		Session:    "agent-42",
		Capability: "network.connect",
		Scope:      map[string]any{"host": "github.com", "port": 443},
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Minute),
	}
	if !grant.MatchesNetwork("agent-42", "github.com", 443, now) {
		t.Fatal("expected network grant match")
	}
	if grant.MatchesNetwork("agent-42", "169.254.169.254", 80, now) {
		t.Fatal("unexpected metadata grant match")
	}
	fact := grant.Fact(structSubject("agent-42"))
	if fact.Type != "CapabilityGrant" || fact.Fields["id"] != "grant_1" {
		t.Fatalf("fact = %+v", fact)
	}
}

func TestGrantFileAndProcessMatch(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	fileGrant := Grant{
		ID:         "grant_file",
		Session:    "agent-42",
		Capability: "file.write",
		Scope:      map[string]any{"path": "/repo/.github/workflows/test.yml", "op": "write"},
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Minute),
	}
	if !fileGrant.MatchesFile("agent-42", "/repo/.github/workflows/test.yml", "write", now) {
		t.Fatal("expected file grant match")
	}
	if fileGrant.MatchesFile("agent-42", "/repo/.ssh/id_ed25519", "write", now) {
		t.Fatal("unexpected file grant match")
	}
	processGrant := Grant{
		ID:         "grant_proc",
		Session:    "agent-42",
		Capability: "process.exec",
		Scope:      map[string]any{"comm": "go"},
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Minute),
	}
	if !processGrant.MatchesProcess("agent-42", "/usr/local/go/bin/go", "go test ./...", now) {
		t.Fatal("expected process grant match")
	}
	if processGrant.MatchesProcess("agent-42", "bash", "bash", now) {
		t.Fatal("unexpected process grant match")
	}
}

func structSubject(session string) subject.Subject {
	return subject.Subject{Kind: "agent", Session: session}
}
