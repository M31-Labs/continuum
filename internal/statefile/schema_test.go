package statefile

import (
	"errors"
	"testing"
)

func TestMigrateSchemaRunsHooks(t *testing.T) {
	version := 1
	var migratedFrom []int
	err := MigrateSchema("test store", &version, 3, func(from int) error {
		migratedFrom = append(migratedFrom, from)
		return nil
	})
	if err != nil {
		t.Fatalf("MigrateSchema: %v", err)
	}
	if version != 3 || len(migratedFrom) != 2 || migratedFrom[0] != 1 || migratedFrom[1] != 2 {
		t.Fatalf("version=%d migrated=%+v", version, migratedFrom)
	}
}

func TestMigrateSchemaRejectsFutureVersion(t *testing.T) {
	version := 4
	if err := MigrateSchema("test store", &version, 3, nil); err == nil {
		t.Fatal("future schema version was accepted")
	}
}

func TestMigrateSchemaWrapsHookError(t *testing.T) {
	version := 1
	want := errors.New("bad migration")
	err := MigrateSchema("test store", &version, 2, func(int) error {
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("MigrateSchema error = %v", err)
	}
}
