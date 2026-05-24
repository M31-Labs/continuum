package statefile

import "fmt"

func MigrateSchema(storeName string, version *int, current int, migrate func(from int) error) error {
	if storeName == "" {
		storeName = "state store"
	}
	if version == nil {
		return fmt.Errorf("%s schema version pointer is nil", storeName)
	}
	if current <= 0 {
		return fmt.Errorf("%s current schema version must be positive", storeName)
	}
	if *version < 0 {
		return fmt.Errorf("%s schema version %d is invalid", storeName, *version)
	}
	if *version > current {
		return fmt.Errorf("%s schema version %d is newer than supported version %d", storeName, *version, current)
	}
	if *version == 0 {
		*version = 1
	}
	for *version < current {
		if migrate == nil {
			return fmt.Errorf("%s schema version %d has no migration hook", storeName, *version)
		}
		if err := migrate(*version); err != nil {
			return fmt.Errorf("migrate %s schema version %d: %w", storeName, *version, err)
		}
		*version++
	}
	return nil
}
