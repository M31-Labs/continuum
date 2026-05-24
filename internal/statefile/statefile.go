package statefile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	DirMode  os.FileMode = 0700
	FileMode os.FileMode = 0600
)

func WriteJSON(path string, value any) error {
	return WithLock(path, func() error {
		return WriteJSONWithoutLock(path, value)
	})
}

// WriteJSONWithoutLock writes JSON using the atomic state-file protocol.
// Callers must already hold WithLock(path).
func WriteJSONWithoutLock(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return WriteWithoutLock(path, append(data, '\n'))
}

func Write(path string, data []byte) error {
	return WithLock(path, func() error {
		return WriteWithoutLock(path, data)
	})
}

// WriteWithoutLock writes bytes using the atomic state-file protocol.
// Callers must already hold WithLock(path).
func WriteWithoutLock(path string, data []byte) error {
	return WriteModeWithoutLock(path, data, FileMode)
}

func WriteMode(path string, data []byte, mode os.FileMode) error {
	return WithLock(path, func() error {
		return writeModeWithoutLock(path, data, mode)
	})
}

// WriteModeWithoutLock writes bytes with a custom mode using the atomic
// state-file protocol. Callers must already hold WithLock(path).
func WriteModeWithoutLock(path string, data []byte, mode os.FileMode) error {
	return writeModeWithoutLock(path, data, mode)
}

func writeModeWithoutLock(path string, data []byte, mode os.FileMode) error {
	if path == "" {
		return fmt.Errorf("state file path is required")
	}
	dir := filepath.Dir(path)
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("create temp state file %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	closed := false
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("chmod temp state file %s: %w", tmpPath, err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temp state file %s: %w", tmpPath, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp state file %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp state file %s: %w", tmpPath, err)
	}
	closed = true
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace state file %s: %w", path, err)
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	return nil
}

func OpenAppend(path string) (*os.File, error) {
	if path == "" {
		return nil, fmt.Errorf("state file path is required")
	}
	dir := filepath.Dir(path)
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, FileMode)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(FileMode); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, DirMode); err != nil {
		return fmt.Errorf("create state dir %s: %w", dir, err)
	}
	clean := filepath.Clean(dir)
	if clean == "." || clean == string(os.PathSeparator) {
		return nil
	}
	if err := os.Chmod(clean, DirMode); err != nil {
		return fmt.Errorf("chmod state dir %s: %w", dir, err)
	}
	return nil
}

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open state dir %s: %w", dir, err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync state dir %s: %w", dir, err)
	}
	return nil
}
