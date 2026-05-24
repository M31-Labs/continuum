package statefile

import (
	"fmt"
	"os"
	"path/filepath"
)

// WithLock holds an exclusive advisory lock for the state file path while fn
// runs. The lock file is stored beside the state file and has private perms.
func WithLock(path string, fn func() error) error {
	if path == "" {
		return fmt.Errorf("state file path is required")
	}
	if fn == nil {
		return fmt.Errorf("state lock callback is required")
	}
	dir := filepath.Dir(path)
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	lockPath := filepath.Join(dir, "."+filepath.Base(path)+".lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, FileMode)
	if err != nil {
		return fmt.Errorf("open state lock %s: %w", lockPath, err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
	}()
	if err := f.Chmod(FileMode); err != nil {
		return fmt.Errorf("chmod state lock %s: %w", lockPath, err)
	}
	if err := lockFile(f); err != nil {
		return err
	}
	defer func() {
		_ = unlockFile(f)
		_ = f.Close()
		closed = true
	}()
	return fn()
}
