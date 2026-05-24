//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package statefile

import (
	"fmt"
	"os"
	"syscall"
)

func lockFile(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock state file %s: %w", f.Name(), err)
	}
	return nil
}

func unlockFile(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("unlock state file %s: %w", f.Name(), err)
	}
	return nil
}
