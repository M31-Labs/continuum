//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package statefile

import "os"

func lockFile(_ *os.File) error {
	return nil
}

func unlockFile(_ *os.File) error {
	return nil
}
