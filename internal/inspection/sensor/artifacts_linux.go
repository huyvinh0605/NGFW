//go:build linux

package sensor

import (
	"errors"
	"os"
	"syscall"
)

func validateRootOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("file ownership metadata unavailable")
	}
	if stat.Uid != 0 {
		return errors.New("file must be owned by root")
	}
	return nil
}
