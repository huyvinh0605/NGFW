//go:build linux

package eve

import (
	"fmt"
	"os"
	"syscall"
)

func fileGeneration(info os.FileInfo) string {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
	}
	return portableGeneration(info)
}
