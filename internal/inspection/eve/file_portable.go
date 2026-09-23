//go:build !linux

package eve

import "os"

func fileGeneration(info os.FileInfo) string { return portableGeneration(info) }
