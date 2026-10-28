package dataplane

import (
	"strings"
)

func isIPObjectNotFound(output string) bool {
	message := strings.ToLower(output)
	return strings.Contains(message, "cannot find device") ||
		strings.Contains(message, "does not exist") ||
		strings.Contains(message, "no such process") ||
		strings.Contains(message, "cannot find") ||
		strings.Contains(message, "cannot assign requested address") ||
		strings.Contains(message, "address not found")
}
