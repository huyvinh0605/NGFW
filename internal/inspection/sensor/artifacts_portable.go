//go:build !linux

package sensor

import "os"

// Ownership is enforced by the production Linux build. Portable builds keep
// hashing/mode tests available without pretending to validate Unix uid 0.
func validateRootOwner(os.FileInfo) error { return nil }
