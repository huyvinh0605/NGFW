package domain

import "errors"

// Shared across the store and IPC without making transports depend on storage.
var ErrRuntimeSessionNotFound = errors.New("runtime session not found")
