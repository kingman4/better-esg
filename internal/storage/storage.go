// Package storage provides an abstraction over file storage backends.
// The Store interface is implemented by local filesystem, S3, GCS, etc.
package storage

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
)

// ErrInvalidKey is returned when a storage key contains path traversal characters.
var ErrInvalidKey = errors.New("invalid storage key")

// validateKey rejects keys that could escape the base directory.
// Shared by all storage backends.
func validateKey(key string) error {
	if key == "" {
		return ErrInvalidKey
	}
	if strings.Contains(key, "..") {
		return ErrInvalidKey
	}
	if filepath.IsAbs(key) {
		return ErrInvalidKey
	}
	return nil
}

// ReadSeekCloser combines io.ReadSeeker and io.Closer.
// Returned by Store.Open so callers can both seek (e.g. for streaming uploads)
// and close the handle when done.
type ReadSeekCloser interface {
	io.ReadSeeker
	io.Closer
}

// Store is the interface for file storage backends.
type Store interface {
	// Save writes the contents of r to the given key.
	// Returns the number of bytes written.
	Save(ctx context.Context, key string, r io.Reader) (int64, error)

	// Open returns a seekable reader for the stored file at key.
	// The caller must close the returned ReadSeekCloser.
	Open(ctx context.Context, key string) (ReadSeekCloser, error)

	// Delete removes the file at key. Returns nil if the file does not exist.
	Delete(ctx context.Context, key string) error
}
