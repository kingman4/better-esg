package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// LocalStore implements Store using the local filesystem.
type LocalStore struct {
	baseDir string
}

// NewLocalStore creates a LocalStore rooted at baseDir.
// Creates the directory if it does not exist.
func NewLocalStore(baseDir string) (*LocalStore, error) {
	abs, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("resolving storage path: %w", err)
	}
	if err := os.MkdirAll(abs, 0o750); err != nil {
		return nil, fmt.Errorf("creating storage directory: %w", err)
	}
	return &LocalStore{baseDir: abs}, nil
}

// Save writes the contents of r to {baseDir}/{key}.
// Uses a temp file + rename for atomic writes.
func (s *LocalStore) Save(_ context.Context, key string, r io.Reader) (int64, error) {
	if err := validateKey(key); err != nil {
		return 0, err
	}

	fullPath := filepath.Join(s.baseDir, filepath.FromSlash(key))

	// Ensure parent directory exists
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return 0, fmt.Errorf("creating directory %s: %w", dir, err)
	}

	// Write to temp file in the same directory (same filesystem for rename)
	tmp, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		return 0, fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()

	n, err := io.Copy(tmp, r)
	if closeErr := tmp.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(tmpPath)
		return 0, fmt.Errorf("writing file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, fullPath); err != nil {
		os.Remove(tmpPath)
		return 0, fmt.Errorf("finalizing file: %w", err)
	}

	return n, nil
}

// Open returns a seekable reader for the file at {baseDir}/{key}.
func (s *LocalStore) Open(_ context.Context, key string) (ReadSeekCloser, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	fullPath := filepath.Join(s.baseDir, filepath.FromSlash(key))
	f, err := os.Open(fullPath)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	return f, nil
}

// Delete removes the file at {baseDir}/{key}. Returns nil if the file does not exist.
func (s *LocalStore) Delete(_ context.Context, key string) error {
	if err := validateKey(key); err != nil {
		return err
	}
	fullPath := filepath.Join(s.baseDir, filepath.FromSlash(key))
	if err := os.Remove(fullPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("deleting file: %w", err)
	}
	return nil
}
