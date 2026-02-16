package storage

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func tempStore(t *testing.T) *LocalStore {
	t.Helper()
	dir := t.TempDir()
	s, err := NewLocalStore(dir)
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	return s
}

func TestLocalStore_SaveAndOpen(t *testing.T) {
	store := tempStore(t)
	ctx := context.Background()

	data := []byte("hello FDA submission content")
	n, err := store.Save(ctx, "test-file.txt", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	if n != int64(len(data)) {
		t.Errorf("expected %d bytes written, got %d", len(data), n)
	}

	rc, err := store.Open(ctx, "test-file.txt")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("content mismatch: got %q, want %q", got, data)
	}
}

func TestLocalStore_SaveCreatesSubdirs(t *testing.T) {
	store := tempStore(t)
	ctx := context.Background()

	key := "sub-123/nested/report.pdf"
	data := []byte("pdf content")
	_, err := store.Save(ctx, key, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Save with subdirs: %v", err)
	}

	// Verify file exists at expected path
	fullPath := filepath.Join(store.baseDir, "sub-123", "nested", "report.pdf")
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		t.Error("expected file to exist at nested path")
	}
}

func TestLocalStore_Delete(t *testing.T) {
	store := tempStore(t)
	ctx := context.Background()

	_, err := store.Save(ctx, "to-delete.txt", bytes.NewReader([]byte("data")))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := store.Delete(ctx, "to-delete.txt"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = store.Open(ctx, "to-delete.txt")
	if err == nil {
		t.Error("expected Open to fail after Delete")
	}
}

func TestLocalStore_DeleteNonExistent(t *testing.T) {
	store := tempStore(t)
	ctx := context.Background()

	// Should not error on missing file
	if err := store.Delete(ctx, "does-not-exist.txt"); err != nil {
		t.Errorf("expected nil error for missing file, got: %v", err)
	}
}

func TestLocalStore_PathTraversal(t *testing.T) {
	store := tempStore(t)
	ctx := context.Background()

	badKeys := []string{
		"../escape.txt",
		"sub/../../../etc/passwd",
		"",
		"/absolute/path.txt",
	}

	for _, key := range badKeys {
		t.Run(key, func(t *testing.T) {
			_, err := store.Save(ctx, key, bytes.NewReader([]byte("x")))
			if err != ErrInvalidKey {
				t.Errorf("Save(%q): expected ErrInvalidKey, got %v", key, err)
			}

			_, err = store.Open(ctx, key)
			if err != ErrInvalidKey {
				t.Errorf("Open(%q): expected ErrInvalidKey, got %v", key, err)
			}

			err = store.Delete(ctx, key)
			if err != ErrInvalidKey {
				t.Errorf("Delete(%q): expected ErrInvalidKey, got %v", key, err)
			}
		})
	}
}

func TestLocalStore_SaveAtomicity(t *testing.T) {
	store := tempStore(t)
	ctx := context.Background()

	key := "atomic-test.txt"
	fullPath := filepath.Join(store.baseDir, key)

	// File should not exist before save completes
	data := []byte("atomic content")
	_, err := store.Save(ctx, key, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	// After save, file should exist at the final path (not a temp name)
	info, err := os.Stat(fullPath)
	if err != nil {
		t.Fatalf("file should exist after Save: %v", err)
	}
	if info.Size() != int64(len(data)) {
		t.Errorf("expected size %d, got %d", len(data), info.Size())
	}

	// No temp files should remain in the directory
	entries, _ := os.ReadDir(store.baseDir)
	for _, e := range entries {
		if e.Name() != key {
			t.Errorf("unexpected file in store dir: %s (possible temp file leak)", e.Name())
		}
	}
}

func TestNewLocalStore_CreatesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "storage", "dir")
	_, err := NewLocalStore(dir)
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("expected directory to be created")
	}
}
