package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// --- Mock S3 client ---

type mockS3Client struct {
	putFn    func(ctx context.Context, input *s3.PutObjectInput) (*s3.PutObjectOutput, error)
	getFn    func(ctx context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error)
	deleteFn func(ctx context.Context, input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error)
}

func (m *mockS3Client) PutObject(ctx context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if m.putFn != nil {
		return m.putFn(ctx, input)
	}
	return &s3.PutObjectOutput{}, nil
}

func (m *mockS3Client) GetObject(ctx context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if m.getFn != nil {
		return m.getFn(ctx, input)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockS3Client) DeleteObject(ctx context.Context, input *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	if m.deleteFn != nil {
		return m.deleteFn(ctx, input)
	}
	return &s3.DeleteObjectOutput{}, nil
}

// --- Tests ---

func TestS3Store_Save_KeyValidation(t *testing.T) {
	store := NewS3Store("bucket", "", &mockS3Client{})
	tests := []struct {
		name string
		key  string
	}{
		{"empty key", ""},
		{"path traversal", "../etc/passwd"},
		{"absolute path", "/etc/passwd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := store.Save(context.Background(), tt.key, bytes.NewReader(nil))
			if err != ErrInvalidKey {
				t.Errorf("expected ErrInvalidKey, got %v", err)
			}
		})
	}
}

func TestS3Store_Save_Success(t *testing.T) {
	data := []byte("hello s3")
	var capturedKey string
	var capturedBody []byte

	mock := &mockS3Client{
		putFn: func(_ context.Context, input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
			capturedKey = *input.Key
			capturedBody, _ = io.ReadAll(input.Body)
			return &s3.PutObjectOutput{}, nil
		},
	}

	store := NewS3Store("test-bucket", "uploads/", mock)
	n, err := store.Save(context.Background(), "org-1/file.xml", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != int64(len(data)) {
		t.Errorf("expected %d bytes, got %d", len(data), n)
	}
	if capturedKey != "uploads/org-1/file.xml" {
		t.Errorf("expected key 'uploads/org-1/file.xml', got %q", capturedKey)
	}
	if !bytes.Equal(capturedBody, data) {
		t.Errorf("body mismatch")
	}
}

func TestS3Store_Save_NoPrefix(t *testing.T) {
	var capturedKey string
	mock := &mockS3Client{
		putFn: func(_ context.Context, input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
			capturedKey = *input.Key
			return &s3.PutObjectOutput{}, nil
		},
	}

	store := NewS3Store("bucket", "", mock)
	_, err := store.Save(context.Background(), "file.xml", bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedKey != "file.xml" {
		t.Errorf("expected key 'file.xml', got %q", capturedKey)
	}
}

func TestS3Store_Open_ReturnsSeekableReader(t *testing.T) {
	data := []byte("seekable content from s3")
	mock := &mockS3Client{
		getFn: func(_ context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
			return &s3.GetObjectOutput{
				Body: io.NopCloser(bytes.NewReader(data)),
			}, nil
		},
	}

	store := NewS3Store("bucket", "", mock)
	rsc, err := store.Open(context.Background(), "test.xml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer rsc.Close()

	// Read all content
	got, err := io.ReadAll(rsc)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("content mismatch: got %q, want %q", got, data)
	}

	// Seek back to start (this is the critical requirement for FDA client retries)
	_, err = rsc.Seek(0, io.SeekStart)
	if err != nil {
		t.Fatalf("seek error: %v", err)
	}

	// Read again after seek
	got2, err := io.ReadAll(rsc)
	if err != nil {
		t.Fatalf("read after seek error: %v", err)
	}
	if !bytes.Equal(got2, data) {
		t.Errorf("content after seek mismatch: got %q, want %q", got2, data)
	}
}

func TestS3Store_Open_KeyValidation(t *testing.T) {
	store := NewS3Store("bucket", "", &mockS3Client{})
	_, err := store.Open(context.Background(), "../escape")
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestS3Store_Delete_Success(t *testing.T) {
	var capturedKey string
	mock := &mockS3Client{
		deleteFn: func(_ context.Context, input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
			capturedKey = *input.Key
			return &s3.DeleteObjectOutput{}, nil
		},
	}

	store := NewS3Store("bucket", "pfx/", mock)
	err := store.Delete(context.Background(), "org/file.xml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedKey != "pfx/org/file.xml" {
		t.Errorf("expected key 'pfx/org/file.xml', got %q", capturedKey)
	}
}

func TestS3Store_Delete_KeyValidation(t *testing.T) {
	store := NewS3Store("bucket", "", &mockS3Client{})
	err := store.Delete(context.Background(), "")
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestTempFileCloser_RemovesFile(t *testing.T) {
	tmp, err := os.CreateTemp("", "test-cleanup-*")
	if err != nil {
		t.Fatalf("failed to create temp: %v", err)
	}
	name := tmp.Name()
	tmp.WriteString("data")

	tfc := &tempFileCloser{File: tmp}
	if err := tfc.Close(); err != nil {
		t.Fatalf("close error: %v", err)
	}

	// File should be gone
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Errorf("expected temp file %s to be removed", name)
	}
}

func TestCountingReader(t *testing.T) {
	data := []byte("counting these bytes")
	cr := &countingReader{r: bytes.NewReader(data)}
	got, err := io.ReadAll(cr)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("data mismatch")
	}
	if cr.n != int64(len(data)) {
		t.Errorf("expected %d bytes counted, got %d", len(data), cr.n)
	}
}
