package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3API is the subset of the S3 client used by S3Store.
// Defined as an interface so tests can mock it without hitting real S3.
type S3API interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

// S3Store implements Store using Amazon S3 (or any S3-compatible service).
type S3Store struct {
	bucket string
	prefix string // optional key prefix (e.g. "uploads/")
	client S3API
}

// NewS3Store creates an S3Store.
// prefix is prepended to all keys (e.g. "uploads/"). Pass "" for no prefix.
func NewS3Store(bucket, prefix string, client S3API) *S3Store {
	return &S3Store{
		bucket: bucket,
		prefix: prefix,
		client: client,
	}
}

// s3Key builds the full S3 object key from a storage key.
func (s *S3Store) s3Key(key string) string {
	if s.prefix == "" {
		return key
	}
	return path.Join(s.prefix, key)
}

// Save uploads the contents of r to S3.
func (s *S3Store) Save(ctx context.Context, key string, r io.Reader) (int64, error) {
	if err := validateKey(key); err != nil {
		return 0, err
	}

	// Wrap reader to count bytes written
	cr := &countingReader{r: r}

	objKey := s.s3Key(key)
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &s.bucket,
		Key:    &objKey,
		Body:   cr,
	})
	if err != nil {
		return 0, fmt.Errorf("s3 put %s: %w", objKey, err)
	}

	return cr.n, nil
}

// Open downloads the S3 object to a temp file and returns a seekable reader.
// The temp file is automatically deleted when Close() is called.
// This is necessary because S3 GetObject returns a streaming body that
// is not seekable, but the FDA client needs seeking for upload retries.
func (s *S3Store) Open(ctx context.Context, key string) (ReadSeekCloser, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}

	objKey := s.s3Key(key)
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &s.bucket,
		Key:    &objKey,
	})
	if err != nil {
		return nil, fmt.Errorf("s3 get %s: %w", objKey, err)
	}
	defer result.Body.Close()

	// Download to temp file for seekability
	tmp, err := os.CreateTemp("", "s3-download-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}

	if _, err := io.Copy(tmp, result.Body); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, fmt.Errorf("downloading s3 object: %w", err)
	}

	// Seek to start so caller reads from the beginning
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, fmt.Errorf("seeking temp file: %w", err)
	}

	return &tempFileCloser{File: tmp}, nil
}

// Delete removes the object at key. S3 delete is idempotent — returns nil
// even if the object does not exist (matching the Store interface contract).
func (s *S3Store) Delete(ctx context.Context, key string) error {
	if err := validateKey(key); err != nil {
		return err
	}

	objKey := s.s3Key(key)
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &s.bucket,
		Key:    &objKey,
	})
	if err != nil {
		return fmt.Errorf("s3 delete %s: %w", objKey, err)
	}
	return nil
}

// tempFileCloser wraps an *os.File and removes the file on Close.
type tempFileCloser struct {
	*os.File
}

func (t *tempFileCloser) Close() error {
	name := t.File.Name()
	err := t.File.Close()
	os.Remove(name) // best-effort cleanup
	return err
}

// countingReader wraps an io.Reader and counts bytes read.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
