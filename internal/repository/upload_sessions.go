package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// UploadSession represents a chunked upload session.
type UploadSession struct {
	ID             string
	SubmissionID   string
	FileName       string
	FileSizeBytes  int64
	ChunkSizeBytes int
	TotalChunks    int
	Status         string // "uploading", "completed", "failed"
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// UploadChunk represents a received chunk within an upload session.
type UploadChunk struct {
	ID              string
	UploadSessionID string
	ChunkIndex      int
	ChunkSizeBytes  int64
	SHA256Checksum  string
	StoragePath     string
	CreatedAt       time.Time
}

// UploadSessionRepo handles database operations for chunked upload sessions.
type UploadSessionRepo struct {
	db *sql.DB
}

// NewUploadSessionRepo creates a new UploadSessionRepo.
func NewUploadSessionRepo(db *sql.DB) *UploadSessionRepo {
	return &UploadSessionRepo{db: db}
}

// Create inserts a new upload session.
func (r *UploadSessionRepo) Create(ctx context.Context, submissionID, fileName string, fileSizeBytes int64, chunkSizeBytes, totalChunks int) (*UploadSession, error) {
	query := `
		INSERT INTO upload_sessions (submission_id, file_name, file_size_bytes, chunk_size_bytes, total_chunks)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, submission_id, file_name, file_size_bytes, chunk_size_bytes, total_chunks, status, created_at, updated_at`

	var s UploadSession
	err := r.db.QueryRowContext(ctx, query,
		submissionID, fileName, fileSizeBytes, chunkSizeBytes, totalChunks,
	).Scan(
		&s.ID, &s.SubmissionID, &s.FileName, &s.FileSizeBytes,
		&s.ChunkSizeBytes, &s.TotalChunks, &s.Status, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("creating upload session: %w", err)
	}
	return &s, nil
}

// GetByID returns an upload session by its ID.
func (r *UploadSessionRepo) GetByID(ctx context.Context, id string) (*UploadSession, error) {
	query := `
		SELECT id, submission_id, file_name, file_size_bytes, chunk_size_bytes, total_chunks, status, created_at, updated_at
		FROM upload_sessions
		WHERE id = $1`

	var s UploadSession
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&s.ID, &s.SubmissionID, &s.FileName, &s.FileSizeBytes,
		&s.ChunkSizeBytes, &s.TotalChunks, &s.Status, &s.CreatedAt, &s.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting upload session: %w", err)
	}
	return &s, nil
}

// RecordChunk upserts a chunk record. If the same (session, index) exists, it is overwritten.
func (r *UploadSessionRepo) RecordChunk(ctx context.Context, sessionID string, chunkIndex int, chunkSizeBytes int64, sha256 string, storagePath string) (*UploadChunk, error) {
	query := `
		INSERT INTO upload_chunks (upload_session_id, chunk_index, chunk_size_bytes, sha256_checksum, storage_path)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (upload_session_id, chunk_index)
		DO UPDATE SET chunk_size_bytes = EXCLUDED.chunk_size_bytes,
		              sha256_checksum = EXCLUDED.sha256_checksum,
		              storage_path = EXCLUDED.storage_path
		RETURNING id, upload_session_id, chunk_index, chunk_size_bytes, sha256_checksum, storage_path, created_at`

	var c UploadChunk
	err := r.db.QueryRowContext(ctx, query,
		sessionID, chunkIndex, chunkSizeBytes, sha256, storagePath,
	).Scan(
		&c.ID, &c.UploadSessionID, &c.ChunkIndex, &c.ChunkSizeBytes,
		&c.SHA256Checksum, &c.StoragePath, &c.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("recording chunk: %w", err)
	}
	return &c, nil
}

// ListChunks returns all chunks for a session, ordered by chunk_index.
func (r *UploadSessionRepo) ListChunks(ctx context.Context, sessionID string) ([]UploadChunk, error) {
	query := `
		SELECT id, upload_session_id, chunk_index, chunk_size_bytes, sha256_checksum, storage_path, created_at
		FROM upload_chunks
		WHERE upload_session_id = $1
		ORDER BY chunk_index`

	rows, err := r.db.QueryContext(ctx, query, sessionID)
	if err != nil {
		return nil, fmt.Errorf("listing chunks: %w", err)
	}
	defer rows.Close()

	var chunks []UploadChunk
	for rows.Next() {
		var c UploadChunk
		if err := rows.Scan(
			&c.ID, &c.UploadSessionID, &c.ChunkIndex, &c.ChunkSizeBytes,
			&c.SHA256Checksum, &c.StoragePath, &c.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning chunk row: %w", err)
		}
		chunks = append(chunks, c)
	}
	return chunks, rows.Err()
}

// CountChunks returns the number of chunks received for a session.
func (r *UploadSessionRepo) CountChunks(ctx context.Context, sessionID string) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM upload_chunks WHERE upload_session_id = $1`, sessionID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting chunks: %w", err)
	}
	return count, nil
}

// UpdateStatus transitions the session status.
func (r *UploadSessionRepo) UpdateStatus(ctx context.Context, id, newStatus string) error {
	result, err := r.db.ExecContext(ctx,
		`UPDATE upload_sessions SET status = $1 WHERE id = $2`, newStatus, id,
	)
	if err != nil {
		return fmt.Errorf("updating upload session status: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("upload session %s not found", id)
	}
	return nil
}
