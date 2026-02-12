package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// SubmissionFile represents a row in the submission_files table.
type SubmissionFile struct {
	ID              string
	SubmissionID    string
	FileName        string
	FileSizeBytes   int64
	SHA256Checksum  string
	MimeType        sql.NullString
	StoragePath     string
	StorageBackend  string
	UploadStatus    string
	UploadedAt      sql.NullTime
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// CreateFileParams holds the fields needed to create a new submission file record.
type CreateFileParams struct {
	SubmissionID   string
	FileName       string
	FileSizeBytes  int64
	SHA256Checksum string
	MimeType       string
	StoragePath    string
	StorageBackend string
}

// SubmissionFileRepo handles database operations for submission files.
type SubmissionFileRepo struct {
	db *sql.DB
}

// NewSubmissionFileRepo creates a new SubmissionFileRepo.
func NewSubmissionFileRepo(db *sql.DB) *SubmissionFileRepo {
	return &SubmissionFileRepo{db: db}
}

// Create inserts a new submission file record.
func (r *SubmissionFileRepo) Create(ctx context.Context, p CreateFileParams) (*SubmissionFile, error) {
	query := `
		INSERT INTO submission_files (submission_id, file_name, file_size_bytes, sha256_checksum, mime_type, storage_path, storage_backend)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, submission_id, file_name, file_size_bytes, sha256_checksum, mime_type,
		          storage_path, storage_backend, upload_status, uploaded_at, created_at, updated_at`

	var f SubmissionFile
	err := r.db.QueryRowContext(ctx, query,
		p.SubmissionID, p.FileName, p.FileSizeBytes, p.SHA256Checksum,
		p.MimeType, p.StoragePath, p.StorageBackend,
	).Scan(
		&f.ID, &f.SubmissionID, &f.FileName, &f.FileSizeBytes, &f.SHA256Checksum,
		&f.MimeType, &f.StoragePath, &f.StorageBackend, &f.UploadStatus,
		&f.UploadedAt, &f.CreatedAt, &f.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("creating submission file: %w", err)
	}
	return &f, nil
}

// ListBySubmission returns all files for a given submission.
func (r *SubmissionFileRepo) ListBySubmission(ctx context.Context, submissionID string) ([]SubmissionFile, error) {
	query := `
		SELECT id, submission_id, file_name, file_size_bytes, sha256_checksum, mime_type,
		       storage_path, storage_backend, upload_status, uploaded_at, created_at, updated_at
		FROM submission_files
		WHERE submission_id = $1
		ORDER BY created_at`

	rows, err := r.db.QueryContext(ctx, query, submissionID)
	if err != nil {
		return nil, fmt.Errorf("listing submission files: %w", err)
	}
	defer rows.Close()

	var files []SubmissionFile
	for rows.Next() {
		var f SubmissionFile
		if err := rows.Scan(
			&f.ID, &f.SubmissionID, &f.FileName, &f.FileSizeBytes, &f.SHA256Checksum,
			&f.MimeType, &f.StoragePath, &f.StorageBackend, &f.UploadStatus,
			&f.UploadedAt, &f.CreatedAt, &f.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning submission file row: %w", err)
		}
		files = append(files, f)
	}
	return files, rows.Err()
}

// UpdateStatus updates the upload_status of a file. Sets uploaded_at when moving to "uploaded".
func (r *SubmissionFileRepo) UpdateStatus(ctx context.Context, id, status string) error {
	var query string
	if status == "uploaded" {
		query = `UPDATE submission_files SET upload_status = $1, uploaded_at = CURRENT_TIMESTAMP WHERE id = $2`
	} else {
		query = `UPDATE submission_files SET upload_status = $1 WHERE id = $2`
	}
	result, err := r.db.ExecContext(ctx, query, status, id)
	if err != nil {
		return fmt.Errorf("updating file status: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("file %s not found", id)
	}
	return nil
}

// CountBySubmission returns the total number of files and how many are uploaded.
func (r *SubmissionFileRepo) CountBySubmission(ctx context.Context, submissionID string) (total, uploaded int, err error) {
	query := `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE upload_status = 'uploaded')
		FROM submission_files
		WHERE submission_id = $1`

	err = r.db.QueryRowContext(ctx, query, submissionID).Scan(&total, &uploaded)
	if err != nil {
		return 0, 0, fmt.Errorf("counting submission files: %w", err)
	}
	return total, uploaded, nil
}
