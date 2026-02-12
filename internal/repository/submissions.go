package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Submission represents a row in the submissions table.
type Submission struct {
	ID                 string
	OrgID              string
	CoreID             sql.NullString
	FDACenter          sql.NullString
	SubmissionType     string
	SubmissionName     string
	SubmissionProtocol string
	FileCount          int
	TotalSizeBytes     sql.NullInt64
	Description        sql.NullString
	Status             string
	WorkflowState      string
	PayloadID          sql.NullString
	UploadFileLink     sql.NullString
	SubmitFormLink     sql.NullString
	CreatedBy          string
	CreatedAt          time.Time
	SubmittedAt        sql.NullTime
	CompletedAt        sql.NullTime
	UpdatedAt          time.Time
}

// CreateSubmissionParams holds the fields needed to create a new submission.
type CreateSubmissionParams struct {
	OrgID              string
	FDACenter          string
	SubmissionType     string
	SubmissionName     string
	SubmissionProtocol string
	FileCount          int
	Description        string
	CreatedBy          string
}

// SubmissionRepo handles database operations for submissions.
type SubmissionRepo struct {
	db *sql.DB
}

// NewSubmissionRepo creates a new SubmissionRepo.
func NewSubmissionRepo(db *sql.DB) *SubmissionRepo {
	return &SubmissionRepo{db: db}
}

// Create inserts a new submission and returns the created record.
func (r *SubmissionRepo) Create(ctx context.Context, p CreateSubmissionParams) (*Submission, error) {
	query := `
		INSERT INTO submissions (org_id, fda_center, submission_type, submission_name, submission_protocol, file_count, description, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, org_id, core_id, fda_center, submission_type, submission_name, submission_protocol,
		          file_count, total_size_bytes, description, status, workflow_state,
		          payload_id, upload_file_link, submit_form_link,
		          created_by, created_at, submitted_at, completed_at, updated_at`

	var s Submission
	err := r.db.QueryRowContext(ctx, query,
		p.OrgID, p.FDACenter, p.SubmissionType, p.SubmissionName, p.SubmissionProtocol,
		p.FileCount, p.Description, p.CreatedBy,
	).Scan(
		&s.ID, &s.OrgID, &s.CoreID, &s.FDACenter, &s.SubmissionType, &s.SubmissionName,
		&s.SubmissionProtocol, &s.FileCount, &s.TotalSizeBytes, &s.Description,
		&s.Status, &s.WorkflowState, &s.PayloadID, &s.UploadFileLink, &s.SubmitFormLink,
		&s.CreatedBy, &s.CreatedAt, &s.SubmittedAt, &s.CompletedAt, &s.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("creating submission: %w", err)
	}
	return &s, nil
}

// GetByID retrieves a submission by its primary key, scoped to an org.
func (r *SubmissionRepo) GetByID(ctx context.Context, orgID, id string) (*Submission, error) {
	query := `
		SELECT id, org_id, core_id, fda_center, submission_type, submission_name, submission_protocol,
		       file_count, total_size_bytes, description, status, workflow_state,
		       payload_id, upload_file_link, submit_form_link,
		       created_by, created_at, submitted_at, completed_at, updated_at
		FROM submissions
		WHERE id = $1 AND org_id = $2`

	var s Submission
	err := r.db.QueryRowContext(ctx, query, id, orgID).Scan(
		&s.ID, &s.OrgID, &s.CoreID, &s.FDACenter, &s.SubmissionType, &s.SubmissionName,
		&s.SubmissionProtocol, &s.FileCount, &s.TotalSizeBytes, &s.Description,
		&s.Status, &s.WorkflowState, &s.PayloadID, &s.UploadFileLink, &s.SubmitFormLink,
		&s.CreatedBy, &s.CreatedAt, &s.SubmittedAt, &s.CompletedAt, &s.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting submission: %w", err)
	}
	return &s, nil
}

// ListByOrg retrieves all submissions for an org, newest first.
func (r *SubmissionRepo) ListByOrg(ctx context.Context, orgID string, limit, offset int) ([]Submission, error) {
	query := `
		SELECT id, org_id, core_id, fda_center, submission_type, submission_name, submission_protocol,
		       file_count, total_size_bytes, description, status, workflow_state,
		       payload_id, upload_file_link, submit_form_link,
		       created_by, created_at, submitted_at, completed_at, updated_at
		FROM submissions
		WHERE org_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.db.QueryContext(ctx, query, orgID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("listing submissions: %w", err)
	}
	defer rows.Close()

	var submissions []Submission
	for rows.Next() {
		var s Submission
		if err := rows.Scan(
			&s.ID, &s.OrgID, &s.CoreID, &s.FDACenter, &s.SubmissionType, &s.SubmissionName,
			&s.SubmissionProtocol, &s.FileCount, &s.TotalSizeBytes, &s.Description,
			&s.Status, &s.WorkflowState, &s.PayloadID, &s.UploadFileLink, &s.SubmitFormLink,
			&s.CreatedBy, &s.CreatedAt, &s.SubmittedAt, &s.CompletedAt, &s.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning submission row: %w", err)
		}
		submissions = append(submissions, s)
	}
	return submissions, rows.Err()
}

// UpdateStatus updates the status and workflow_state of a submission.
func (r *SubmissionRepo) UpdateStatus(ctx context.Context, id, status, workflowState string) error {
	query := `UPDATE submissions SET status = $1, workflow_state = $2 WHERE id = $3`
	result, err := r.db.ExecContext(ctx, query, status, workflowState, id)
	if err != nil {
		return fmt.Errorf("updating submission status: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("submission %s not found", id)
	}
	return nil
}

// UpdateFDAFields updates the FDA-specific fields after credential and payload steps.
func (r *SubmissionRepo) UpdateFDAFields(ctx context.Context, id string, coreID, payloadID, uploadLink, submitLink string) error {
	query := `
		UPDATE submissions
		SET core_id = $1, payload_id = $2, upload_file_link = $3, submit_form_link = $4
		WHERE id = $5`
	result, err := r.db.ExecContext(ctx, query, coreID, payloadID, uploadLink, submitLink, id)
	if err != nil {
		return fmt.Errorf("updating FDA fields: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("submission %s not found", id)
	}
	return nil
}
