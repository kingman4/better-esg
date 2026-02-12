package repository

import (
	"context"
	"database/sql"
)

// WorkflowLogEntry represents a row in the workflow_state_log table.
type WorkflowLogEntry struct {
	ID           string
	SubmissionID string
	FromState    string
	ToState      string
	TriggeredBy  sql.NullString
	ErrorDetails sql.NullString
	CreatedAt    string
}

// WorkflowLogRepo handles workflow state transition logging.
type WorkflowLogRepo struct {
	db *sql.DB
}

// NewWorkflowLogRepo creates a new WorkflowLogRepo.
func NewWorkflowLogRepo(db *sql.DB) *WorkflowLogRepo {
	return &WorkflowLogRepo{db: db}
}

// Insert records a workflow state transition.
// triggeredBy is optional (nil for system-initiated transitions like the poller).
func (r *WorkflowLogRepo) Insert(ctx context.Context, submissionID, fromState, toState string, triggeredBy *string, errorDetails string) error {
	query := `INSERT INTO workflow_state_log (submission_id, from_state, to_state, triggered_by, error_details)
	           VALUES ($1, $2, $3, $4, NULLIF($5, ''))`
	_, err := r.db.ExecContext(ctx, query, submissionID, fromState, toState, triggeredBy, errorDetails)
	return err
}

// ListBySubmission returns all workflow log entries for a submission, ordered by created_at.
func (r *WorkflowLogRepo) ListBySubmission(ctx context.Context, submissionID string) ([]WorkflowLogEntry, error) {
	query := `SELECT id, submission_id, from_state, to_state, triggered_by, error_details, created_at
	           FROM workflow_state_log WHERE submission_id = $1 ORDER BY created_at ASC`
	rows, err := r.db.QueryContext(ctx, query, submissionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []WorkflowLogEntry
	for rows.Next() {
		var e WorkflowLogEntry
		if err := rows.Scan(&e.ID, &e.SubmissionID, &e.FromState, &e.ToState, &e.TriggeredBy, &e.ErrorDetails, &e.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
