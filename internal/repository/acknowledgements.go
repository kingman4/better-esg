package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// AckRepo handles database operations for acknowledgements.
type AckRepo struct {
	db *sql.DB
}

// NewAckRepo creates a new AckRepo.
func NewAckRepo(db *sql.DB) *AckRepo {
	return &AckRepo{db: db}
}

// InsertAckParams holds the fields needed to insert an acknowledgement.
type InsertAckParams struct {
	SubmissionID string
	FDAAckID     string         // FDA-assigned acknowledgement ID (used for dedup)
	AckType      string         // e.g. "ACK1", "ACK2", "ACK3"
	Status       string         // e.g. "Upload Received"
	RawMessage   string         // raw FDA message
	ParsedData   map[string]any // parsed data from FDA
	ESGNGCode    string
}

// Acknowledgement represents a row in the acknowledgements table.
type Acknowledgement struct {
	ID             string
	SubmissionID   string
	FDAAckID       sql.NullString
	AckType        string
	Status         string
	RawMessage     sql.NullString
	ParsedDataJSON sql.NullString // raw JSONB string
	ESGNGCode      sql.NullString
	ReceivedAt     time.Time
	CreatedAt      time.Time
}

// ListBySubmission returns all acknowledgements for a submission, ordered by received_at.
func (r *AckRepo) ListBySubmission(ctx context.Context, submissionID string) ([]Acknowledgement, error) {
	query := `SELECT id, submission_id, fda_ack_id, ack_type, status,
	                  raw_message, parsed_data_json, esgng_code, received_at, created_at
	           FROM acknowledgements
	           WHERE submission_id = $1
	           ORDER BY received_at ASC`

	rows, err := r.db.QueryContext(ctx, query, submissionID)
	if err != nil {
		return nil, fmt.Errorf("listing acknowledgements: %w", err)
	}
	defer rows.Close()

	var acks []Acknowledgement
	for rows.Next() {
		var a Acknowledgement
		if err := rows.Scan(&a.ID, &a.SubmissionID, &a.FDAAckID, &a.AckType, &a.Status,
			&a.RawMessage, &a.ParsedDataJSON, &a.ESGNGCode, &a.ReceivedAt, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning acknowledgement: %w", err)
		}
		acks = append(acks, a)
	}
	return acks, rows.Err()
}

// Insert inserts an acknowledgement into the DB.
// Silently skips duplicates via ON CONFLICT DO NOTHING on fda_ack_id.
func (r *AckRepo) Insert(ctx context.Context, p InsertAckParams) error {
	parsedJSON, err := json.Marshal(p.ParsedData)
	if err != nil {
		return fmt.Errorf("marshaling parsed_data: %w", err)
	}

	query := `
		INSERT INTO acknowledgements (submission_id, fda_ack_id, ack_type, status, raw_message, parsed_data_json, esgng_code, received_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (fda_ack_id) WHERE fda_ack_id IS NOT NULL DO NOTHING`

	_, err = r.db.ExecContext(ctx, query,
		p.SubmissionID, p.FDAAckID, p.AckType, p.Status, p.RawMessage, parsedJSON, p.ESGNGCode, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("inserting acknowledgement: %w", err)
	}
	return nil
}
