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
