package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// AuditLogEntry represents a row in the audit_logs table.
type AuditLogEntry struct {
	ID          int64
	OrgID       string
	UserID      sql.NullString
	Action      string
	EntityType  string
	EntityID    sql.NullString
	RequestIP   sql.NullString
	UserAgent   sql.NullString
	DetailsJSON sql.NullString // raw JSONB string
	CreatedAt   time.Time
}

// InsertAuditLogParams holds the fields needed to insert an audit log entry.
type InsertAuditLogParams struct {
	OrgID      string
	UserID     *string        // nil for system-initiated actions
	Action     string         // e.g. "create_submission", "upload_file"
	EntityType string         // e.g. "submission", "file", "webhook"
	EntityID   string
	RequestIP  string         // from r.RemoteAddr
	UserAgent  string         // from User-Agent header
	Details    map[string]any // operation-specific metadata
}

// AuditLogRepo handles database operations for audit logs.
type AuditLogRepo struct {
	db *sql.DB
}

// NewAuditLogRepo creates a new AuditLogRepo.
func NewAuditLogRepo(db *sql.DB) *AuditLogRepo {
	return &AuditLogRepo{db: db}
}

// Insert records an audit log entry. Best-effort — callers should log errors
// but not fail the request on audit insert failures.
func (r *AuditLogRepo) Insert(ctx context.Context, p InsertAuditLogParams) error {
	var detailsJSON []byte
	if p.Details != nil {
		var err error
		detailsJSON, err = json.Marshal(p.Details)
		if err != nil {
			return fmt.Errorf("marshaling audit details: %w", err)
		}
	}

	query := `
		INSERT INTO audit_logs (org_id, user_id, action, entity_type, entity_id, request_ip, user_agent, details_json)
		VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, NULLIF($7, ''), $8)`

	// request_ip is INET type — pass nil for empty string to get NULL
	var requestIP any
	if p.RequestIP != "" {
		requestIP = p.RequestIP
	}

	_, err := r.db.ExecContext(ctx, query,
		p.OrgID, p.UserID, p.Action, p.EntityType, p.EntityID,
		requestIP, p.UserAgent, detailsJSON,
	)
	if err != nil {
		return fmt.Errorf("inserting audit log: %w", err)
	}
	return nil
}

// ListByOrg returns audit log entries for an org, ordered by created_at DESC.
func (r *AuditLogRepo) ListByOrg(ctx context.Context, orgID string, limit, offset int) ([]AuditLogEntry, error) {
	query := `SELECT id, org_id, user_id, action, entity_type, entity_id,
	                  request_ip, user_agent, details_json, created_at
	           FROM audit_logs
	           WHERE org_id = $1
	           ORDER BY created_at DESC
	           LIMIT $2 OFFSET $3`

	rows, err := r.db.QueryContext(ctx, query, orgID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("listing audit logs: %w", err)
	}
	defer rows.Close()

	var entries []AuditLogEntry
	for rows.Next() {
		var e AuditLogEntry
		if err := rows.Scan(
			&e.ID, &e.OrgID, &e.UserID, &e.Action, &e.EntityType, &e.EntityID,
			&e.RequestIP, &e.UserAgent, &e.DetailsJSON, &e.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning audit log: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
