package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Webhook represents a row in the webhooks table.
type Webhook struct {
	ID          string
	OrgID       string
	URL         string
	Secret      string
	Events      []string
	IsActive    bool
	Description sql.NullString
	CreatedBy   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// CreateWebhookParams holds the fields needed to create a webhook.
type CreateWebhookParams struct {
	OrgID       string
	URL         string
	Secret      string
	Events      []string
	Description string
	CreatedBy   string
}

// WebhookRepo handles database operations for webhooks.
type WebhookRepo struct {
	db *sql.DB
}

// NewWebhookRepo creates a new WebhookRepo.
func NewWebhookRepo(db *sql.DB) *WebhookRepo {
	return &WebhookRepo{db: db}
}

// scanWebhook scans a webhook row, parsing the JSONB events column.
func scanWebhook(scanner interface{ Scan(...any) error }) (Webhook, error) {
	var w Webhook
	var eventsJSON []byte
	if err := scanner.Scan(
		&w.ID, &w.OrgID, &w.URL, &w.Secret, &eventsJSON,
		&w.IsActive, &w.Description, &w.CreatedBy, &w.CreatedAt, &w.UpdatedAt,
	); err != nil {
		return Webhook{}, err
	}
	if err := json.Unmarshal(eventsJSON, &w.Events); err != nil {
		return Webhook{}, fmt.Errorf("parsing events JSON: %w", err)
	}
	return w, nil
}

const webhookColumns = `id, org_id, url, secret, events, is_active, description, created_by, created_at, updated_at`

// Create inserts a new webhook.
func (r *WebhookRepo) Create(ctx context.Context, p CreateWebhookParams) (*Webhook, error) {
	eventsJSON, err := json.Marshal(p.Events)
	if err != nil {
		return nil, fmt.Errorf("marshaling events: %w", err)
	}

	query := fmt.Sprintf(`
		INSERT INTO webhooks (org_id, url, secret, events, description, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING %s`, webhookColumns)

	row := r.db.QueryRowContext(ctx, query,
		p.OrgID, p.URL, p.Secret, eventsJSON, nullString(p.Description), p.CreatedBy,
	)
	w, err := scanWebhook(row)
	if err != nil {
		return nil, fmt.Errorf("creating webhook: %w", err)
	}
	return &w, nil
}

// GetByID returns a single webhook scoped to the org. Returns nil if not found.
func (r *WebhookRepo) GetByID(ctx context.Context, orgID, id string) (*Webhook, error) {
	query := fmt.Sprintf(`SELECT %s FROM webhooks WHERE id = $1 AND org_id = $2`, webhookColumns)

	row := r.db.QueryRowContext(ctx, query, id, orgID)
	w, err := scanWebhook(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting webhook: %w", err)
	}
	return &w, nil
}

// ListByOrg returns webhooks for an org with pagination.
func (r *WebhookRepo) ListByOrg(ctx context.Context, orgID string, limit, offset int) ([]Webhook, error) {
	query := fmt.Sprintf(`SELECT %s FROM webhooks WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, webhookColumns)

	rows, err := r.db.QueryContext(ctx, query, orgID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("listing webhooks: %w", err)
	}
	defer rows.Close()

	var webhooks []Webhook
	for rows.Next() {
		w, err := scanWebhook(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning webhook: %w", err)
		}
		webhooks = append(webhooks, w)
	}
	return webhooks, rows.Err()
}

// ListActiveForEvent returns all active webhooks for an org that subscribe to a given event type.
func (r *WebhookRepo) ListActiveForEvent(ctx context.Context, orgID, eventType string) ([]Webhook, error) {
	query := fmt.Sprintf(`SELECT %s FROM webhooks WHERE org_id = $1 AND is_active = true AND events @> $2`, webhookColumns)

	// @> checks if the JSONB array contains the element
	eventJSON, _ := json.Marshal([]string{eventType})

	rows, err := r.db.QueryContext(ctx, query, orgID, eventJSON)
	if err != nil {
		return nil, fmt.Errorf("listing webhooks for event: %w", err)
	}
	defer rows.Close()

	var webhooks []Webhook
	for rows.Next() {
		w, err := scanWebhook(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning webhook: %w", err)
		}
		webhooks = append(webhooks, w)
	}
	return webhooks, rows.Err()
}

// Delete removes a webhook. Only deletes if it belongs to the given org.
func (r *WebhookRepo) Delete(ctx context.Context, orgID, id string) error {
	query := `DELETE FROM webhooks WHERE id = $1 AND org_id = $2`
	result, err := r.db.ExecContext(ctx, query, id, orgID)
	if err != nil {
		return fmt.Errorf("deleting webhook: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("webhook not found")
	}
	return nil
}

// nullString converts an empty string to sql.NullString{Valid: false}.
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
