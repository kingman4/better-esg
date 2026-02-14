package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// WebhookDelivery represents a row in the webhook_deliveries table.
type WebhookDelivery struct {
	ID           string
	WebhookID    string
	EventType    string
	Payload      map[string]any
	StatusCode   sql.NullInt32
	ResponseBody sql.NullString
	Error        sql.NullString
	Attempt      int
	DeliveredAt  sql.NullTime
	CreatedAt    time.Time
}

// LogDeliveryParams holds the fields for logging a webhook delivery attempt.
type LogDeliveryParams struct {
	WebhookID    string
	EventType    string
	Payload      map[string]any
	StatusCode   int    // 0 if no response (network error)
	ResponseBody string // truncated response body
	Error        string // empty on success
	Attempt      int
	Delivered    bool   // true if 2xx response
}

// WebhookDeliveryRepo handles database operations for webhook delivery logs.
type WebhookDeliveryRepo struct {
	db *sql.DB
}

// NewWebhookDeliveryRepo creates a new WebhookDeliveryRepo.
func NewWebhookDeliveryRepo(db *sql.DB) *WebhookDeliveryRepo {
	return &WebhookDeliveryRepo{db: db}
}

// LogDelivery inserts a delivery attempt record.
func (r *WebhookDeliveryRepo) LogDelivery(ctx context.Context, p LogDeliveryParams) error {
	payloadJSON, err := json.Marshal(p.Payload)
	if err != nil {
		return fmt.Errorf("marshaling delivery payload: %w", err)
	}

	var statusCode sql.NullInt32
	if p.StatusCode > 0 {
		statusCode = sql.NullInt32{Int32: int32(p.StatusCode), Valid: true}
	}

	var deliveredAt sql.NullTime
	if p.Delivered {
		deliveredAt = sql.NullTime{Time: time.Now(), Valid: true}
	}

	query := `
		INSERT INTO webhook_deliveries (webhook_id, event_type, payload, status_code, response_body, error, attempt, delivered_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err = r.db.ExecContext(ctx, query,
		p.WebhookID, p.EventType, payloadJSON,
		statusCode, nullString(p.ResponseBody), nullString(p.Error),
		p.Attempt, deliveredAt,
	)
	if err != nil {
		return fmt.Errorf("logging webhook delivery: %w", err)
	}
	return nil
}
