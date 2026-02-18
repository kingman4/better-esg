package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// NotificationPreference represents a row in the notification_preferences table.
type NotificationPreference struct {
	ID            string
	UserID        string
	Channel       string
	Events        []string
	WebhookURL    sql.NullString
	WebhookSecret sql.NullString
	IsActive      bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// CreateNotificationPrefParams holds the fields needed to create/upsert a notification preference.
type CreateNotificationPrefParams struct {
	UserID        string
	Channel       string
	Events        []string
	WebhookURL    string
	WebhookSecret string
	IsActive      bool
}

// UpdateNotificationPrefParams holds optional fields for updating a notification preference.
type UpdateNotificationPrefParams struct {
	Events        *[]string
	WebhookURL    *string
	WebhookSecret *string
	IsActive      *bool
}

// NotificationPreferenceRepo handles database operations for notification preferences.
type NotificationPreferenceRepo struct {
	db *sql.DB
}

// NewNotificationPreferenceRepo creates a new NotificationPreferenceRepo.
func NewNotificationPreferenceRepo(db *sql.DB) *NotificationPreferenceRepo {
	return &NotificationPreferenceRepo{db: db}
}

const notifPrefColumns = `id, user_id, channel, events_json, webhook_url, webhook_secret, is_active, created_at, updated_at`

func scanNotifPref(scanner interface{ Scan(...any) error }) (NotificationPreference, error) {
	var np NotificationPreference
	var eventsJSON []byte
	if err := scanner.Scan(
		&np.ID, &np.UserID, &np.Channel, &eventsJSON,
		&np.WebhookURL, &np.WebhookSecret, &np.IsActive,
		&np.CreatedAt, &np.UpdatedAt,
	); err != nil {
		return NotificationPreference{}, err
	}
	if err := json.Unmarshal(eventsJSON, &np.Events); err != nil {
		return NotificationPreference{}, fmt.Errorf("parsing events JSON: %w", err)
	}
	return np, nil
}

// Create upserts a notification preference (ON CONFLICT by user_id + channel).
func (r *NotificationPreferenceRepo) Create(ctx context.Context, p CreateNotificationPrefParams) (*NotificationPreference, error) {
	eventsJSON, err := json.Marshal(p.Events)
	if err != nil {
		return nil, fmt.Errorf("marshaling events: %w", err)
	}

	query := fmt.Sprintf(`
		INSERT INTO notification_preferences (user_id, channel, events_json, webhook_url, webhook_secret, is_active)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (user_id, channel) DO UPDATE SET
			events_json = EXCLUDED.events_json,
			webhook_url = EXCLUDED.webhook_url,
			webhook_secret = EXCLUDED.webhook_secret,
			is_active = EXCLUDED.is_active
		RETURNING %s`, notifPrefColumns)

	row := r.db.QueryRowContext(ctx, query,
		p.UserID, p.Channel, eventsJSON,
		nullString(p.WebhookURL), nullString(p.WebhookSecret), p.IsActive,
	)
	np, err := scanNotifPref(row)
	if err != nil {
		return nil, fmt.Errorf("creating notification preference: %w", err)
	}
	return &np, nil
}

// GetByUserAndChannel returns a single preference. Returns nil if not found.
func (r *NotificationPreferenceRepo) GetByUserAndChannel(ctx context.Context, userID, channel string) (*NotificationPreference, error) {
	query := fmt.Sprintf(`SELECT %s FROM notification_preferences WHERE user_id = $1 AND channel = $2`, notifPrefColumns)

	row := r.db.QueryRowContext(ctx, query, userID, channel)
	np, err := scanNotifPref(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting notification preference: %w", err)
	}
	return &np, nil
}

// ListByUser returns all preferences for a user.
func (r *NotificationPreferenceRepo) ListByUser(ctx context.Context, userID string) ([]NotificationPreference, error) {
	query := fmt.Sprintf(`SELECT %s FROM notification_preferences WHERE user_id = $1 ORDER BY created_at`, notifPrefColumns)

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("listing notification preferences: %w", err)
	}
	defer rows.Close()

	var prefs []NotificationPreference
	for rows.Next() {
		np, err := scanNotifPref(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning notification preference: %w", err)
		}
		prefs = append(prefs, np)
	}
	return prefs, rows.Err()
}

// ListActiveByOrgAndEvent returns all active preferences for users in the given org
// that are subscribed to the specified event type.
func (r *NotificationPreferenceRepo) ListActiveByOrgAndEvent(ctx context.Context, orgID, eventType string) ([]NotificationPreference, error) {
	query := `
		SELECT np.id, np.user_id, np.channel, np.events_json, np.webhook_url, np.webhook_secret, np.is_active, np.created_at, np.updated_at
		FROM notification_preferences np
		JOIN users u ON u.id = np.user_id
		WHERE u.org_id = $1
		  AND np.is_active = true
		  AND np.events_json @> $2`

	eventJSON, _ := json.Marshal([]string{eventType})

	rows, err := r.db.QueryContext(ctx, query, orgID, eventJSON)
	if err != nil {
		return nil, fmt.Errorf("listing active notification preferences for event: %w", err)
	}
	defer rows.Close()

	var prefs []NotificationPreference
	for rows.Next() {
		np, err := scanNotifPref(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning notification preference: %w", err)
		}
		prefs = append(prefs, np)
	}
	return prefs, rows.Err()
}

// Update updates a notification preference's fields. Only non-nil params are applied.
func (r *NotificationPreferenceRepo) Update(ctx context.Context, userID, channel string, p UpdateNotificationPrefParams) (*NotificationPreference, error) {
	// Build dynamic SET clause
	setClauses := []string{}
	args := []any{}
	argN := 1

	if p.Events != nil {
		eventsJSON, err := json.Marshal(*p.Events)
		if err != nil {
			return nil, fmt.Errorf("marshaling events: %w", err)
		}
		setClauses = append(setClauses, fmt.Sprintf("events_json = $%d", argN))
		args = append(args, eventsJSON)
		argN++
	}
	if p.WebhookURL != nil {
		setClauses = append(setClauses, fmt.Sprintf("webhook_url = $%d", argN))
		args = append(args, nullString(*p.WebhookURL))
		argN++
	}
	if p.WebhookSecret != nil {
		setClauses = append(setClauses, fmt.Sprintf("webhook_secret = $%d", argN))
		args = append(args, nullString(*p.WebhookSecret))
		argN++
	}
	if p.IsActive != nil {
		setClauses = append(setClauses, fmt.Sprintf("is_active = $%d", argN))
		args = append(args, *p.IsActive)
		argN++
	}

	if len(setClauses) == 0 {
		return r.GetByUserAndChannel(ctx, userID, channel)
	}

	setStr := ""
	for i, c := range setClauses {
		if i > 0 {
			setStr += ", "
		}
		setStr += c
	}

	query := fmt.Sprintf(`UPDATE notification_preferences SET %s WHERE user_id = $%d AND channel = $%d RETURNING %s`,
		setStr, argN, argN+1, notifPrefColumns)
	args = append(args, userID, channel)

	row := r.db.QueryRowContext(ctx, query, args...)
	np, err := scanNotifPref(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("updating notification preference: %w", err)
	}
	return &np, nil
}

// Delete removes a notification preference by user and channel.
func (r *NotificationPreferenceRepo) Delete(ctx context.Context, userID, channel string) error {
	query := `DELETE FROM notification_preferences WHERE user_id = $1 AND channel = $2`
	result, err := r.db.ExecContext(ctx, query, userID, channel)
	if err != nil {
		return fmt.Errorf("deleting notification preference: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("notification preference not found")
	}
	return nil
}
