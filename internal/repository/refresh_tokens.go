package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

// RefreshToken represents a row in the refresh_tokens table.
type RefreshToken struct {
	ID        string
	UserID    string
	OrgID     string
	TokenHash string
	ExpiresAt time.Time
	IsActive  bool
	CreatedAt time.Time
}

// RefreshTokenRepo handles database operations for refresh tokens.
type RefreshTokenRepo struct {
	db *sql.DB
}

// NewRefreshTokenRepo creates a new RefreshTokenRepo.
func NewRefreshTokenRepo(db *sql.DB) *RefreshTokenRepo {
	return &RefreshTokenRepo{db: db}
}

// Create generates a random refresh token, stores its SHA-256 hash, and returns
// the raw token. The raw token is only available at creation time.
func (r *RefreshTokenRepo) Create(ctx context.Context, userID, orgID string, expiresAt time.Time) (string, error) {
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return "", fmt.Errorf("generating random token: %w", err)
	}
	rawToken := hex.EncodeToString(rawBytes)

	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(hash[:])

	query := `
		INSERT INTO refresh_tokens (user_id, org_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)`

	_, err := r.db.ExecContext(ctx, query, userID, orgID, tokenHash, expiresAt)
	if err != nil {
		return "", fmt.Errorf("creating refresh token: %w", err)
	}
	return rawToken, nil
}

// Validate hashes the raw token and looks up an active, non-expired refresh token.
// Returns nil if not found or expired.
func (r *RefreshTokenRepo) Validate(ctx context.Context, rawToken string) (*RefreshToken, error) {
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(hash[:])

	query := `
		SELECT id, user_id, org_id, token_hash, expires_at, is_active, created_at
		FROM refresh_tokens
		WHERE token_hash = $1 AND is_active = true AND expires_at > NOW()`

	var t RefreshToken
	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&t.ID, &t.UserID, &t.OrgID, &t.TokenHash, &t.ExpiresAt, &t.IsActive, &t.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("validating refresh token: %w", err)
	}
	return &t, nil
}

// Revoke deactivates a single refresh token.
func (r *RefreshTokenRepo) Revoke(ctx context.Context, tokenHash string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET is_active = false WHERE token_hash = $1`,
		tokenHash,
	)
	if err != nil {
		return fmt.Errorf("revoking refresh token: %w", err)
	}
	return nil
}

// RevokeAllForUser deactivates all refresh tokens for a user.
func (r *RefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET is_active = false WHERE user_id = $1 AND is_active = true`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("revoking all refresh tokens for user: %w", err)
	}
	return nil
}
