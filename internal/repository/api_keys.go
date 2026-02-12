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

// APIKey represents a row in the api_keys table.
type APIKey struct {
	ID         string
	OrgID      string
	UserID     string
	KeyHash    string
	KeyPrefix  string
	Name       string
	Role       string
	IsActive   bool
	LastUsedAt sql.NullTime
	ExpiresAt  sql.NullTime
	CreatedAt  time.Time
}

// APIKeyRepo handles database operations for API keys.
type APIKeyRepo struct {
	db *sql.DB
}

// NewAPIKeyRepo creates a new APIKeyRepo.
func NewAPIKeyRepo(db *sql.DB) *APIKeyRepo {
	return &APIKeyRepo{db: db}
}

// CreateKeyParams holds the fields needed to create a new API key.
type CreateKeyParams struct {
	OrgID  string
	UserID string
	Name   string
	Role   string
}

// CreateKeyResult holds the created API key record and the raw key (shown once).
type CreateKeyResult struct {
	APIKey APIKey
	RawKey string // Only available at creation time; never stored
}

// Create generates a new API key, stores its hash, and returns the raw key.
// The raw key is only available at creation time.
func (r *APIKeyRepo) Create(ctx context.Context, p CreateKeyParams) (*CreateKeyResult, error) {
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return nil, fmt.Errorf("generating random key: %w", err)
	}
	rawKey := hex.EncodeToString(rawBytes)

	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])
	keyPrefix := rawKey[:8]

	role := p.Role
	if role == "" {
		role = "submitter"
	}
	name := p.Name
	if name == "" {
		name = "default"
	}

	query := `
		INSERT INTO api_keys (org_id, user_id, key_hash, key_prefix, name, role)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, org_id, user_id, key_hash, key_prefix, name, role, is_active, last_used_at, expires_at, created_at`

	var k APIKey
	err := r.db.QueryRowContext(ctx, query, p.OrgID, p.UserID, keyHash, keyPrefix, name, role).Scan(
		&k.ID, &k.OrgID, &k.UserID, &k.KeyHash, &k.KeyPrefix,
		&k.Name, &k.Role, &k.IsActive, &k.LastUsedAt, &k.ExpiresAt, &k.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("creating api key: %w", err)
	}
	return &CreateKeyResult{APIKey: k, RawKey: rawKey}, nil
}

// LookupByRawKey hashes the raw key and looks up the corresponding active, non-expired API key.
func (r *APIKeyRepo) LookupByRawKey(ctx context.Context, rawKey string) (*APIKey, error) {
	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])

	query := `
		SELECT id, org_id, user_id, key_hash, key_prefix, name, role, is_active, last_used_at, expires_at, created_at
		FROM api_keys
		WHERE key_hash = $1 AND is_active = true
		  AND (expires_at IS NULL OR expires_at > NOW())`

	var k APIKey
	err := r.db.QueryRowContext(ctx, query, keyHash).Scan(
		&k.ID, &k.OrgID, &k.UserID, &k.KeyHash, &k.KeyPrefix,
		&k.Name, &k.Role, &k.IsActive, &k.LastUsedAt, &k.ExpiresAt, &k.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("looking up api key: %w", err)
	}
	return &k, nil
}

// TouchLastUsed updates the last_used_at timestamp for an API key.
// This is fire-and-forget; callers should not block on errors.
func (r *APIKeyRepo) TouchLastUsed(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE api_keys SET last_used_at = NOW() WHERE id = $1`, id)
	return err
}
