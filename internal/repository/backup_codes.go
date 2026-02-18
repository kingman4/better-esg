package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/kingman4/better-esg/internal/auth"
)

// BackupCode represents a row in the mfa_backup_codes table.
type BackupCode struct {
	ID        string
	UserID    string
	CodeHash  string
	UsedAt    *time.Time
	CreatedAt time.Time
}

// BackupCodeRepo handles database operations for MFA backup codes.
type BackupCodeRepo struct {
	db *sql.DB
}

// NewBackupCodeRepo creates a new BackupCodeRepo.
func NewBackupCodeRepo(db *sql.DB) *BackupCodeRepo {
	return &BackupCodeRepo{db: db}
}

// Create stores backup code hashes for a user, replacing any existing codes.
// Runs inside a transaction: deletes old codes, then bulk inserts new ones.
func (r *BackupCodeRepo) Create(ctx context.Context, userID string, codeHashes []string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete existing codes for this user
	if _, err := tx.ExecContext(ctx, `DELETE FROM mfa_backup_codes WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("deleting old backup codes: %w", err)
	}

	// Insert new codes
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES ($1, $2)`)
	if err != nil {
		return fmt.Errorf("preparing insert: %w", err)
	}
	defer stmt.Close()

	for _, hash := range codeHashes {
		if _, err := stmt.ExecContext(ctx, userID, hash); err != nil {
			return fmt.Errorf("inserting backup code: %w", err)
		}
	}

	return tx.Commit()
}

// VerifyAndConsume checks a plaintext backup code against the user's unused codes.
// If a match is found, marks it as used and returns true.
func (r *BackupCodeRepo) VerifyAndConsume(ctx context.Context, userID, plainCode string) (bool, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, code_hash FROM mfa_backup_codes WHERE user_id = $1 AND used_at IS NULL`,
		userID,
	)
	if err != nil {
		return false, fmt.Errorf("querying backup codes: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id, hash string
		if err := rows.Scan(&id, &hash); err != nil {
			return false, fmt.Errorf("scanning backup code: %w", err)
		}

		if auth.CheckBackupCode(plainCode, hash) {
			// Mark as used
			if _, err := r.db.ExecContext(ctx,
				`UPDATE mfa_backup_codes SET used_at = NOW() WHERE id = $1`,
				id,
			); err != nil {
				return false, fmt.Errorf("marking backup code used: %w", err)
			}
			return true, nil
		}
	}

	return false, rows.Err()
}

// CountUnused returns the number of unused backup codes for a user.
func (r *BackupCodeRepo) CountUnused(ctx context.Context, userID string) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id = $1 AND used_at IS NULL`,
		userID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting unused backup codes: %w", err)
	}
	return count, nil
}

// DeleteByUser removes all backup codes for a user.
func (r *BackupCodeRepo) DeleteByUser(ctx context.Context, userID string) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM mfa_backup_codes WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("deleting backup codes: %w", err)
	}
	return nil
}
