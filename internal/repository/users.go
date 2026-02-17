package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// User represents a row in the users table.
type User struct {
	ID           string
	OrgID        string
	Email        string
	PasswordHash *string // nil when not set
	Role         string
	IsActive     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// CreateUserParams holds the fields needed to create a new user.
type CreateUserParams struct {
	OrgID string
	Email string
	Role  string
}

// UpdateUserParams holds optional fields for updating a user.
type UpdateUserParams struct {
	Role     *string
	IsActive *bool
}

// UserRepo handles database operations for users.
type UserRepo struct {
	db *sql.DB
}

// NewUserRepo creates a new UserRepo.
func NewUserRepo(db *sql.DB) *UserRepo {
	return &UserRepo{db: db}
}

// ValidRoles is the set of allowed user roles.
var ValidRoles = map[string]bool{
	"admin":     true,
	"submitter": true,
	"reviewer":  true,
	"viewer":    true,
}

// Create inserts a new user and returns it.
func (r *UserRepo) Create(ctx context.Context, p CreateUserParams) (*User, error) {
	role := p.Role
	if role == "" {
		role = "viewer"
	}

	query := `
		INSERT INTO users (org_id, email, role)
		VALUES ($1, $2, $3)
		RETURNING id, org_id, email, password_hash, role, is_active, created_at, updated_at`

	var u User
	err := r.db.QueryRowContext(ctx, query, p.OrgID, p.Email, role).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.PasswordHash, &u.Role, &u.IsActive, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("creating user: %w", err)
	}
	return &u, nil
}

// GetByID returns a user by org and user ID, or nil if not found.
func (r *UserRepo) GetByID(ctx context.Context, orgID, userID string) (*User, error) {
	query := `
		SELECT id, org_id, email, password_hash, role, is_active, created_at, updated_at
		FROM users
		WHERE org_id = $1 AND id = $2`

	var u User
	err := r.db.QueryRowContext(ctx, query, orgID, userID).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.PasswordHash, &u.Role, &u.IsActive, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting user: %w", err)
	}
	return &u, nil
}

// ListByOrg returns users for an org with pagination.
func (r *UserRepo) ListByOrg(ctx context.Context, orgID string, limit, offset int) ([]User, error) {
	query := `
		SELECT id, org_id, email, password_hash, role, is_active, created_at, updated_at
		FROM users
		WHERE org_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.db.QueryContext(ctx, query, orgID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.OrgID, &u.Email, &u.PasswordHash, &u.Role, &u.IsActive, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning user: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// Update modifies a user's role and/or is_active status. Returns the updated user.
func (r *UserRepo) Update(ctx context.Context, orgID, userID string, p UpdateUserParams) (*User, error) {
	// Build SET clause dynamically based on which fields are provided
	query := `UPDATE users SET `
	args := []any{}
	argIdx := 1
	setClauses := []byte{}

	if p.Role != nil {
		if len(setClauses) > 0 {
			setClauses = append(setClauses, ',')
		}
		setClauses = append(setClauses, []byte(fmt.Sprintf("role = $%d", argIdx))...)
		args = append(args, *p.Role)
		argIdx++
	}
	if p.IsActive != nil {
		if len(setClauses) > 0 {
			setClauses = append(setClauses, ',')
		}
		setClauses = append(setClauses, []byte(fmt.Sprintf("is_active = $%d", argIdx))...)
		args = append(args, *p.IsActive)
		argIdx++
	}

	if len(setClauses) == 0 {
		// Nothing to update — just return current user
		return r.GetByID(ctx, orgID, userID)
	}

	query += string(setClauses) + fmt.Sprintf(
		" WHERE org_id = $%d AND id = $%d RETURNING id, org_id, email, password_hash, role, is_active, created_at, updated_at",
		argIdx, argIdx+1,
	)
	args = append(args, orgID, userID)

	var u User
	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.PasswordHash, &u.Role, &u.IsActive, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("updating user: %w", err)
	}
	return &u, nil
}

// Delete soft-deletes a user by setting is_active = false.
func (r *UserRepo) Delete(ctx context.Context, orgID, userID string) error {
	result, err := r.db.ExecContext(ctx,
		`UPDATE users SET is_active = false WHERE org_id = $1 AND id = $2 AND is_active = true`,
		orgID, userID,
	)
	if err != nil {
		return fmt.Errorf("deleting user: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// GetByEmail returns an active user by org ID and email, or nil if not found.
// Includes password_hash for credential verification.
func (r *UserRepo) GetByEmail(ctx context.Context, orgID, email string) (*User, error) {
	query := `
		SELECT id, org_id, email, password_hash, role, is_active, created_at, updated_at
		FROM users
		WHERE org_id = $1 AND email = $2 AND is_active = true`

	var u User
	err := r.db.QueryRowContext(ctx, query, orgID, email).Scan(
		&u.ID, &u.OrgID, &u.Email, &u.PasswordHash, &u.Role, &u.IsActive, &u.CreatedAt, &u.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting user by email: %w", err)
	}
	return &u, nil
}

// SetPassword updates a user's password_hash.
func (r *UserRepo) SetPassword(ctx context.Context, userID, hash string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET password_hash = $1 WHERE id = $2`,
		hash, userID,
	)
	if err != nil {
		return fmt.Errorf("setting password: %w", err)
	}
	return nil
}

// UpdateLastLogin sets last_login = NOW() for the given user.
func (r *UserRepo) UpdateLastLogin(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE users SET last_login = NOW() WHERE id = $1`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("updating last login: %w", err)
	}
	return nil
}
