package repository

import (
	"context"
	"database/sql"
	"fmt"
)

// Org represents a row in the organizations table.
type Org struct {
	ID   string
	Name string
	Slug string
}

// OrgRepo handles database operations for organizations.
type OrgRepo struct {
	db *sql.DB
}

// NewOrgRepo creates a new OrgRepo.
func NewOrgRepo(db *sql.DB) *OrgRepo {
	return &OrgRepo{db: db}
}

// GetBySlug returns an organization by slug, or nil if not found.
func (r *OrgRepo) GetBySlug(ctx context.Context, slug string) (*Org, error) {
	query := `SELECT id, name, slug FROM organizations WHERE slug = $1`

	var o Org
	err := r.db.QueryRowContext(ctx, query, slug).Scan(&o.ID, &o.Name, &o.Slug)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting org by slug: %w", err)
	}
	return &o, nil
}
