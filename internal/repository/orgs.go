package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Org represents a row in the organizations table.
type Org struct {
	ID                string
	Name              string
	Slug              string
	Industry          *string
	SettingsJSON      json.RawMessage
	MFARequired       bool
	DataRetentionDays int
	IsActive          bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// CreateOrgParams holds the fields needed to create a new organization.
type CreateOrgParams struct {
	Name              string
	Slug              string
	Industry          *string
	MFARequired       bool
	DataRetentionDays int // 0 uses DB default (2555)
}

// UpdateOrgParams holds optional fields for updating an organization.
type UpdateOrgParams struct {
	Name              *string
	Industry          *string
	MFARequired       *bool
	DataRetentionDays *int
}

// OrgRepo handles database operations for organizations.
type OrgRepo struct {
	db *sql.DB
}

// NewOrgRepo creates a new OrgRepo.
func NewOrgRepo(db *sql.DB) *OrgRepo {
	return &OrgRepo{db: db}
}

// allColumns is the SELECT column list shared by all org queries.
const orgColumns = `id, name, slug, industry, settings_json, mfa_required, data_retention_days, is_active, created_at, updated_at`

// scanOrg scans a row into an Org struct.
func scanOrg(row interface{ Scan(...any) error }) (*Org, error) {
	var o Org
	err := row.Scan(
		&o.ID, &o.Name, &o.Slug, &o.Industry, &o.SettingsJSON,
		&o.MFARequired, &o.DataRetentionDays, &o.IsActive, &o.CreatedAt, &o.UpdatedAt,
	)
	return &o, err
}

// Create inserts a new organization and returns it.
func (r *OrgRepo) Create(ctx context.Context, p CreateOrgParams) (*Org, error) {
	query := `
		INSERT INTO organizations (name, slug, industry, mfa_required, data_retention_days)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING ` + orgColumns

	retentionDays := p.DataRetentionDays
	if retentionDays <= 0 {
		retentionDays = 2555 // DB default
	}

	o, err := scanOrg(r.db.QueryRowContext(ctx, query, p.Name, p.Slug, p.Industry, p.MFARequired, retentionDays))
	if err != nil {
		return nil, fmt.Errorf("creating org: %w", err)
	}
	return o, nil
}

// GetByID returns an organization by ID, or nil if not found.
func (r *OrgRepo) GetByID(ctx context.Context, id string) (*Org, error) {
	query := `SELECT ` + orgColumns + ` FROM organizations WHERE id = $1`

	o, err := scanOrg(r.db.QueryRowContext(ctx, query, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting org by id: %w", err)
	}
	return o, nil
}

// GetBySlug returns an organization by slug, or nil if not found.
func (r *OrgRepo) GetBySlug(ctx context.Context, slug string) (*Org, error) {
	query := `SELECT ` + orgColumns + ` FROM organizations WHERE slug = $1`

	o, err := scanOrg(r.db.QueryRowContext(ctx, query, slug))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting org by slug: %w", err)
	}
	return o, nil
}

// List returns organizations with pagination.
func (r *OrgRepo) List(ctx context.Context, limit, offset int) ([]Org, error) {
	query := `SELECT ` + orgColumns + ` FROM organizations ORDER BY created_at DESC LIMIT $1 OFFSET $2`

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("listing orgs: %w", err)
	}
	defer rows.Close()

	var orgs []Org
	for rows.Next() {
		o, err := scanOrg(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning org: %w", err)
		}
		orgs = append(orgs, *o)
	}
	return orgs, rows.Err()
}

// Update modifies an organization's fields. Returns the updated org or nil if not found.
func (r *OrgRepo) Update(ctx context.Context, id string, p UpdateOrgParams) (*Org, error) {
	query := `UPDATE organizations SET `
	args := []any{}
	argIdx := 1
	setClauses := []byte{}

	if p.Name != nil {
		if len(setClauses) > 0 {
			setClauses = append(setClauses, ',')
		}
		setClauses = append(setClauses, []byte(fmt.Sprintf("name = $%d", argIdx))...)
		args = append(args, *p.Name)
		argIdx++
	}
	if p.Industry != nil {
		if len(setClauses) > 0 {
			setClauses = append(setClauses, ',')
		}
		setClauses = append(setClauses, []byte(fmt.Sprintf("industry = $%d", argIdx))...)
		args = append(args, *p.Industry)
		argIdx++
	}
	if p.MFARequired != nil {
		if len(setClauses) > 0 {
			setClauses = append(setClauses, ',')
		}
		setClauses = append(setClauses, []byte(fmt.Sprintf("mfa_required = $%d", argIdx))...)
		args = append(args, *p.MFARequired)
		argIdx++
	}
	if p.DataRetentionDays != nil {
		if len(setClauses) > 0 {
			setClauses = append(setClauses, ',')
		}
		setClauses = append(setClauses, []byte(fmt.Sprintf("data_retention_days = $%d", argIdx))...)
		args = append(args, *p.DataRetentionDays)
		argIdx++
	}

	if len(setClauses) == 0 {
		return r.GetByID(ctx, id)
	}

	query += string(setClauses) + fmt.Sprintf(
		" WHERE id = $%d RETURNING "+orgColumns,
		argIdx,
	)
	args = append(args, id)

	o, err := scanOrg(r.db.QueryRowContext(ctx, query, args...))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("updating org: %w", err)
	}
	return o, nil
}

// Delete soft-deletes an organization by setting is_active = false.
func (r *OrgRepo) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx,
		`UPDATE organizations SET is_active = false WHERE id = $1 AND is_active = true`,
		id,
	)
	if err != nil {
		return fmt.Errorf("deleting org: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}
