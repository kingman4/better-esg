package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// SubmissionTemplate represents a row in the submission_templates table.
type SubmissionTemplate struct {
	ID                 string
	OrgID              string
	Name               string
	Description        sql.NullString
	FDACenter          sql.NullString
	SubmissionType     string
	SubmissionProtocol string
	DefaultFileCount   int
	IsActive           bool
	CreatedBy          string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// CreateTemplateParams holds the fields needed to create a submission template.
type CreateTemplateParams struct {
	OrgID              string
	Name               string
	Description        string
	FDACenter          string
	SubmissionType     string
	SubmissionProtocol string
	DefaultFileCount   int
	CreatedBy          string
}

// UpdateTemplateParams holds optional fields for updating a submission template.
type UpdateTemplateParams struct {
	Name               *string
	Description        *string
	FDACenter          *string
	SubmissionType     *string
	SubmissionProtocol *string
	DefaultFileCount   *int
}

// SubmissionTemplateRepo handles database operations for submission templates.
type SubmissionTemplateRepo struct {
	db *sql.DB
}

// NewSubmissionTemplateRepo creates a new SubmissionTemplateRepo.
func NewSubmissionTemplateRepo(db *sql.DB) *SubmissionTemplateRepo {
	return &SubmissionTemplateRepo{db: db}
}

const templateColumns = `id, org_id, name, description, fda_center, submission_type, submission_protocol, default_file_count, is_active, created_by, created_at, updated_at`

func scanTemplate(row interface{ Scan(...any) error }) (*SubmissionTemplate, error) {
	var t SubmissionTemplate
	err := row.Scan(
		&t.ID, &t.OrgID, &t.Name, &t.Description, &t.FDACenter,
		&t.SubmissionType, &t.SubmissionProtocol, &t.DefaultFileCount,
		&t.IsActive, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt,
	)
	return &t, err
}

// Create inserts a new submission template.
func (r *SubmissionTemplateRepo) Create(ctx context.Context, p CreateTemplateParams) (*SubmissionTemplate, error) {
	protocol := p.SubmissionProtocol
	if protocol == "" {
		protocol = "API"
	}
	fileCount := p.DefaultFileCount
	if fileCount < 1 {
		fileCount = 1
	}

	query := `
		INSERT INTO submission_templates (org_id, name, description, fda_center, submission_type, submission_protocol, default_file_count, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING ` + templateColumns

	t, err := scanTemplate(r.db.QueryRowContext(ctx, query,
		p.OrgID, p.Name, nullString(p.Description), nullString(p.FDACenter),
		p.SubmissionType, protocol, fileCount, p.CreatedBy,
	))
	if err != nil {
		return nil, fmt.Errorf("creating template: %w", err)
	}
	return t, nil
}

// GetByID returns a single template scoped to the org. Returns nil if not found or inactive.
func (r *SubmissionTemplateRepo) GetByID(ctx context.Context, orgID, id string) (*SubmissionTemplate, error) {
	query := `SELECT ` + templateColumns + ` FROM submission_templates WHERE id = $1 AND org_id = $2 AND is_active = true`

	t, err := scanTemplate(r.db.QueryRowContext(ctx, query, id, orgID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting template: %w", err)
	}
	return t, nil
}

// ListByOrg returns active templates for an org with pagination.
func (r *SubmissionTemplateRepo) ListByOrg(ctx context.Context, orgID string, limit, offset int) ([]SubmissionTemplate, error) {
	query := `SELECT ` + templateColumns + ` FROM submission_templates WHERE org_id = $1 AND is_active = true ORDER BY name ASC LIMIT $2 OFFSET $3`

	rows, err := r.db.QueryContext(ctx, query, orgID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("listing templates: %w", err)
	}
	defer rows.Close()

	var templates []SubmissionTemplate
	for rows.Next() {
		t, err := scanTemplate(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning template: %w", err)
		}
		templates = append(templates, *t)
	}
	return templates, rows.Err()
}

// Update modifies a template's fields. Returns the updated template or nil if not found.
func (r *SubmissionTemplateRepo) Update(ctx context.Context, orgID, id string, p UpdateTemplateParams) (*SubmissionTemplate, error) {
	setClauses := []string{}
	args := []any{}
	argN := 1

	if p.Name != nil {
		setClauses = append(setClauses, fmt.Sprintf("name = $%d", argN))
		args = append(args, *p.Name)
		argN++
	}
	if p.Description != nil {
		setClauses = append(setClauses, fmt.Sprintf("description = $%d", argN))
		args = append(args, nullString(*p.Description))
		argN++
	}
	if p.FDACenter != nil {
		setClauses = append(setClauses, fmt.Sprintf("fda_center = $%d", argN))
		args = append(args, nullString(*p.FDACenter))
		argN++
	}
	if p.SubmissionType != nil {
		setClauses = append(setClauses, fmt.Sprintf("submission_type = $%d", argN))
		args = append(args, *p.SubmissionType)
		argN++
	}
	if p.SubmissionProtocol != nil {
		setClauses = append(setClauses, fmt.Sprintf("submission_protocol = $%d", argN))
		args = append(args, *p.SubmissionProtocol)
		argN++
	}
	if p.DefaultFileCount != nil {
		setClauses = append(setClauses, fmt.Sprintf("default_file_count = $%d", argN))
		args = append(args, *p.DefaultFileCount)
		argN++
	}

	if len(setClauses) == 0 {
		return r.GetByID(ctx, orgID, id)
	}

	setStr := ""
	for i, c := range setClauses {
		if i > 0 {
			setStr += ", "
		}
		setStr += c
	}

	query := fmt.Sprintf(`UPDATE submission_templates SET %s WHERE id = $%d AND org_id = $%d AND is_active = true RETURNING %s`,
		setStr, argN, argN+1, templateColumns)
	args = append(args, id, orgID)

	t, err := scanTemplate(r.db.QueryRowContext(ctx, query, args...))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("updating template: %w", err)
	}
	return t, nil
}

// Delete soft-deletes a template by setting is_active = false.
func (r *SubmissionTemplateRepo) Delete(ctx context.Context, orgID, id string) error {
	result, err := r.db.ExecContext(ctx,
		`UPDATE submission_templates SET is_active = false WHERE id = $1 AND org_id = $2 AND is_active = true`,
		id, orgID,
	)
	if err != nil {
		return fmt.Errorf("deleting template: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}
