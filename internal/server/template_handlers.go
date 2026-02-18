package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/kingman4/better-esg/internal/repository"
)

// --- Request/Response types ---

type createTemplateRequest struct {
	Name               string `json:"name"`
	Description        string `json:"description,omitempty"`
	FDACenter          string `json:"fda_center,omitempty"`
	SubmissionType     string `json:"submission_type"`
	SubmissionProtocol string `json:"submission_protocol,omitempty"`
	DefaultFileCount   int    `json:"default_file_count,omitempty"`
}

type updateTemplateRequest struct {
	Name               *string `json:"name,omitempty"`
	Description        *string `json:"description,omitempty"`
	FDACenter          *string `json:"fda_center,omitempty"`
	SubmissionType     *string `json:"submission_type,omitempty"`
	SubmissionProtocol *string `json:"submission_protocol,omitempty"`
	DefaultFileCount   *int    `json:"default_file_count,omitempty"`
}

type templateResponse struct {
	ID                 string  `json:"id"`
	OrgID              string  `json:"org_id"`
	Name               string  `json:"name"`
	Description        *string `json:"description,omitempty"`
	FDACenter          *string `json:"fda_center,omitempty"`
	SubmissionType     string  `json:"submission_type"`
	SubmissionProtocol string  `json:"submission_protocol"`
	DefaultFileCount   int     `json:"default_file_count"`
	CreatedBy          string  `json:"created_by"`
	CreatedAt          string  `json:"created_at"`
	UpdatedAt          string  `json:"updated_at"`
}

func toTemplateResponse(t *repository.SubmissionTemplate) templateResponse {
	resp := templateResponse{
		ID:                 t.ID,
		OrgID:              t.OrgID,
		Name:               t.Name,
		SubmissionType:     t.SubmissionType,
		SubmissionProtocol: t.SubmissionProtocol,
		DefaultFileCount:   t.DefaultFileCount,
		CreatedBy:          t.CreatedBy,
		CreatedAt:          t.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:          t.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
	if t.Description.Valid {
		resp.Description = &t.Description.String
	}
	if t.FDACenter.Valid {
		resp.FDACenter = &t.FDACenter.String
	}
	return resp
}

// --- Handlers ---

// handleCreateTemplate handles POST /api/v1/submission-templates.
func (s *Server) handleCreateTemplate(w http.ResponseWriter, r *http.Request) {
	orgID := orgIDFromContext(r.Context())
	userID := userIDFromContext(r.Context())

	var req createTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	if req.SubmissionType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "submission_type is required"})
		return
	}
	if req.DefaultFileCount < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "default_file_count must be non-negative"})
		return
	}

	t, err := s.templates.Create(r.Context(), repository.CreateTemplateParams{
		OrgID:              orgID,
		Name:               req.Name,
		Description:        req.Description,
		FDACenter:          req.FDACenter,
		SubmissionType:     req.SubmissionType,
		SubmissionProtocol: req.SubmissionProtocol,
		DefaultFileCount:   req.DefaultFileCount,
		CreatedBy:          userID,
	})
	if err != nil {
		s.logger.Error("failed to create template", "org_id", orgID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create template"})
		return
	}

	s.audit(r, "create_template", "submission_template", t.ID, map[string]any{
		"name":            req.Name,
		"submission_type": req.SubmissionType,
	})

	writeJSON(w, http.StatusCreated, toTemplateResponse(t))
}

// handleListTemplates handles GET /api/v1/submission-templates.
func (s *Server) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	orgID := orgIDFromContext(r.Context())

	limit := 50
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 200 {
			limit = v
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}

	templates, err := s.templates.ListByOrg(r.Context(), orgID, limit, offset)
	if err != nil {
		s.logger.Error("failed to list templates", "org_id", orgID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list templates"})
		return
	}

	resp := make([]templateResponse, len(templates))
	for i := range templates {
		resp[i] = toTemplateResponse(&templates[i])
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleGetTemplate handles GET /api/v1/submission-templates/{id}.
func (s *Server) handleGetTemplate(w http.ResponseWriter, r *http.Request) {
	orgID := orgIDFromContext(r.Context())
	id := r.PathValue("id")

	t, err := s.templates.GetByID(r.Context(), orgID, id)
	if err != nil {
		s.logger.Error("failed to get template", "org_id", orgID, "id", id, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get template"})
		return
	}
	if t == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "template not found"})
		return
	}

	writeJSON(w, http.StatusOK, toTemplateResponse(t))
}

// handleUpdateTemplate handles PATCH /api/v1/submission-templates/{id}.
func (s *Server) handleUpdateTemplate(w http.ResponseWriter, r *http.Request) {
	orgID := orgIDFromContext(r.Context())
	id := r.PathValue("id")

	var req updateTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Name != nil && *req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name cannot be empty"})
		return
	}
	if req.SubmissionType != nil && *req.SubmissionType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "submission_type cannot be empty"})
		return
	}
	if req.DefaultFileCount != nil && *req.DefaultFileCount < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "default_file_count must be non-negative"})
		return
	}

	t, err := s.templates.Update(r.Context(), orgID, id, repository.UpdateTemplateParams{
		Name:               req.Name,
		Description:        req.Description,
		FDACenter:          req.FDACenter,
		SubmissionType:     req.SubmissionType,
		SubmissionProtocol: req.SubmissionProtocol,
		DefaultFileCount:   req.DefaultFileCount,
	})
	if err != nil {
		s.logger.Error("failed to update template", "org_id", orgID, "id", id, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update template"})
		return
	}
	if t == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "template not found"})
		return
	}

	s.audit(r, "update_template", "submission_template", t.ID, nil)

	writeJSON(w, http.StatusOK, toTemplateResponse(t))
}

// handleDeleteTemplate handles DELETE /api/v1/submission-templates/{id}.
func (s *Server) handleDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	orgID := orgIDFromContext(r.Context())
	id := r.PathValue("id")

	if err := s.templates.Delete(r.Context(), orgID, id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "template not found"})
		return
	}

	s.audit(r, "delete_template", "submission_template", id, nil)

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
