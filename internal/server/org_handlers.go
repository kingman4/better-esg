package server

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/kingman4/better-esg/internal/repository"
)

// --- Request/Response types ---

type createOrgRequest struct {
	Name              string  `json:"name"`
	Slug              string  `json:"slug"`
	Industry          *string `json:"industry,omitempty"`
	MFARequired       bool    `json:"mfa_required"`
	DataRetentionDays int     `json:"data_retention_days,omitempty"`
}

type updateOrgRequest struct {
	Name              *string `json:"name,omitempty"`
	Industry          *string `json:"industry,omitempty"`
	MFARequired       *bool   `json:"mfa_required,omitempty"`
	DataRetentionDays *int    `json:"data_retention_days,omitempty"`
}

type orgResponse struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Slug              string `json:"slug"`
	Industry          string `json:"industry,omitempty"`
	MFARequired       bool   `json:"mfa_required"`
	DataRetentionDays int    `json:"data_retention_days"`
	IsActive          bool   `json:"is_active"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

func toOrgResponse(o *repository.Org) orgResponse {
	industry := ""
	if o.Industry != nil {
		industry = *o.Industry
	}
	return orgResponse{
		ID:                o.ID,
		Name:              o.Name,
		Slug:              o.Slug,
		Industry:          industry,
		MFARequired:       o.MFARequired,
		DataRetentionDays: o.DataRetentionDays,
		IsActive:          o.IsActive,
		CreatedAt:         o.CreatedAt.Format(time.RFC3339),
		UpdatedAt:         o.UpdatedAt.Format(time.RFC3339),
	}
}

// slugRegex validates org slugs: lowercase alphanumeric + hyphens, 3-100 chars.
// Must start and end with alphanumeric.
var slugRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9\-]{1,98}[a-z0-9]$`)

// --- Handlers ---

func (s *Server) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	var req createOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	if req.Slug == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "slug is required"})
		return
	}
	if !slugRegex.MatchString(req.Slug) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid slug: must be 3-100 chars, lowercase alphanumeric and hyphens, starting and ending with alphanumeric"})
		return
	}
	if req.DataRetentionDays < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "data_retention_days must be non-negative"})
		return
	}

	org, err := s.orgs.Create(r.Context(), repository.CreateOrgParams{
		Name:              req.Name,
		Slug:              req.Slug,
		Industry:          req.Industry,
		MFARequired:       req.MFARequired,
		DataRetentionDays: req.DataRetentionDays,
	})
	if err != nil {
		s.logger.Error("failed to create org", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create org"})
		return
	}

	s.audit(r, "create_org", "org", org.ID, map[string]any{
		"name": org.Name,
		"slug": org.Slug,
	})

	writeJSON(w, http.StatusCreated, toOrgResponse(org))
}

func (s *Server) handleListOrgs(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	offset := 0
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	orgs, err := s.orgs.List(r.Context(), limit, offset)
	if err != nil {
		s.logger.Error("failed to list orgs", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list orgs"})
		return
	}

	results := make([]orgResponse, 0, len(orgs))
	for i := range orgs {
		results = append(results, toOrgResponse(&orgs[i]))
	}

	writeJSON(w, http.StatusOK, results)
}

func (s *Server) handleGetOrg(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing org id"})
		return
	}

	org, err := s.orgs.GetByID(r.Context(), id)
	if err != nil {
		s.logger.Error("failed to get org", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get org"})
		return
	}
	if org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "org not found"})
		return
	}

	writeJSON(w, http.StatusOK, toOrgResponse(org))
}

func (s *Server) handleUpdateOrg(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing org id"})
		return
	}

	var req updateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Name != nil && *req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name cannot be empty"})
		return
	}
	if req.DataRetentionDays != nil && *req.DataRetentionDays <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "data_retention_days must be positive"})
		return
	}

	org, err := s.orgs.Update(r.Context(), id, repository.UpdateOrgParams{
		Name:              req.Name,
		Industry:          req.Industry,
		MFARequired:       req.MFARequired,
		DataRetentionDays: req.DataRetentionDays,
	})
	if err != nil {
		s.logger.Error("failed to update org", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update org"})
		return
	}
	if org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "org not found"})
		return
	}

	s.audit(r, "update_org", "org", id, map[string]any{
		"name":                req.Name,
		"industry":            req.Industry,
		"mfa_required":        req.MFARequired,
		"data_retention_days": req.DataRetentionDays,
	})

	writeJSON(w, http.StatusOK, toOrgResponse(org))
}

func (s *Server) handleDeleteOrg(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing org id"})
		return
	}

	// Prevent deleting the caller's own org
	callerOrgID := orgIDFromContext(r.Context())
	if id == callerOrgID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot delete your own organization"})
		return
	}

	if err := s.orgs.Delete(r.Context(), id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "org not found"})
		return
	}

	s.audit(r, "delete_org", "org", id, nil)

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
