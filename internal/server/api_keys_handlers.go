package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/kingman4/better-esg/internal/repository"
)

// --- Request/Response types ---

type createAPIKeyRequest struct {
	UserID string `json:"user_id"`
	Name   string `json:"name"`
	Role   string `json:"role"`
}

type apiKeyResponse struct {
	ID         string  `json:"id"`
	OrgID      string  `json:"org_id"`
	UserID     string  `json:"user_id"`
	KeyPrefix  string  `json:"key_prefix"`
	RawKey     *string `json:"raw_key,omitempty"` // Only on create
	Name       string  `json:"name"`
	Role       string  `json:"role"`
	IsActive   bool    `json:"is_active"`
	LastUsedAt *string `json:"last_used_at,omitempty"`
	ExpiresAt  *string `json:"expires_at,omitempty"`
	CreatedAt  string  `json:"created_at"`
}

func toAPIKeyResponse(k *repository.APIKey, rawKey *string) apiKeyResponse {
	resp := apiKeyResponse{
		ID:        k.ID,
		OrgID:     k.OrgID,
		UserID:    k.UserID,
		KeyPrefix: k.KeyPrefix,
		RawKey:    rawKey,
		Name:      k.Name,
		Role:      k.Role,
		IsActive:  k.IsActive,
		CreatedAt: k.CreatedAt.Format(time.RFC3339),
	}
	if k.LastUsedAt.Valid {
		s := k.LastUsedAt.Time.Format(time.RFC3339)
		resp.LastUsedAt = &s
	}
	if k.ExpiresAt.Valid {
		s := k.ExpiresAt.Time.Format(time.RFC3339)
		resp.ExpiresAt = &s
	}
	return resp
}

// --- Handlers ---

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	orgID := orgIDFromContext(r.Context())

	var req createAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.UserID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_id is required"})
		return
	}

	role := req.Role
	if role == "" {
		role = "submitter"
	}
	if !repository.ValidRoles[role] {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid role: " + role + " (valid: admin, submitter, reviewer, viewer)",
		})
		return
	}

	// Verify the target user exists in the same org
	user, err := s.users.GetByID(r.Context(), orgID, req.UserID)
	if err != nil {
		s.logger.Error("failed to verify user for API key creation", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to verify user"})
		return
	}
	if user == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user not found in this organization"})
		return
	}

	result, err := s.apiKeys.Create(r.Context(), repository.CreateKeyParams{
		OrgID:  orgID,
		UserID: req.UserID,
		Name:   req.Name,
		Role:   role,
	})
	if err != nil {
		s.logger.Error("failed to create API key", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create API key"})
		return
	}

	s.audit(r, "create_api_key", "api_key", result.APIKey.ID, map[string]any{
		"user_id":    req.UserID,
		"role":       role,
		"key_prefix": result.APIKey.KeyPrefix,
	})

	writeJSON(w, http.StatusCreated, toAPIKeyResponse(&result.APIKey, &result.RawKey))
}

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	orgID := orgIDFromContext(r.Context())

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

	keys, err := s.apiKeys.ListByOrg(r.Context(), orgID, limit, offset)
	if err != nil {
		s.logger.Error("failed to list API keys", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list API keys"})
		return
	}

	results := make([]apiKeyResponse, 0, len(keys))
	for i := range keys {
		results = append(results, toAPIKeyResponse(&keys[i], nil))
	}

	writeJSON(w, http.StatusOK, results)
}

func (s *Server) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing api key id"})
		return
	}

	orgID := orgIDFromContext(r.Context())
	if err := s.apiKeys.Revoke(r.Context(), orgID, id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "API key not found"})
		return
	}

	s.audit(r, "revoke_api_key", "api_key", id, nil)

	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
