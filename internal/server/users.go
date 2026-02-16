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

type createUserRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

type updateUserRequest struct {
	Role     *string `json:"role,omitempty"`
	IsActive *bool   `json:"is_active,omitempty"`
}

type userResponse struct {
	ID        string `json:"id"`
	OrgID     string `json:"org_id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	IsActive  bool   `json:"is_active"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func toUserResponse(u *repository.User) userResponse {
	return userResponse{
		ID:        u.ID,
		OrgID:     u.OrgID,
		Email:     u.Email,
		Role:      u.Role,
		IsActive:  u.IsActive,
		CreatedAt: u.CreatedAt.Format(time.RFC3339),
		UpdatedAt: u.UpdatedAt.Format(time.RFC3339),
	}
}

// emailRegex is a basic email validation pattern.
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// --- Handlers ---

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	orgID := orgIDFromContext(r.Context())

	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email is required"})
		return
	}
	if !emailRegex.MatchString(req.Email) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid email format"})
		return
	}

	role := req.Role
	if role == "" {
		role = "viewer"
	}
	if !repository.ValidRoles[role] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid role: " + role + " (valid: admin, submitter, reviewer, viewer)"})
		return
	}

	user, err := s.users.Create(r.Context(), repository.CreateUserParams{
		OrgID: orgID,
		Email: req.Email,
		Role:  role,
	})
	if err != nil {
		s.logger.Error("failed to create user", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create user"})
		return
	}

	s.audit(r, "create_user", "user", user.ID, map[string]any{
		"email": user.Email,
		"role":  user.Role,
	})

	writeJSON(w, http.StatusCreated, toUserResponse(user))
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
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

	users, err := s.users.ListByOrg(r.Context(), orgID, limit, offset)
	if err != nil {
		s.logger.Error("failed to list users", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list users"})
		return
	}

	results := make([]userResponse, 0, len(users))
	for i := range users {
		results = append(results, toUserResponse(&users[i]))
	}

	writeJSON(w, http.StatusOK, results)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing user id"})
		return
	}

	orgID := orgIDFromContext(r.Context())
	user, err := s.users.GetByID(r.Context(), orgID, id)
	if err != nil {
		s.logger.Error("failed to get user", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get user"})
		return
	}
	if user == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

	writeJSON(w, http.StatusOK, toUserResponse(user))
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing user id"})
		return
	}

	orgID := orgIDFromContext(r.Context())

	var req updateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	// Validate role if provided
	if req.Role != nil && !repository.ValidRoles[*req.Role] {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid role: " + *req.Role + " (valid: admin, submitter, reviewer, viewer)",
		})
		return
	}

	user, err := s.users.Update(r.Context(), orgID, id, repository.UpdateUserParams{
		Role:     req.Role,
		IsActive: req.IsActive,
	})
	if err != nil {
		s.logger.Error("failed to update user", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update user"})
		return
	}
	if user == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

	s.audit(r, "update_user", "user", id, map[string]any{
		"role":      req.Role,
		"is_active": req.IsActive,
	})

	writeJSON(w, http.StatusOK, toUserResponse(user))
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing user id"})
		return
	}

	// Prevent self-deletion
	userID := userIDFromContext(r.Context())
	if id == userID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot delete your own user"})
		return
	}

	orgID := orgIDFromContext(r.Context())
	if err := s.users.Delete(r.Context(), orgID, id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

	s.audit(r, "delete_user", "user", id, nil)

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
