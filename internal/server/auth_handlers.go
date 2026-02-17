package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/kingman4/better-esg/internal/auth"
)

// loginRequest is the JSON body for POST /api/v1/auth/login.
type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	OrgSlug  string `json:"org_slug"`
}

// loginResponse is returned on successful login.
type loginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"` // seconds
}

// refreshRequest is the JSON body for POST /api/v1/auth/refresh.
type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// refreshResponse is returned on successful token refresh.
type refreshResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// logoutRequest is the JSON body for POST /api/v1/auth/logout.
type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// setPasswordRequest is the JSON body for PATCH /api/v1/users/{id}/password.
type setPasswordRequest struct {
	Password string `json:"password"`
}

// handleLogin handles POST /api/v1/auth/login.
// Authenticates via email + password + org_slug, returns JWT access + refresh tokens.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Email == "" || req.Password == "" || req.OrgSlug == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email, password, and org_slug are required"})
		return
	}

	// Resolve org by slug
	org, err := s.orgs.GetBySlug(r.Context(), req.OrgSlug)
	if err != nil {
		s.logger.Error("failed to look up org", "slug", req.OrgSlug, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication error"})
		return
	}
	if org == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	// Look up user by email in that org
	user, err := s.users.GetByEmail(r.Context(), org.ID, req.Email)
	if err != nil {
		s.logger.Error("failed to look up user", "email", req.Email, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication error"})
		return
	}
	if user == nil || user.PasswordHash == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	// Verify password
	if err := auth.CheckPassword(req.Password, *user.PasswordHash); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	// Sign tokens
	accessToken, err := auth.SignAccessToken(user.ID, org.ID, user.Role, s.jwtSecret)
	if err != nil {
		s.logger.Error("failed to sign access token", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication error"})
		return
	}

	refreshToken, err := s.refreshTokens.Create(r.Context(), user.ID, org.ID, time.Now().Add(7*24*time.Hour))
	if err != nil {
		s.logger.Error("failed to create refresh token", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication error"})
		return
	}

	// Update last_login (fire-and-forget)
	go func() {
		if err := s.users.UpdateLastLogin(r.Context(), user.ID); err != nil {
			s.logger.Warn("failed to update last_login", "user_id", user.ID, "error", err)
		}
	}()

	s.audit(r, "login_success", "user", user.ID, map[string]any{
		"org_slug": req.OrgSlug,
		"email":    req.Email,
	})

	writeJSON(w, http.StatusOK, loginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(auth.AccessTokenExpiry().Seconds()),
	})
}

// handleRefresh handles POST /api/v1/auth/refresh.
// Validates the refresh token and issues a new access token with current role.
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.RefreshToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "refresh_token is required"})
		return
	}

	// Validate the refresh token
	token, err := s.refreshTokens.Validate(r.Context(), req.RefreshToken)
	if err != nil {
		s.logger.Error("failed to validate refresh token", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication error"})
		return
	}
	if token == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired refresh token"})
		return
	}

	// Look up user to get current role (role may have changed since last login)
	user, err := s.users.GetByID(r.Context(), token.OrgID, token.UserID)
	if err != nil {
		s.logger.Error("failed to look up user for refresh", "user_id", token.UserID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication error"})
		return
	}
	if user == nil || !user.IsActive {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found or inactive"})
		return
	}

	accessToken, err := auth.SignAccessToken(user.ID, token.OrgID, user.Role, s.jwtSecret)
	if err != nil {
		s.logger.Error("failed to sign access token", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication error"})
		return
	}

	writeJSON(w, http.StatusOK, refreshResponse{
		AccessToken: accessToken,
		ExpiresIn:   int(auth.AccessTokenExpiry().Seconds()),
	})
}

// handleLogout handles POST /api/v1/auth/logout.
// Revokes the provided refresh token.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var req logoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.RefreshToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "refresh_token is required"})
		return
	}

	// Validate first to get the token record, then revoke by hash
	token, err := s.refreshTokens.Validate(r.Context(), req.RefreshToken)
	if err != nil {
		s.logger.Error("failed to validate refresh token for logout", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "logout error"})
		return
	}
	if token != nil {
		if err := s.refreshTokens.Revoke(r.Context(), token.TokenHash); err != nil {
			s.logger.Error("failed to revoke refresh token", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "logout error"})
			return
		}
	}

	// Always return success (don't reveal whether the token was valid)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// handleSetPassword handles PATCH /api/v1/users/{id}/password.
// Admin-only. Sets the password hash for a user.
func (s *Server) handleSetPassword(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if userID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing user id"})
		return
	}

	var req setPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if len(req.Password) < 8 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
		return
	}

	orgID := orgIDFromContext(r.Context())

	// Verify user exists in the same org
	user, err := s.users.GetByID(r.Context(), orgID, userID)
	if err != nil {
		s.logger.Error("failed to look up user", "user_id", userID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to look up user"})
		return
	}
	if user == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		s.logger.Error("failed to hash password", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to set password"})
		return
	}

	if err := s.users.SetPassword(r.Context(), userID, hash); err != nil {
		s.logger.Error("failed to set password", "user_id", userID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to set password"})
		return
	}

	s.audit(r, "set_user_password", "user", userID, nil)

	writeJSON(w, http.StatusOK, map[string]string{"status": "password_set"})
}
