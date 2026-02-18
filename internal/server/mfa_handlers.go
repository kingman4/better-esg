package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/kingman4/better-esg/internal/auth"
)

// --- Request/Response types ---

type mfaSetupResponse struct {
	Secret      string   `json:"secret"`
	QRURL       string   `json:"qr_url"`
	BackupCodes []string `json:"backup_codes"`
}

type mfaConfirmRequest struct {
	Code string `json:"code"`
}

type verifyMFARequest struct {
	MFAToken string `json:"mfa_token"`
	Code     string `json:"code"`
}

type mfaDisableRequest struct {
	UserID string `json:"user_id"`
}

// --- Handlers ---

// handleMFASetup handles POST /api/v1/auth/mfa/setup.
// Generates a new TOTP key and backup codes. The TOTP secret is stored temporarily
// in memory until confirmed via handleMFAConfirm.
func (s *Server) handleMFASetup(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	orgID := orgIDFromContext(r.Context())

	// Look up user to get email for TOTP key generation
	user, err := s.users.GetByID(r.Context(), orgID, userID)
	if err != nil {
		s.logger.Error("failed to look up user for MFA setup", "user_id", userID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MFA setup error"})
		return
	}
	if user == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

	if user.MFAEnabled {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "MFA is already enabled"})
		return
	}

	// Generate TOTP key
	key, err := auth.GenerateTOTP(user.Email)
	if err != nil {
		s.logger.Error("failed to generate TOTP key", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MFA setup error"})
		return
	}

	// Generate backup codes
	codes, err := auth.GenerateBackupCodes(10)
	if err != nil {
		s.logger.Error("failed to generate backup codes", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MFA setup error"})
		return
	}

	// Hash backup codes and store in DB
	hashes := make([]string, len(codes))
	for i, code := range codes {
		hash, err := auth.HashBackupCode(code)
		if err != nil {
			s.logger.Error("failed to hash backup code", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MFA setup error"})
			return
		}
		hashes[i] = hash
	}

	if err := s.backupCodes.Create(r.Context(), userID, hashes); err != nil {
		s.logger.Error("failed to store backup codes", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "MFA setup error"})
		return
	}

	// Store temp secret for confirmation step
	s.mfaTempSecrets.Store(userID, tempMFASecret{
		secret:    key.Secret(),
		createdAt: time.Now(),
	})

	s.audit(r, "mfa_setup_initiated", "user", userID, nil)

	writeJSON(w, http.StatusOK, mfaSetupResponse{
		Secret:      key.Secret(),
		QRURL:       key.URL(),
		BackupCodes: codes,
	})
}

// handleMFAConfirm handles POST /api/v1/auth/mfa/confirm.
// Validates a TOTP code against the temp secret from setup, then enables MFA.
func (s *Server) handleMFAConfirm(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	var req mfaConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "code is required"})
		return
	}

	// Retrieve temp secret
	val, ok := s.mfaTempSecrets.Load(userID)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no MFA setup in progress, call /auth/mfa/setup first"})
		return
	}

	temp := val.(tempMFASecret)

	// Enforce TTL (10 minutes for setup flow)
	if time.Since(temp.createdAt) > 10*time.Minute {
		s.mfaTempSecrets.Delete(userID)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "MFA setup expired, please start again"})
		return
	}

	// Validate TOTP code
	if !auth.ValidateTOTP(req.Code, temp.secret) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid TOTP code"})
		return
	}

	// Persist MFA secret and enable MFA
	if err := s.users.SetMFA(r.Context(), userID, temp.secret); err != nil {
		s.logger.Error("failed to enable MFA", "user_id", userID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to enable MFA"})
		return
	}

	s.mfaTempSecrets.Delete(userID)

	s.audit(r, "mfa_enabled", "user", userID, nil)

	writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_enabled"})
}

// handleVerifyMFA handles POST /api/v1/auth/verify-mfa.
// Public endpoint (no withAuth). Validates the MFA token + TOTP code, then issues
// real access + refresh tokens. Also accepts backup codes as fallback.
func (s *Server) handleVerifyMFA(w http.ResponseWriter, r *http.Request) {
	var req verifyMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.MFAToken == "" || req.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mfa_token and code are required"})
		return
	}

	// Verify MFA token
	claims, err := auth.VerifyToken(req.MFAToken, s.jwtSecret)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired MFA token"})
		return
	}

	if claims.Type != auth.TokenTypeMFA {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token type"})
		return
	}

	// Look up user to get MFA secret
	user, err := s.users.GetByID(r.Context(), claims.OrgID, claims.UserID)
	if err != nil {
		s.logger.Error("failed to look up user for MFA verify", "user_id", claims.UserID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "verification error"})
		return
	}
	if user == nil || !user.IsActive {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found or inactive"})
		return
	}

	// Try TOTP validation first
	verified := false
	if user.MFAEnabled && user.MFASecret != nil {
		verified = auth.ValidateTOTP(req.Code, *user.MFASecret)
	}

	// If TOTP failed, try backup code
	if !verified {
		used, err := s.backupCodes.VerifyAndConsume(r.Context(), user.ID, req.Code)
		if err != nil {
			s.logger.Error("failed to verify backup code", "user_id", user.ID, "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "verification error"})
			return
		}
		verified = used
	}

	if !verified {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid code"})
		return
	}

	// MFA verified — issue real tokens
	accessToken, err := auth.SignAccessToken(user.ID, claims.OrgID, claims.Role, s.jwtSecret)
	if err != nil {
		s.logger.Error("failed to sign access token after MFA", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication error"})
		return
	}

	refreshToken, err := s.refreshTokens.Create(r.Context(), user.ID, claims.OrgID, time.Now().Add(7*24*time.Hour))
	if err != nil {
		s.logger.Error("failed to create refresh token after MFA", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication error"})
		return
	}

	// Update last_login (fire-and-forget)
	go func() {
		if err := s.users.UpdateLastLogin(r.Context(), user.ID); err != nil {
			s.logger.Warn("failed to update last_login", "user_id", user.ID, "error", err)
		}
	}()

	s.audit(r, "mfa_verify_success", "user", user.ID, nil)

	writeJSON(w, http.StatusOK, loginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(auth.AccessTokenExpiry().Seconds()),
	})
}

// handleMFADisable handles DELETE /api/v1/auth/mfa.
// Admin-only. Disables MFA for a user and deletes their backup codes.
func (s *Server) handleMFADisable(w http.ResponseWriter, r *http.Request) {
	var req mfaDisableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.UserID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_id is required"})
		return
	}

	orgID := orgIDFromContext(r.Context())

	// Verify target user exists in the same org
	user, err := s.users.GetByID(r.Context(), orgID, req.UserID)
	if err != nil {
		s.logger.Error("failed to look up user for MFA disable", "user_id", req.UserID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to look up user"})
		return
	}
	if user == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

	// Disable MFA
	if err := s.users.DisableMFA(r.Context(), req.UserID); err != nil {
		s.logger.Error("failed to disable MFA", "user_id", req.UserID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to disable MFA"})
		return
	}

	// Delete backup codes
	if err := s.backupCodes.DeleteByUser(r.Context(), req.UserID); err != nil {
		s.logger.Error("failed to delete backup codes", "user_id", req.UserID, "error", err)
		// Non-fatal — MFA is already disabled
	}

	s.audit(r, "mfa_disabled", "user", req.UserID, map[string]any{
		"disabled_by": userIDFromContext(r.Context()),
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_disabled"})
}

// tempMFASecret holds a TOTP secret during the setup→confirm flow.
type tempMFASecret struct {
	secret    string
	createdAt time.Time
}
