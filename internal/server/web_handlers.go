package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/kingman4/better-esg/internal/auth"
	"github.com/kingman4/better-esg/internal/views/pages"
)

// handleLoginPage renders the login form. If already authenticated, redirects to dashboard.
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// In local dev mode, skip login entirely
	if s.authDisabled {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	// If already authenticated via cookie, redirect to dashboard
	if userIDFromContext(r.Context()) != "" {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	pages.LoginPage(pages.LoginData{Env: s.fdaEnvironment}).Render(r.Context(), w)
}

// handleWebLogin processes the login form submission.
func (s *Server) handleWebLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderLoginError(w, r, "Invalid form data", "", "")
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	orgSlug := r.FormValue("org_slug")

	if email == "" || password == "" || orgSlug == "" {
		s.renderLoginError(w, r, "All fields are required", email, orgSlug)
		return
	}

	// Resolve org
	org, err := s.orgs.GetBySlug(r.Context(), orgSlug)
	if err != nil {
		s.logger.Error("login: failed to look up org", "slug", orgSlug, "error", err)
		s.renderLoginError(w, r, "Invalid credentials", email, orgSlug)
		return
	}
	if org == nil {
		s.renderLoginError(w, r, "Invalid credentials", email, orgSlug)
		return
	}

	// Look up user
	user, err := s.users.GetByEmail(r.Context(), org.ID, email)
	if err != nil {
		s.logger.Error("login: failed to look up user", "email", email, "error", err)
		s.renderLoginError(w, r, "Invalid credentials", email, orgSlug)
		return
	}
	if user == nil || user.PasswordHash == nil {
		s.renderLoginError(w, r, "Invalid credentials", email, orgSlug)
		return
	}

	// Verify password
	if err := auth.CheckPassword(password, *user.PasswordHash); err != nil {
		s.renderLoginError(w, r, "Invalid credentials", email, orgSlug)
		return
	}

	// Check MFA
	mfaRequired := user.MFAEnabled || org.MFARequired
	if mfaRequired {
		mfaToken, err := auth.SignMFAToken(user.ID, org.ID, user.Role, s.jwtSecret)
		if err != nil {
			s.logger.Error("login: failed to sign MFA token", "error", err)
			s.renderLoginError(w, r, "Authentication error", email, orgSlug)
			return
		}

		pages.LoginPage(pages.LoginData{
			Env:            s.fdaEnvironment,
			MFARequired:    true,
			MFAToken:       mfaToken,
			MFASetupNeeded: !user.MFAEnabled && org.MFARequired,
			Email:          email,
			OrgSlug:        orgSlug,
		}).Render(r.Context(), w)
		return
	}

	// Issue tokens and set cookies
	s.issueWebSession(w, r, user.ID, org.ID, user.Role)
}

// handleWebVerifyMFA processes the MFA verification form.
func (s *Server) handleWebVerifyMFA(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderLoginError(w, r, "Invalid form data", "", "")
		return
	}

	mfaToken := r.FormValue("mfa_token")
	totpCode := r.FormValue("totp_code")

	if mfaToken == "" || totpCode == "" {
		s.renderLoginError(w, r, "Authentication code is required", "", "")
		return
	}

	// Verify MFA token
	claims, err := auth.VerifyToken(mfaToken, s.jwtSecret)
	if err != nil || claims.Type != auth.TokenTypeMFA {
		s.renderLoginError(w, r, "MFA session expired. Please log in again.", "", "")
		return
	}

	// Look up user to get TOTP secret
	user, err := s.users.GetByID(r.Context(), claims.OrgID, claims.UserID)
	if err != nil || user == nil {
		s.renderLoginError(w, r, "Authentication error", "", "")
		return
	}

	// Try TOTP
	valid := false
	if user.MFASecret != nil {
		valid = auth.ValidateTOTP(totpCode, *user.MFASecret)
	}

	// Try backup code
	if !valid {
		consumed, err := s.backupCodes.VerifyAndConsume(r.Context(), user.ID, totpCode)
		if err == nil && consumed {
			valid = true
		}
	}

	if !valid {
		pages.LoginPage(pages.LoginData{
			Env:         s.fdaEnvironment,
			Error:       "Invalid authentication code",
			MFARequired: true,
			MFAToken:    mfaToken,
		}).Render(r.Context(), w)
		return
	}

	// Issue tokens and set cookies
	s.issueWebSession(w, r, user.ID, claims.OrgID, claims.Role)
}

// handleWebLogout clears auth cookies and redirects to login.
func (s *Server) handleWebLogout(w http.ResponseWriter, r *http.Request) {
	clearAuthCookies(w)
	http.Redirect(w, r, "/auth/login", http.StatusFound)
}

// issueWebSession creates access + refresh tokens, sets cookies, and redirects to dashboard.
func (s *Server) issueWebSession(w http.ResponseWriter, r *http.Request, userID, orgID, role string) {
	accessToken, err := auth.SignAccessToken(userID, orgID, role, s.jwtSecret)
	if err != nil {
		s.logger.Error("login: failed to sign access token", "error", err)
		s.renderLoginError(w, r, "Authentication error", "", "")
		return
	}

	refreshToken, err := s.refreshTokens.Create(r.Context(), userID, orgID, time.Now().Add(7*24*time.Hour))
	if err != nil {
		s.logger.Error("login: failed to create refresh token", "error", err)
		s.renderLoginError(w, r, "Authentication error", "", "")
		return
	}

	setAuthCookies(w, accessToken, refreshToken)

	// Redirect to next URL or dashboard (prevent open redirect)
	next := r.URL.Query().Get("next")
	if next == "" {
		next = r.FormValue("next")
	}
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/dashboard"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

// renderLoginError re-renders the login page with an error message.
func (s *Server) renderLoginError(w http.ResponseWriter, r *http.Request, errMsg, email, orgSlug string) {
	w.WriteHeader(http.StatusUnauthorized)
	pages.LoginPage(pages.LoginData{
		Env:     s.fdaEnvironment,
		Error:   errMsg,
		Email:   email,
		OrgSlug: orgSlug,
	}).Render(r.Context(), w)
}
