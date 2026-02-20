package server

import (
	"net/http"
	"strings"

	"github.com/kingman4/better-esg/internal/auth"
)

const (
	cookieAuthToken    = "auth_token"
	cookieRefreshToken = "refresh_token"
)

// withCookieAuth reads a JWT from the auth_token cookie (falling back to Bearer header)
// and injects org/user/role into the request context. Does NOT enforce auth — if no
// valid token is found, the request proceeds without auth context.
func (s *Server) withCookieAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var tokenStr string

		// Try cookie first
		if cookie, err := r.Cookie(cookieAuthToken); err == nil {
			tokenStr = cookie.Value
		}

		// Fall back to Bearer header (API clients)
		if tokenStr == "" {
			if h := r.Header.Get("Authorization"); h != "" {
				if t, ok := parseBearerToken(h); ok {
					tokenStr = t
				}
			}
		}

		if tokenStr != "" && strings.Contains(tokenStr, ".") {
			claims, err := auth.VerifyToken(tokenStr, s.jwtSecret)
			if err == nil && claims.Type != auth.TokenTypeMFA {
				ctx := withAuthContext(r.Context(), claims.OrgID, claims.UserID, claims.Role)
				r = r.WithContext(ctx)
			}
		}

		next(w, r)
	}
}

// requireWebAuth wraps withCookieAuth and enforces authentication.
// If the user is not authenticated, redirects to the login page.
// When AUTH_DISABLED=true (local dev), auto-injects the default dev user
// so the login page is bypassed entirely.
func (s *Server) requireWebAuth(next http.HandlerFunc) http.HandlerFunc {
	return s.withCookieAuth(func(w http.ResponseWriter, r *http.Request) {
		if userIDFromContext(r.Context()) == "" {
			// In local dev mode, auto-inject the default org/user instead of redirecting to login.
			if s.authDisabled {
				ctx := withAuthContext(r.Context(), s.defaultOrgID, s.defaultUserID, "admin")
				next(w, r.WithContext(ctx))
				return
			}
			redirectURL := "/auth/login"
			if r.URL.Path != "/" && r.URL.Path != "/dashboard" {
				redirectURL += "?next=" + r.URL.Path
			}
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
		next(w, r)
	})
}

// setAuthCookies sets the httpOnly auth cookies on the response.
func setAuthCookies(w http.ResponseWriter, accessToken, refreshToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieAuthToken,
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   900, // 15 minutes
	})
	if refreshToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     cookieRefreshToken,
			Value:    refreshToken,
			Path:     "/auth",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   604800, // 7 days
		})
	}
}

// clearAuthCookies removes auth cookies from the response.
func clearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: cookieAuthToken, Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: cookieRefreshToken, Path: "/auth", MaxAge: -1})
}
