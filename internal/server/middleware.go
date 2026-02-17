package server

import (
	"net/http"
	"strings"

	"github.com/kingman4/better-esg/internal/auth"
)

// withAuth wraps a handler with authentication.
// When auth is disabled, it injects the default org/user and passes through.
// Otherwise it detects the token type (JWT vs API key) and validates accordingly.
// JWTs contain dots (header.payload.signature); API keys are hex strings.
func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.authDisabled {
			ctx := withAuthContext(r.Context(), s.defaultOrgID, s.defaultUserID, "admin")
			next(w, r.WithContext(ctx))
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing Authorization header"})
			return
		}

		token, ok := parseBearerToken(authHeader)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid Authorization header format, expected: Bearer <token>"})
			return
		}

		if looksLikeJWT(token) {
			s.authenticateJWT(next, w, r, token)
		} else {
			s.authenticateAPIKey(next, w, r, token)
		}
	}
}

// looksLikeJWT returns true if the token looks like a JWT (contains exactly 2 dots).
func looksLikeJWT(token string) bool {
	return strings.Count(token, ".") == 2
}

// authenticateJWT verifies a JWT access token and sets auth context.
func (s *Server) authenticateJWT(next http.HandlerFunc, w http.ResponseWriter, r *http.Request, token string) {
	claims, err := auth.VerifyToken(token, s.jwtSecret)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired token"})
		return
	}

	ctx := withAuthContext(r.Context(), claims.OrgID, claims.UserID, claims.Role)
	next(w, r.WithContext(ctx))
}

// authenticateAPIKey verifies an API key and sets auth context.
func (s *Server) authenticateAPIKey(next http.HandlerFunc, w http.ResponseWriter, r *http.Request, rawKey string) {
	apiKey, err := s.apiKeys.LookupByRawKey(r.Context(), rawKey)
	if err != nil {
		s.logger.Error("failed to look up API key", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication error"})
		return
	}
	if apiKey == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired API key"})
		return
	}

	// Fire-and-forget last_used_at update
	go func() {
		if err := s.apiKeys.TouchLastUsed(r.Context(), apiKey.ID); err != nil {
			s.logger.Warn("failed to update API key last_used_at", "error", err)
		}
	}()

	ctx := withAuthContext(r.Context(), apiKey.OrgID, apiKey.UserID, apiKey.Role)
	next(w, r.WithContext(ctx))
}

// parseBearerToken extracts the token from "Bearer <token>".
func parseBearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}
