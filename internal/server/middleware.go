package server

import (
	"log"
	"net/http"
	"strings"
)

// withAuth wraps a handler with API key authentication.
// When auth is disabled, it injects the default org/user and passes through.
// Otherwise it validates the Bearer token against the api_keys table.
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

		rawKey, ok := parseBearerToken(authHeader)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid Authorization header format, expected: Bearer <api_key>"})
			return
		}

		apiKey, err := s.apiKeys.LookupByRawKey(r.Context(), rawKey)
		if err != nil {
			log.Printf("error looking up API key: %v", err)
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
				log.Printf("error updating api key last_used_at: %v", err)
			}
		}()

		ctx := withAuthContext(r.Context(), apiKey.OrgID, apiKey.UserID, apiKey.Role)
		next(w, r.WithContext(ctx))
	}
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
