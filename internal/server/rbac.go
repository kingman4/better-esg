package server

import (
	"net/http"
)

// requireRole returns a middleware that checks if the authenticated user's role
// is in the allowed set. Returns 403 Forbidden if not.
func (s *Server) requireRole(next http.HandlerFunc, roles ...string) http.HandlerFunc {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(w http.ResponseWriter, r *http.Request) {
		role := roleFromContext(r.Context())
		if !allowed[role] {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "insufficient permissions",
			})
			return
		}
		next(w, r)
	}
}

// adminOnly restricts access to admin role only.
func (s *Server) adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return s.requireRole(next, "admin")
}

// canWrite restricts access to roles that can create/modify resources: admin + submitter.
func (s *Server) canWrite(next http.HandlerFunc) http.HandlerFunc {
	return s.requireRole(next, "admin", "submitter")
}

// canReview restricts access to roles that can view detailed data: admin + submitter + reviewer.
func (s *Server) canReview(next http.HandlerFunc) http.HandlerFunc {
	return s.requireRole(next, "admin", "submitter", "reviewer")
}
