package server

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/kingman4/better-esg/internal/repository"
)

// extractIP pulls the IP address from a RemoteAddr string (host:port or just host).
func extractIP(remoteAddr string) string {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr // fallback if no port
	}
	return ip
}

// audit logs a user-initiated action. Extracts org/user/IP/UA from the request.
// Best-effort: logs errors but never fails the request.
func (s *Server) audit(r *http.Request, action, entityType, entityID string, details map[string]any) {
	if s.auditLog == nil {
		return
	}

	orgID := orgIDFromContext(r.Context())
	userID := userIDFromContext(r.Context())
	ip := extractIP(r.RemoteAddr)

	if err := s.auditLog.Insert(r.Context(), repository.InsertAuditLogParams{
		OrgID:      orgID,
		UserID:     &userID,
		Action:     action,
		EntityType: entityType,
		EntityID:   entityID,
		RequestIP:  ip,
		UserAgent:  r.Header.Get("User-Agent"),
		Details:    details,
	}); err != nil {
		log.Printf("warning: audit log insert failed: %v", err)
	}
}

// auditSystem logs a system-initiated action (e.g. poller). No request context.
func (s *Server) auditSystem(ctx context.Context, orgID, action, entityType, entityID string, details map[string]any) {
	if s.auditLog == nil {
		return
	}

	if err := s.auditLog.Insert(ctx, repository.InsertAuditLogParams{
		OrgID:      orgID,
		UserID:     nil, // system action
		Action:     action,
		EntityType: entityType,
		EntityID:   entityID,
		Details:    details,
	}); err != nil {
		log.Printf("warning: audit log insert failed: %v", err)
	}
}

// --- Audit log query endpoint ---

type auditLogResponse struct {
	ID          int64          `json:"id"`
	OrgID       string         `json:"org_id"`
	UserID      *string        `json:"user_id,omitempty"`
	Action      string         `json:"action"`
	EntityType  string         `json:"entity_type"`
	EntityID    *string        `json:"entity_id,omitempty"`
	RequestIP   *string        `json:"request_ip,omitempty"`
	UserAgent   *string        `json:"user_agent,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
	CreatedAt   string         `json:"created_at"`
}

func toAuditLogResponse(e *repository.AuditLogEntry) auditLogResponse {
	resp := auditLogResponse{
		ID:         e.ID,
		OrgID:      e.OrgID,
		Action:     e.Action,
		EntityType: e.EntityType,
		CreatedAt:  e.CreatedAt.Format(time.RFC3339),
	}
	if e.UserID.Valid {
		resp.UserID = &e.UserID.String
	}
	if e.EntityID.Valid {
		resp.EntityID = &e.EntityID.String
	}
	if e.RequestIP.Valid {
		resp.RequestIP = &e.RequestIP.String
	}
	if e.UserAgent.Valid {
		resp.UserAgent = &e.UserAgent.String
	}
	if e.DetailsJSON.Valid && e.DetailsJSON.String != "" {
		var details map[string]any
		if json.Unmarshal([]byte(e.DetailsJSON.String), &details) == nil {
			resp.Details = details
		}
	}
	return resp
}

func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
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

	entries, err := s.auditLog.ListByOrg(r.Context(), orgID, limit, offset)
	if err != nil {
		log.Printf("error listing audit logs: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list audit logs"})
		return
	}

	results := make([]auditLogResponse, 0, len(entries))
	for i := range entries {
		results = append(results, toAuditLogResponse(&entries[i]))
	}

	writeJSON(w, http.StatusOK, results)
}
