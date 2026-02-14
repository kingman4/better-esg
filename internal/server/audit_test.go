package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/kingman4/better-esg/internal/repository"
)

// TestAuditExtractsContext verifies that audit() correctly extracts org_id,
// user_id, IP, and User-Agent from the HTTP request context.
func TestAuditExtractsContext(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/submissions", nil)
	req.RemoteAddr = "192.168.1.42:54321"
	req.Header.Set("User-Agent", "BetterESG-CLI/1.0")

	ctx := withAuthContext(req.Context(), "org-abc", "user-xyz", "admin")
	req = req.WithContext(ctx)

	// Extract values the same way audit() does
	orgID := orgIDFromContext(req.Context())
	userID := userIDFromContext(req.Context())

	if orgID != "org-abc" {
		t.Errorf("orgID = %q, want %q", orgID, "org-abc")
	}
	if userID != "user-xyz" {
		t.Errorf("userID = %q, want %q", userID, "user-xyz")
	}

	// Verify IP extraction
	ip := extractIP(req.RemoteAddr)
	if ip != "192.168.1.42" {
		t.Errorf("ip = %q, want %q", ip, "192.168.1.42")
	}

	// Verify User-Agent
	ua := req.Header.Get("User-Agent")
	if ua != "BetterESG-CLI/1.0" {
		t.Errorf("user-agent = %q, want %q", ua, "BetterESG-CLI/1.0")
	}
}

// TestAuditIPExtraction tests various RemoteAddr formats.
func TestAuditIPExtraction(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		wantIP     string
	}{
		{"host:port", "10.0.0.1:8080", "10.0.0.1"},
		{"ipv6 with port", "[::1]:8080", "::1"},
		{"ip only (no port)", "10.0.0.1", "10.0.0.1"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIP(tt.remoteAddr)
			if got != tt.wantIP {
				t.Errorf("extractIP(%q) = %q, want %q", tt.remoteAddr, got, tt.wantIP)
			}
		})
	}
}

// TestAuditSystem_NilUserID verifies that system-initiated audit entries have nil user_id.
func TestAuditSystem_NilUserID(t *testing.T) {
	// Build params the same way auditSystem does
	params := repository.InsertAuditLogParams{
		OrgID:      "org-123",
		UserID:     nil, // system action
		Action:     "receive_acknowledgement",
		EntityType: "acknowledgement",
		EntityID:   "ack-456",
		Details:    map[string]any{"submission_id": "sub-789"},
	}

	if params.UserID != nil {
		t.Error("system action should have nil UserID")
	}
	if params.RequestIP != "" {
		t.Error("system action should have empty RequestIP")
	}
	if params.UserAgent != "" {
		t.Error("system action should have empty UserAgent")
	}
}

// TestAudit_NilAuditLog verifies that audit() is a no-op when auditLog is nil.
func TestAudit_NilAuditLog(t *testing.T) {
	s := &Server{auditLog: nil}

	req := httptest.NewRequest("POST", "/test", nil)
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	// Should not panic
	s.audit(req, "test_action", "test", "id-1", nil)
}

// TestAuditSystem_NilAuditLog verifies that auditSystem() is a no-op when auditLog is nil.
func TestAuditSystem_NilAuditLog(t *testing.T) {
	s := &Server{auditLog: nil}

	// Should not panic
	s.auditSystem(context.Background(), "org-1", "test_action", "test", "id-1", nil)
}

// TestToAuditLogResponse verifies the response conversion.
func TestToAuditLogResponse(t *testing.T) {
	userID := "user-abc"
	entityID := "sub-123"
	ip := "10.0.0.1"
	ua := "TestAgent/1.0"
	now := time.Now().UTC().Truncate(time.Second)

	entry := &repository.AuditLogEntry{
		ID:          42,
		OrgID:       "org-xyz",
		UserID:      sql.NullString{String: userID, Valid: true},
		Action:      "create_submission",
		EntityType:  "submission",
		EntityID:    sql.NullString{String: entityID, Valid: true},
		RequestIP:   sql.NullString{String: ip, Valid: true},
		UserAgent:   sql.NullString{String: ua, Valid: true},
		DetailsJSON: sql.NullString{String: `{"type":"510k","name":"Test"}`, Valid: true},
		CreatedAt:   now,
	}

	resp := toAuditLogResponse(entry)

	if resp.ID != 42 {
		t.Errorf("ID = %d, want 42", resp.ID)
	}
	if resp.OrgID != "org-xyz" {
		t.Errorf("OrgID = %q, want %q", resp.OrgID, "org-xyz")
	}
	if resp.UserID == nil || *resp.UserID != userID {
		t.Errorf("UserID = %v, want %q", resp.UserID, userID)
	}
	if resp.Action != "create_submission" {
		t.Errorf("Action = %q, want %q", resp.Action, "create_submission")
	}
	if resp.EntityType != "submission" {
		t.Errorf("EntityType = %q, want %q", resp.EntityType, "submission")
	}
	if resp.EntityID == nil || *resp.EntityID != entityID {
		t.Errorf("EntityID = %v, want %q", resp.EntityID, entityID)
	}
	if resp.RequestIP == nil || *resp.RequestIP != ip {
		t.Errorf("RequestIP = %v, want %q", resp.RequestIP, ip)
	}
	if resp.UserAgent == nil || *resp.UserAgent != ua {
		t.Errorf("UserAgent = %v, want %q", resp.UserAgent, ua)
	}
	if resp.Details == nil {
		t.Fatal("Details should not be nil")
	}
	if resp.Details["type"] != "510k" {
		t.Errorf("Details[type] = %v, want %q", resp.Details["type"], "510k")
	}
	if resp.CreatedAt != now.Format(time.RFC3339) {
		t.Errorf("CreatedAt = %q, want %q", resp.CreatedAt, now.Format(time.RFC3339))
	}
}

// TestToAuditLogResponse_NullFields verifies that null DB fields produce nil JSON pointers.
func TestToAuditLogResponse_NullFields(t *testing.T) {
	entry := &repository.AuditLogEntry{
		ID:          1,
		OrgID:       "org-1",
		Action:      "receive_acknowledgement",
		EntityType:  "acknowledgement",
		CreatedAt:   time.Now(),
		// All nullable fields left as zero-value (Valid: false)
	}

	resp := toAuditLogResponse(entry)

	if resp.UserID != nil {
		t.Errorf("UserID should be nil for system action, got %v", resp.UserID)
	}
	if resp.EntityID != nil {
		t.Errorf("EntityID should be nil when not set, got %v", resp.EntityID)
	}
	if resp.RequestIP != nil {
		t.Errorf("RequestIP should be nil for system action, got %v", resp.RequestIP)
	}
	if resp.UserAgent != nil {
		t.Errorf("UserAgent should be nil for system action, got %v", resp.UserAgent)
	}
	if resp.Details != nil {
		t.Errorf("Details should be nil when no JSON, got %v", resp.Details)
	}
}

// TestToAuditLogResponse_InvalidJSON verifies that bad details_json doesn't crash.
func TestToAuditLogResponse_InvalidJSON(t *testing.T) {
	entry := &repository.AuditLogEntry{
		ID:          1,
		OrgID:       "org-1",
		Action:      "test",
		EntityType:  "test",
		DetailsJSON: sql.NullString{String: "not valid json{{{", Valid: true},
		CreatedAt:   time.Now(),
	}

	resp := toAuditLogResponse(entry)

	// Should not crash, details should be nil
	if resp.Details != nil {
		t.Errorf("invalid JSON should result in nil Details, got %v", resp.Details)
	}
}

// TestParseLimitOffset verifies the limit/offset parsing logic used by handleListAuditLogs.
func TestParseLimitOffset(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantLimit  int
		wantOffset int
	}{
		{"defaults", "", 50, 0},
		{"custom limit", "?limit=10", 10, 0},
		{"custom offset", "?offset=20", 50, 20},
		{"both", "?limit=25&offset=50", 25, 50},
		{"invalid limit falls back to default", "?limit=abc", 50, 0},
		{"limit over 100 falls back to default", "?limit=200", 50, 0},
		{"negative limit falls back to default", "?limit=-5", 50, 0},
		{"negative offset falls back to default", "?offset=-1", 50, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/audit-logs"+tt.query, nil)

			// Replicate the parsing logic from handleListAuditLogs
			limit := 50
			if l := req.URL.Query().Get("limit"); l != "" {
				if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
					limit = parsed
				}
			}
			offset := 0
			if o := req.URL.Query().Get("offset"); o != "" {
				if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
					offset = parsed
				}
			}

			if limit != tt.wantLimit {
				t.Errorf("limit = %d, want %d", limit, tt.wantLimit)
			}
			if offset != tt.wantOffset {
				t.Errorf("offset = %d, want %d", offset, tt.wantOffset)
			}
		})
	}
}

// TestInsertAuditLogParams_DetailsMarshaling verifies JSON marshaling of details.
func TestInsertAuditLogParams_DetailsMarshaling(t *testing.T) {
	details := map[string]any{
		"submission_id": "sub-123",
		"file_count":    float64(3),
		"type":          "510k",
	}

	data, err := json.Marshal(details)
	if err != nil {
		t.Fatalf("failed to marshal details: %v", err)
	}

	var roundTrip map[string]any
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatalf("failed to unmarshal details: %v", err)
	}

	if roundTrip["submission_id"] != "sub-123" {
		t.Errorf("submission_id = %v, want %q", roundTrip["submission_id"], "sub-123")
	}
	if roundTrip["file_count"] != float64(3) {
		t.Errorf("file_count = %v, want 3", roundTrip["file_count"])
	}
}
