package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// --- handleCreateNotificationPref tests ---

func TestCreateNotifPref_InvalidJSON(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("POST", "/api/v1/notifications/preferences", bytes.NewReader([]byte("not json")))
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleCreateNotificationPref(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCreateNotifPref_InvalidChannel(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(createNotifPrefRequest{Channel: "sms", Events: []string{"submission.created"}})
	req := httptest.NewRequest("POST", "/api/v1/notifications/preferences", bytes.NewReader(body))
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleCreateNotificationPref(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "channel must be one of: email, slack, webhook" {
		t.Errorf("unexpected error: %q", resp["error"])
	}
}

func TestCreateNotifPref_MissingEvents(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(createNotifPrefRequest{Channel: "email", Events: []string{}})
	req := httptest.NewRequest("POST", "/api/v1/notifications/preferences", bytes.NewReader(body))
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleCreateNotificationPref(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCreateNotifPref_InvalidEvent(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(createNotifPrefRequest{Channel: "email", Events: []string{"invalid.event"}})
	req := httptest.NewRequest("POST", "/api/v1/notifications/preferences", bytes.NewReader(body))
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleCreateNotificationPref(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "invalid event type: invalid.event" {
		t.Errorf("unexpected error: %q", resp["error"])
	}
}

func TestCreateNotifPref_WebhookWithoutURL(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(createNotifPrefRequest{Channel: "webhook", Events: []string{"submission.created"}})
	req := httptest.NewRequest("POST", "/api/v1/notifications/preferences", bytes.NewReader(body))
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleCreateNotificationPref(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "webhook_url is required for webhook channel" {
		t.Errorf("unexpected error: %q", resp["error"])
	}
}

// --- handleGetNotificationPref tests ---

func TestGetNotifPref_InvalidChannel(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("GET", "/api/v1/notifications/preferences/sms", nil)
	req.SetPathValue("channel", "sms")
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleGetNotificationPref(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleUpdateNotificationPref tests ---

func TestUpdateNotifPref_InvalidJSON(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("PATCH", "/api/v1/notifications/preferences/email", bytes.NewReader([]byte("not json")))
	req.SetPathValue("channel", "email")
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleUpdateNotificationPref(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestUpdateNotifPref_InvalidChannel(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(updateNotifPrefRequest{})
	req := httptest.NewRequest("PATCH", "/api/v1/notifications/preferences/sms", bytes.NewReader(body))
	req.SetPathValue("channel", "sms")
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleUpdateNotificationPref(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestUpdateNotifPref_EmptyEvents(t *testing.T) {
	s := stubServer()
	emptyEvents := []string{}
	body, _ := json.Marshal(updateNotifPrefRequest{Events: &emptyEvents})
	req := httptest.NewRequest("PATCH", "/api/v1/notifications/preferences/email", bytes.NewReader(body))
	req.SetPathValue("channel", "email")
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleUpdateNotificationPref(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestUpdateNotifPref_InvalidEvent(t *testing.T) {
	s := stubServer()
	events := []string{"submission.created", "bad.event"}
	body, _ := json.Marshal(updateNotifPrefRequest{Events: &events})
	req := httptest.NewRequest("PATCH", "/api/v1/notifications/preferences/email", bytes.NewReader(body))
	req.SetPathValue("channel", "email")
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleUpdateNotificationPref(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleDeleteNotificationPref tests ---

func TestDeleteNotifPref_InvalidChannel(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("DELETE", "/api/v1/notifications/preferences/sms", nil)
	req.SetPathValue("channel", "sms")
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleDeleteNotificationPref(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}
