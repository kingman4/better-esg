package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// --- handleCreateTemplate tests ---

func TestCreateTemplate_InvalidJSON(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("POST", "/api/v1/submission-templates", bytes.NewReader([]byte("not json")))
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleCreateTemplate(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCreateTemplate_MissingName(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(createTemplateRequest{SubmissionType: "NDA"})
	req := httptest.NewRequest("POST", "/api/v1/submission-templates", bytes.NewReader(body))
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleCreateTemplate(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "name is required" {
		t.Errorf("unexpected error: %q", resp["error"])
	}
}

func TestCreateTemplate_MissingSubmissionType(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(createTemplateRequest{Name: "My Template"})
	req := httptest.NewRequest("POST", "/api/v1/submission-templates", bytes.NewReader(body))
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleCreateTemplate(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "submission_type is required" {
		t.Errorf("unexpected error: %q", resp["error"])
	}
}

func TestCreateTemplate_NegativeFileCount(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(createTemplateRequest{Name: "Test", SubmissionType: "NDA", DefaultFileCount: -1})
	req := httptest.NewRequest("POST", "/api/v1/submission-templates", bytes.NewReader(body))
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleCreateTemplate(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleUpdateTemplate tests ---

func TestUpdateTemplate_InvalidJSON(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("PATCH", "/api/v1/submission-templates/abc", bytes.NewReader([]byte("not json")))
	req.SetPathValue("id", "abc")
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleUpdateTemplate(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestUpdateTemplate_EmptyName(t *testing.T) {
	s := stubServer()
	emptyName := ""
	body, _ := json.Marshal(updateTemplateRequest{Name: &emptyName})
	req := httptest.NewRequest("PATCH", "/api/v1/submission-templates/abc", bytes.NewReader(body))
	req.SetPathValue("id", "abc")
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleUpdateTemplate(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "name cannot be empty" {
		t.Errorf("unexpected error: %q", resp["error"])
	}
}

func TestUpdateTemplate_EmptySubmissionType(t *testing.T) {
	s := stubServer()
	emptyType := ""
	body, _ := json.Marshal(updateTemplateRequest{SubmissionType: &emptyType})
	req := httptest.NewRequest("PATCH", "/api/v1/submission-templates/abc", bytes.NewReader(body))
	req.SetPathValue("id", "abc")
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleUpdateTemplate(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestUpdateTemplate_NegativeFileCount(t *testing.T) {
	s := stubServer()
	negCount := -5
	body, _ := json.Marshal(updateTemplateRequest{DefaultFileCount: &negCount})
	req := httptest.NewRequest("PATCH", "/api/v1/submission-templates/abc", bytes.NewReader(body))
	req.SetPathValue("id", "abc")
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleUpdateTemplate(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}
