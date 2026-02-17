package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateOrg_MissingName(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(createOrgRequest{Slug: "valid-slug"})
	req := httptest.NewRequest("POST", "/api/v1/orgs", bytes.NewReader(body))
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleCreateOrg(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "name is required" {
		t.Errorf("expected 'name is required', got %q", resp["error"])
	}
}

func TestCreateOrg_MissingSlug(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(createOrgRequest{Name: "Test Org"})
	req := httptest.NewRequest("POST", "/api/v1/orgs", bytes.NewReader(body))
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleCreateOrg(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "slug is required" {
		t.Errorf("expected 'slug is required', got %q", resp["error"])
	}
}

func TestCreateOrg_InvalidSlug(t *testing.T) {
	tests := []struct {
		name string
		slug string
	}{
		{"uppercase", "MyOrg"},
		{"spaces", "my org"},
		{"too short", "ab"},
		{"starts with hyphen", "-abc"},
		{"ends with hyphen", "abc-"},
		{"special chars", "my_org!"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := stubServer()
			body, _ := json.Marshal(createOrgRequest{Name: "Test", Slug: tt.slug})
			req := httptest.NewRequest("POST", "/api/v1/orgs", bytes.NewReader(body))
			ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			s.handleCreateOrg(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("slug %q: expected 400, got %d", tt.slug, rr.Code)
			}
		})
	}
}

func TestCreateOrg_InvalidJSON(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("POST", "/api/v1/orgs", bytes.NewReader([]byte("not json")))
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleCreateOrg(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestCreateOrg_NegativeRetentionDays(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(createOrgRequest{Name: "Test", Slug: "test-org", DataRetentionDays: -1})
	req := httptest.NewRequest("POST", "/api/v1/orgs", bytes.NewReader(body))
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleCreateOrg(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestUpdateOrg_EmptyName(t *testing.T) {
	s := stubServer()
	name := ""
	body, _ := json.Marshal(updateOrgRequest{Name: &name})
	req := httptest.NewRequest("PATCH", "/api/v1/orgs/org-123", bytes.NewReader(body))
	req.SetPathValue("id", "org-123")
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleUpdateOrg(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "name cannot be empty" {
		t.Errorf("expected 'name cannot be empty', got %q", resp["error"])
	}
}

func TestUpdateOrg_InvalidRetentionDays(t *testing.T) {
	s := stubServer()
	days := 0
	body, _ := json.Marshal(updateOrgRequest{DataRetentionDays: &days})
	req := httptest.NewRequest("PATCH", "/api/v1/orgs/org-123", bytes.NewReader(body))
	req.SetPathValue("id", "org-123")
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleUpdateOrg(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestUpdateOrg_InvalidJSON(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("PATCH", "/api/v1/orgs/org-123", bytes.NewReader([]byte("bad")))
	req.SetPathValue("id", "org-123")
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleUpdateOrg(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestDeleteOrg_PreventsSelfOrgDeletion(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("DELETE", "/api/v1/orgs/org-1", nil)
	req.SetPathValue("id", "org-1")
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleDeleteOrg(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for self-org deletion, got %d", rr.Code)
	}

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "cannot delete your own organization" {
		t.Errorf("expected self-org deletion error, got %q", resp["error"])
	}
}

func TestSlugRegex(t *testing.T) {
	valid := []string{
		"acme",
		"my-org",
		"test-org-123",
		"abc",
		"a1b",
	}
	invalid := []string{
		"",
		"ab",         // too short
		"A",          // uppercase
		"My-Org",     // uppercase
		"-start",     // starts with hyphen
		"end-",       // ends with hyphen
		"has space",  // space
		"has_under",  // underscore
		"has.dot",    // dot
		"a",          // single char
	}

	for _, s := range valid {
		if !slugRegex.MatchString(s) {
			t.Errorf("expected %q to be a valid slug", s)
		}
	}
	for _, s := range invalid {
		if slugRegex.MatchString(s) {
			t.Errorf("expected %q to be an invalid slug", s)
		}
	}
}

func TestGetOrg_MissingID(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("GET", "/api/v1/orgs/", nil)
	// Don't set path value — simulates missing id
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleGetOrg(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}
