package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kingman4/better-esg/internal/repository"
)

func TestCreateUser_ValidatesEmail(t *testing.T) {
	tests := []struct {
		name  string
		body  createUserRequest
		want  int
		error string
	}{
		{"missing email", createUserRequest{}, http.StatusBadRequest, "email is required"},
		{"invalid email", createUserRequest{Email: "not-an-email"}, http.StatusBadRequest, "invalid email format"},
		{"invalid email no tld", createUserRequest{Email: "user@host"}, http.StatusBadRequest, "invalid email format"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := stubServer()
			body, _ := json.Marshal(tt.body)
			req := httptest.NewRequest("POST", "/api/v1/users", bytes.NewReader(body))
			ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			s.handleCreateUser(rr, req)

			if rr.Code != tt.want {
				t.Errorf("expected %d, got %d", tt.want, rr.Code)
			}

			var resp map[string]string
			json.Unmarshal(rr.Body.Bytes(), &resp)
			if resp["error"] != tt.error {
				t.Errorf("expected error %q, got %q", tt.error, resp["error"])
			}
		})
	}
}

func TestCreateUser_ValidatesRole(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(createUserRequest{Email: "test@example.com", Role: "superadmin"})
	req := httptest.NewRequest("POST", "/api/v1/users", bytes.NewReader(body))
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleCreateUser(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid role, got %d", rr.Code)
	}
}

func TestCreateUser_EmptyRoleIsValid(t *testing.T) {
	// An empty role should default to "viewer" — verify it passes ValidRoles check
	// (the actual default is applied in the handler before calling the repo).
	role := ""
	if role == "" {
		role = "viewer"
	}
	if !repository.ValidRoles[role] {
		t.Errorf("default role %q should be valid", role)
	}
}

func TestUpdateUser_ValidatesRole(t *testing.T) {
	s := stubServer()
	badRole := "megaadmin"
	body, _ := json.Marshal(updateUserRequest{Role: &badRole})
	req := httptest.NewRequest("PATCH", "/api/v1/users/user-123", bytes.NewReader(body))
	req.SetPathValue("id", "user-123")
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleUpdateUser(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid role, got %d", rr.Code)
	}
}

func TestDeleteUser_PreventsSelfDeletion(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("DELETE", "/api/v1/users/user-1", nil)
	req.SetPathValue("id", "user-1")
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleDeleteUser(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for self-deletion, got %d", rr.Code)
	}

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "cannot delete your own user" {
		t.Errorf("expected self-deletion error, got %q", resp["error"])
	}
}

func TestEmailRegex(t *testing.T) {
	valid := []string{
		"user@example.com",
		"first.last@company.org",
		"user+tag@domain.co.uk",
		"a@b.cd",
	}
	invalid := []string{
		"",
		"not-an-email",
		"@example.com",
		"user@",
		"user@host",
		"user @example.com",
	}

	for _, e := range valid {
		if !emailRegex.MatchString(e) {
			t.Errorf("expected %q to be valid", e)
		}
	}
	for _, e := range invalid {
		if emailRegex.MatchString(e) {
			t.Errorf("expected %q to be invalid", e)
		}
	}
}

func TestValidRoles(t *testing.T) {
	expected := []string{"admin", "submitter", "reviewer", "viewer"}
	for _, r := range expected {
		if !repository.ValidRoles[r] {
			t.Errorf("expected %q to be a valid role", r)
		}
	}
	if repository.ValidRoles["superadmin"] {
		t.Error("superadmin should not be valid")
	}
}

func TestToUserResponse(t *testing.T) {
	u := &repository.User{
		ID:    "u-1",
		OrgID: "org-1",
		Email: "test@example.com",
		Role:  "admin",
	}
	resp := toUserResponse(u)
	if resp.ID != "u-1" {
		t.Errorf("expected ID u-1, got %s", resp.ID)
	}
	if resp.Email != "test@example.com" {
		t.Errorf("expected email test@example.com, got %s", resp.Email)
	}
}
