package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLogin_InvalidJSON(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader([]byte("not json")))
	rr := httptest.NewRecorder()
	s.handleLogin(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestLogin_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		body loginRequest
	}{
		{"missing email", loginRequest{Password: "pass", OrgSlug: "org"}},
		{"missing password", loginRequest{Email: "e@x.com", OrgSlug: "org"}},
		{"missing org_slug", loginRequest{Email: "e@x.com", Password: "pass"}},
		{"all empty", loginRequest{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := stubServer()
			body, _ := json.Marshal(tt.body)
			req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			s.handleLogin(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", rr.Code)
			}
		})
	}
}

func TestRefresh_MissingToken(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(refreshRequest{})
	req := httptest.NewRequest("POST", "/api/v1/auth/refresh", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleRefresh(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "refresh_token is required" {
		t.Errorf("expected 'refresh_token is required', got %q", resp["error"])
	}
}

func TestLogout_MissingToken(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(logoutRequest{})
	req := httptest.NewRequest("POST", "/api/v1/auth/logout", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleLogout(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestSetPassword_InvalidJSON(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("PATCH", "/api/v1/users/u-1/password", bytes.NewReader([]byte("bad")))
	req.SetPathValue("id", "u-1")
	ctx := withAuthContext(req.Context(), "org-1", "admin-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleSetPassword(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestSetPassword_TooShort(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(setPasswordRequest{Password: "short"})
	req := httptest.NewRequest("PATCH", "/api/v1/users/u-1/password", bytes.NewReader(body))
	req.SetPathValue("id", "u-1")
	ctx := withAuthContext(req.Context(), "org-1", "admin-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleSetPassword(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "password must be at least 8 characters" {
		t.Errorf("expected password length error, got %q", resp["error"])
	}
}

func TestSetPassword_MissingUserID(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(setPasswordRequest{Password: "long-enough-password"})
	req := httptest.NewRequest("PATCH", "/api/v1/users//password", bytes.NewReader(body))
	// Don't set path value — simulates missing id
	ctx := withAuthContext(req.Context(), "org-1", "admin-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleSetPassword(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestRefresh_InvalidJSON(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("POST", "/api/v1/auth/refresh", bytes.NewReader([]byte("{")))
	rr := httptest.NewRecorder()
	s.handleRefresh(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestLogout_InvalidJSON(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("POST", "/api/v1/auth/logout", bytes.NewReader([]byte("{")))
	rr := httptest.NewRecorder()
	s.handleLogout(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestLooksLikeJWT(t *testing.T) {
	tests := []struct {
		token string
		want  bool
	}{
		{"eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOiIxIn0.sig", true},  // JWT format
		{"abc.def.ghi", true},                                   // 2 dots = JWT
		{"abc123def456", false},                                  // hex API key
		{"abc.def", false},                                       // 1 dot
		{"abc.def.ghi.jkl", false},                               // 3 dots
		{"", false},
	}

	for _, tt := range tests {
		got := looksLikeJWT(tt.token)
		if got != tt.want {
			t.Errorf("looksLikeJWT(%q) = %v, want %v", tt.token, got, tt.want)
		}
	}
}
