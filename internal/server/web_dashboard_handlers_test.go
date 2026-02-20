package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// handleDashboard requires the submissions and users repos which need a real DB.
// The requireWebAuth middleware is tested separately.
// Here we test that the handler runs without panic when repos are nil (graceful degradation).

func TestDashboard_RequiresAuth(t *testing.T) {
	s := stubServer()
	s.jwtSecret = "test-secret-that-is-long-enough-for-hs256"

	// requireWebAuth should redirect unauthenticated users
	handler := s.requireWebAuth(s.handleDashboard)

	req := httptest.NewRequest("GET", "/dashboard", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/auth/login" {
		t.Errorf("expected redirect to /auth/login, got %q", loc)
	}
}
