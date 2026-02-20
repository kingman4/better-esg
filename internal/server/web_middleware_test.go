package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kingman4/better-esg/internal/auth"
)

func TestWithCookieAuth_NoCookie(t *testing.T) {
	s := stubServer()
	s.jwtSecret = "test-secret-that-is-long-enough-for-hs256"

	var gotUserID string
	handler := s.withCookieAuth(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = userIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/dashboard", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if gotUserID != "" {
		t.Errorf("expected empty userID without cookie, got %q", gotUserID)
	}
}

func TestWithCookieAuth_ValidCookie(t *testing.T) {
	s := stubServer()
	s.jwtSecret = "test-secret-that-is-long-enough-for-hs256"

	token, err := auth.SignAccessToken("user-1", "org-1", "admin", s.jwtSecret)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	var gotUserID, gotOrgID, gotRole string
	handler := s.withCookieAuth(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = userIDFromContext(r.Context())
		gotOrgID = orgIDFromContext(r.Context())
		gotRole = roleFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: cookieAuthToken, Value: token})
	rr := httptest.NewRecorder()
	handler(rr, req)

	if gotUserID != "user-1" {
		t.Errorf("expected user-1, got %q", gotUserID)
	}
	if gotOrgID != "org-1" {
		t.Errorf("expected org-1, got %q", gotOrgID)
	}
	if gotRole != "admin" {
		t.Errorf("expected admin, got %q", gotRole)
	}
}

func TestWithCookieAuth_ExpiredCookie(t *testing.T) {
	s := stubServer()
	s.jwtSecret = "test-secret-that-is-long-enough-for-hs256"

	// Sign a token with a different secret so it fails verification
	token, _ := auth.SignAccessToken("user-1", "org-1", "admin", "different-secret-that-is-long-enough")

	var gotUserID string
	handler := s.withCookieAuth(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = userIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: cookieAuthToken, Value: token})
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 (pass-through), got %d", rr.Code)
	}
	if gotUserID != "" {
		t.Errorf("expected empty userID for invalid token, got %q", gotUserID)
	}
}

func TestWithCookieAuth_MFATokenRejected(t *testing.T) {
	s := stubServer()
	s.jwtSecret = "test-secret-that-is-long-enough-for-hs256"

	// MFA tokens should not grant auth context
	token, _ := auth.SignMFAToken("user-1", "org-1", "admin", s.jwtSecret)

	var gotUserID string
	handler := s.withCookieAuth(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = userIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: cookieAuthToken, Value: token})
	rr := httptest.NewRecorder()
	handler(rr, req)

	if gotUserID != "" {
		t.Errorf("expected empty userID for MFA token, got %q", gotUserID)
	}
}

func TestRequireWebAuth_Unauthenticated(t *testing.T) {
	s := stubServer()
	s.jwtSecret = "test-secret-that-is-long-enough-for-hs256"

	handler := s.requireWebAuth(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for unauthenticated request")
	})

	req := httptest.NewRequest("GET", "/dashboard", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if loc != "/auth/login" {
		t.Errorf("expected redirect to /auth/login, got %q", loc)
	}
}

func TestRequireWebAuth_UnauthenticatedPreservesNext(t *testing.T) {
	s := stubServer()
	s.jwtSecret = "test-secret-that-is-long-enough-for-hs256"

	handler := s.requireWebAuth(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	})

	req := httptest.NewRequest("GET", "/dashboard/submissions/abc", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	loc := rr.Header().Get("Location")
	if loc != "/auth/login?next=/dashboard/submissions/abc" {
		t.Errorf("expected redirect with next param, got %q", loc)
	}
}

func TestRequireWebAuth_Authenticated(t *testing.T) {
	s := stubServer()
	s.jwtSecret = "test-secret-that-is-long-enough-for-hs256"

	token, _ := auth.SignAccessToken("user-1", "org-1", "admin", s.jwtSecret)

	called := false
	handler := s.requireWebAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: cookieAuthToken, Value: token})
	rr := httptest.NewRecorder()
	handler(rr, req)

	if !called {
		t.Error("expected handler to be called for authenticated user")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestSetAuthCookies(t *testing.T) {
	rr := httptest.NewRecorder()
	setAuthCookies(rr, "access-tok", "refresh-tok")

	cookies := rr.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(cookies))
	}

	var authCookie, refreshCookie *http.Cookie
	for _, c := range cookies {
		switch c.Name {
		case cookieAuthToken:
			authCookie = c
		case cookieRefreshToken:
			refreshCookie = c
		}
	}

	if authCookie == nil {
		t.Fatal("missing auth_token cookie")
	}
	if authCookie.Value != "access-tok" {
		t.Errorf("expected access-tok, got %q", authCookie.Value)
	}
	if !authCookie.HttpOnly {
		t.Error("auth_token should be HttpOnly")
	}
	if authCookie.MaxAge != 900 {
		t.Errorf("expected MaxAge 900, got %d", authCookie.MaxAge)
	}
	if authCookie.Path != "/" {
		t.Errorf("expected path /, got %q", authCookie.Path)
	}

	if refreshCookie == nil {
		t.Fatal("missing refresh_token cookie")
	}
	if refreshCookie.Path != "/auth" {
		t.Errorf("expected path /auth, got %q", refreshCookie.Path)
	}
	if refreshCookie.MaxAge != 604800 {
		t.Errorf("expected MaxAge 604800, got %d", refreshCookie.MaxAge)
	}
}

func TestClearAuthCookies(t *testing.T) {
	rr := httptest.NewRecorder()
	clearAuthCookies(rr)

	cookies := rr.Result().Cookies()
	for _, c := range cookies {
		if c.MaxAge != -1 {
			t.Errorf("cookie %s: expected MaxAge -1 (delete), got %d", c.Name, c.MaxAge)
		}
	}
}
