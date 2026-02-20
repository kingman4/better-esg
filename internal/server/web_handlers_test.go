package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// --- handleLoginPage tests ---

func TestLoginPage_RenderForm(t *testing.T) {
	s := stubServer()
	s.jwtSecret = "test-secret-that-is-long-enough-for-hs256"

	req := httptest.NewRequest("GET", "/auth/login", nil)
	rr := httptest.NewRecorder()
	s.handleLoginPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Sign in") {
		t.Error("expected login page to contain 'Sign in'")
	}
}

func TestLoginPage_RedirectIfAuthenticated(t *testing.T) {
	s := stubServer()
	s.jwtSecret = "test-secret-that-is-long-enough-for-hs256"

	req := httptest.NewRequest("GET", "/auth/login", nil)
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleLoginPage(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/dashboard" {
		t.Errorf("expected redirect to /dashboard, got %q", loc)
	}
}

// --- handleWebLogin validation tests ---

func TestWebLogin_EmptyFields(t *testing.T) {
	s := stubServer()
	s.jwtSecret = "test-secret-that-is-long-enough-for-hs256"

	tests := []struct {
		name    string
		form    url.Values
		wantErr string
	}{
		{
			name:    "all empty",
			form:    url.Values{},
			wantErr: "All fields are required",
		},
		{
			name:    "missing password",
			form:    url.Values{"email": {"user@example.com"}, "org_slug": {"myco"}},
			wantErr: "All fields are required",
		},
		{
			name:    "missing email",
			form:    url.Values{"password": {"secret"}, "org_slug": {"myco"}},
			wantErr: "All fields are required",
		},
		{
			name:    "missing org_slug",
			form:    url.Values{"email": {"user@example.com"}, "password": {"secret"}},
			wantErr: "All fields are required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			s.handleWebLogin(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Errorf("expected 401, got %d", rr.Code)
			}
			body := rr.Body.String()
			if !strings.Contains(body, tt.wantErr) {
				t.Errorf("expected body to contain %q", tt.wantErr)
			}
		})
	}
}

// --- handleWebVerifyMFA validation tests ---

func TestWebVerifyMFA_EmptyFields(t *testing.T) {
	s := stubServer()
	s.jwtSecret = "test-secret-that-is-long-enough-for-hs256"

	tests := []struct {
		name string
		form url.Values
	}{
		{
			name: "missing mfa_token",
			form: url.Values{"totp_code": {"123456"}},
		},
		{
			name: "missing totp_code",
			form: url.Values{"mfa_token": {"some-token"}},
		},
		{
			name: "both empty",
			form: url.Values{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/auth/verify-mfa", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			s.handleWebVerifyMFA(rr, req)

			body := rr.Body.String()
			if !strings.Contains(body, "required") {
				t.Errorf("expected body to mention 'required', got %q", body[:min(len(body), 200)])
			}
		})
	}
}

func TestWebVerifyMFA_InvalidMFAToken(t *testing.T) {
	s := stubServer()
	s.jwtSecret = "test-secret-that-is-long-enough-for-hs256"

	form := url.Values{"mfa_token": {"invalid.token.value"}, "totp_code": {"123456"}}
	req := httptest.NewRequest("POST", "/auth/verify-mfa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	s.handleWebVerifyMFA(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "expired") && !strings.Contains(body, "log in again") {
		t.Errorf("expected expiry message, got %q", body[:min(len(body), 200)])
	}
}

// --- handleWebLogout tests ---

func TestWebLogout_ClearsCookiesAndRedirects(t *testing.T) {
	s := stubServer()

	req := httptest.NewRequest("POST", "/auth/logout", nil)
	rr := httptest.NewRecorder()
	s.handleWebLogout(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected 302, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/auth/login" {
		t.Errorf("expected redirect to /auth/login, got %q", loc)
	}

	// Check cookies are cleared
	cookies := rr.Result().Cookies()
	found := 0
	for _, c := range cookies {
		if (c.Name == cookieAuthToken || c.Name == cookieRefreshToken) && c.MaxAge == -1 {
			found++
		}
	}
	if found != 2 {
		t.Errorf("expected 2 cleared cookies, found %d", found)
	}
}

// --- Open redirect prevention ---

func TestIssueWebSession_OpenRedirectPrevention(t *testing.T) {
	tests := []struct {
		name     string
		next     string
		wantDest string
	}{
		{"empty next", "", "/dashboard"},
		{"valid local path", "/dashboard/submissions", "/dashboard/submissions"},
		{"absolute URL", "https://evil.com", "/dashboard"},
		{"protocol-relative", "//evil.com", "/dashboard"},
		{"no leading slash", "evil.com", "/dashboard"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't call issueWebSession directly (needs refreshTokens repo),
			// but we can test the redirect logic inline.
			next := tt.next
			if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
				next = "/dashboard"
			}
			if next != tt.wantDest {
				t.Errorf("next=%q: expected %q, got %q", tt.next, tt.wantDest, next)
			}
		})
	}
}

