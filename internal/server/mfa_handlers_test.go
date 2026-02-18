package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kingman4/better-esg/internal/auth"
)

// --- handleMFAConfirm tests ---

func TestMFAConfirm_MissingCode(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(mfaConfirmRequest{Code: ""})
	req := httptest.NewRequest("POST", "/api/v1/auth/mfa/confirm", bytes.NewReader(body))
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleMFAConfirm(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestMFAConfirm_NoSetupInProgress(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(mfaConfirmRequest{Code: "123456"})
	req := httptest.NewRequest("POST", "/api/v1/auth/mfa/confirm", bytes.NewReader(body))
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleMFAConfirm(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "no MFA setup in progress, call /auth/mfa/setup first" {
		t.Errorf("unexpected error: %q", resp["error"])
	}
}

func TestMFAConfirm_InvalidJSON(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("POST", "/api/v1/auth/mfa/confirm", bytes.NewReader([]byte("not json")))
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleMFAConfirm(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleVerifyMFA tests ---

func TestVerifyMFA_MissingFields(t *testing.T) {
	s := stubServer()
	tests := []struct {
		name string
		body verifyMFARequest
	}{
		{"missing both", verifyMFARequest{}},
		{"missing code", verifyMFARequest{MFAToken: "some.token.here"}},
		{"missing token", verifyMFARequest{Code: "123456"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.body)
			req := httptest.NewRequest("POST", "/api/v1/auth/verify-mfa", bytes.NewReader(body))
			rr := httptest.NewRecorder()
			s.handleVerifyMFA(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", rr.Code)
			}
		})
	}
}

func TestVerifyMFA_InvalidToken(t *testing.T) {
	s := stubServer()
	s.jwtSecret = "test-secret-that-is-at-least-32-chars"

	body, _ := json.Marshal(verifyMFARequest{
		MFAToken: "invalid.jwt.token",
		Code:     "123456",
	})
	req := httptest.NewRequest("POST", "/api/v1/auth/verify-mfa", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleVerifyMFA(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestVerifyMFA_WrongTokenType(t *testing.T) {
	s := stubServer()
	s.jwtSecret = "test-secret-that-is-at-least-32-chars"

	// Sign a regular access token (not MFA)
	accessToken, _ := auth.SignAccessToken("user-1", "org-1", "admin", s.jwtSecret)

	body, _ := json.Marshal(verifyMFARequest{
		MFAToken: accessToken,
		Code:     "123456",
	})
	req := httptest.NewRequest("POST", "/api/v1/auth/verify-mfa", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleVerifyMFA(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "invalid token type" {
		t.Errorf("unexpected error: %q", resp["error"])
	}
}

func TestVerifyMFA_InvalidJSON(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("POST", "/api/v1/auth/verify-mfa", bytes.NewReader([]byte("not json")))
	rr := httptest.NewRecorder()
	s.handleVerifyMFA(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleMFADisable tests ---

func TestMFADisable_MissingUserID(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(mfaDisableRequest{UserID: ""})
	req := httptest.NewRequest("DELETE", "/api/v1/auth/mfa", bytes.NewReader(body))
	ctx := withAuthContext(req.Context(), "org-1", "admin-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleMFADisable(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestMFADisable_InvalidJSON(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("DELETE", "/api/v1/auth/mfa", bytes.NewReader([]byte("not json")))
	ctx := withAuthContext(req.Context(), "org-1", "admin-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleMFADisable(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- MFA token signing tests ---

func TestSignMFAToken_HasCorrectType(t *testing.T) {
	secret := "test-secret-that-is-at-least-32-chars"
	token, err := auth.SignMFAToken("user-1", "org-1", "admin", secret)
	if err != nil {
		t.Fatalf("SignMFAToken failed: %v", err)
	}

	claims, err := auth.VerifyToken(token, secret)
	if err != nil {
		t.Fatalf("VerifyToken failed: %v", err)
	}

	if claims.Type != auth.TokenTypeMFA {
		t.Errorf("expected type %q, got %q", auth.TokenTypeMFA, claims.Type)
	}
	if claims.UserID != "user-1" {
		t.Errorf("expected user_id 'user-1', got %q", claims.UserID)
	}
	if claims.OrgID != "org-1" {
		t.Errorf("expected org_id 'org-1', got %q", claims.OrgID)
	}
	if claims.Role != "admin" {
		t.Errorf("expected role 'admin', got %q", claims.Role)
	}
}

// --- Middleware MFA token rejection test ---

func TestAuthenticateJWT_RejectsMFAToken(t *testing.T) {
	s := stubServer()
	s.jwtSecret = "test-secret-that-is-at-least-32-chars"

	mfaToken, _ := auth.SignMFAToken("user-1", "org-1", "admin", s.jwtSecret)

	handler := s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+mfaToken)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for MFA token used as access token, got %d", rr.Code)
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "MFA verification required" {
		t.Errorf("unexpected error: %q", resp["error"])
	}
}
