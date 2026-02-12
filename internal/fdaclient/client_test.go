package fdaclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// newTestServer creates a mock FDA OAuth server that returns tokens.
// It tracks how many times the token endpoint was called.
func newTestServer(t *testing.T, callCount *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/as/token.oauth2" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Verify content type
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			http.Error(w, "bad content type", http.StatusBadRequest)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}

		clientID := r.FormValue("client_id")
		clientSecret := r.FormValue("client_secret")
		grantType := r.FormValue("grant_type")
		scope := r.FormValue("scope")

		if clientID == "" || clientSecret == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"esgngcode":        "ESGNG403",
				"esgngdescription": "Client ID is not associated with a valid user account.",
				"message":          "Bad request",
			})
			return
		}

		if grantType != "client_credentials" || scope != "openid profile" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mock-token-12345",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
}

func TestGetToken_Success(t *testing.T) {
	var calls atomic.Int32
	server := newTestServer(t, &calls)
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "test-client-id",
		ClientSecret:    "test-client-secret",
		Environment:     EnvTest,
	})

	token, err := client.GetToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "mock-token-12345" {
		t.Errorf("expected token 'mock-token-12345', got %q", token)
	}
	if calls.Load() != 1 {
		t.Errorf("expected 1 token call, got %d", calls.Load())
	}
}

func TestGetToken_CachesToken(t *testing.T) {
	var calls atomic.Int32
	server := newTestServer(t, &calls)
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "test-client-id",
		ClientSecret:    "test-client-secret",
		Environment:     EnvTest,
	})

	// Call twice — second should use cache
	_, err := client.GetToken(context.Background())
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	_, err = client.GetToken(context.Background())
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	if calls.Load() != 1 {
		t.Errorf("expected 1 token call (cached), got %d", calls.Load())
	}
}

func TestGetToken_RefreshesExpiredToken(t *testing.T) {
	var calls atomic.Int32
	server := newTestServer(t, &calls)
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "test-client-id",
		ClientSecret:    "test-client-secret",
		Environment:     EnvTest,
	})

	// Get a token, then expire it manually
	_, err := client.GetToken(context.Background())
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Force expiry by backdating
	client.mu.Lock()
	client.tokenExpiry = time.Now().Add(-1 * time.Minute)
	client.mu.Unlock()

	_, err = client.GetToken(context.Background())
	if err != nil {
		t.Fatalf("second call after expiry: %v", err)
	}

	if calls.Load() != 2 {
		t.Errorf("expected 2 token calls (refreshed), got %d", calls.Load())
	}
}

func TestGetToken_InvalidCredentials(t *testing.T) {
	var calls atomic.Int32
	server := newTestServer(t, &calls)
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "",
		ClientSecret:    "",
		Environment:     EnvTest,
	})

	_, err := client.GetToken(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid credentials, got nil")
	}
}

func TestGetToken_ServerDown(t *testing.T) {
	client := New(Config{
		ExternalBaseURL: "http://localhost:1", // nothing listening
		ClientID:        "test-client-id",
		ClientSecret:    "test-client-secret",
		Environment:     EnvTest,
	})

	_, err := client.GetToken(context.Background())
	if err == nil {
		t.Fatal("expected error for unreachable server, got nil")
	}
}

func TestEnvironmentConfig(t *testing.T) {
	tests := []struct {
		name     string
		env      Environment
		wantPath string
	}{
		{"prod credential path", EnvProd, "/api/esgng/v1/credentials/api"},
		{"test credential path", EnvTest, "/api/esgng/v1/credentials/api/test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := New(Config{
				ExternalBaseURL: "https://external-api-esgng.fda.gov",
				ClientID:        "id",
				ClientSecret:    "secret",
				Environment:     tt.env,
			})
			if got := client.CredentialPath(); got != tt.wantPath {
				t.Errorf("expected %q, got %q", tt.wantPath, got)
			}
		})
	}
}
