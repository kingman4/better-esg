package fdaclient

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
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

// newCredentialServer creates a mock FDA server that handles both OAuth token
// and credential submission endpoints. It validates Bearer auth, request body,
// and returns appropriate responses.
func newCredentialServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/as/token.oauth2" && r.Method == http.MethodPost:
			// Token endpoint
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "mock-token-12345",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})

		case (r.URL.Path == "/api/esgng/v1/credentials/api" ||
			r.URL.Path == "/api/esgng/v1/credentials/api/test") &&
			r.Method == http.MethodPost:

			// Verify Bearer token
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(errorResponse{
					ESGNGCode:        "ESGNG401",
					ESGNGDescription: "Unauthorized",
				})
				return
			}

			// Verify Content-Type
			if r.Header.Get("Content-Type") != "application/json" {
				http.Error(w, "bad content type", http.StatusBadRequest)
				return
			}

			// Parse and validate request body
			var req CredentialRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}

			if req.UserID == "" || req.FDACenter == "" || req.CompanyID == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(errorResponse{
					ESGNGCode:        "ESGNG400",
					ESGNGDescription: "Missing required fields",
				})
				return
			}

			// Return credential response
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"core_id":          "CORE-12345-ABCDE",
				"temp_user":        "temp_user_abc123",
				"temp_password":    "temp_pass_xyz789",
				"esgngcode":        "ESGNG210",
				"esgngdescription": "Credential submission successful",
			})

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
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

// --- Credential Submission Tests ---

func TestSubmitCredentials_Success(t *testing.T) {
	server := newCredentialServer(t)
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "test-client-id",
		ClientSecret:    "test-client-secret",
		Environment:     EnvTest,
	})

	req := CredentialRequest{
		UserID:             "user@example.com",
		FDACenter:          "CDER",
		CompanyID:          "COMP-001",
		SubmissionType:     "ANDA",
		SubmissionProtocol: "esg",
		FileCount:          3,
		Description:        "Test submission",
	}

	resp, err := client.SubmitCredentials(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.CoreID != "CORE-12345-ABCDE" {
		t.Errorf("expected core_id 'CORE-12345-ABCDE', got %q", resp.CoreID)
	}
	if resp.TempUser != "temp_user_abc123" {
		t.Errorf("expected temp_user 'temp_user_abc123', got %q", resp.TempUser)
	}
	if resp.TempPassword != "temp_pass_xyz789" {
		t.Errorf("expected temp_password 'temp_pass_xyz789', got %q", resp.TempPassword)
	}
	if resp.ESGNGCode != "ESGNG210" {
		t.Errorf("expected esgngcode 'ESGNG210', got %q", resp.ESGNGCode)
	}
}

func TestSubmitCredentials_UsesCorrectEnvironmentPath(t *testing.T) {
	tests := []struct {
		name    string
		env     Environment
		wantURL string
	}{
		{"prod", EnvProd, "/api/esgng/v1/credentials/api"},
		{"test", EnvTest, "/api/esgng/v1/credentials/api/test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calledPath string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/as/token.oauth2" {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]any{
						"access_token": "mock-token", "token_type": "Bearer", "expires_in": 3600,
					})
					return
				}
				calledPath = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{
					"core_id": "CORE-1", "temp_user": "u", "temp_password": "p",
					"esgngcode": "ESGNG210", "esgngdescription": "ok",
				})
			}))
			defer server.Close()

			client := New(Config{
				ExternalBaseURL: server.URL,
				ClientID:        "id",
				ClientSecret:    "secret",
				Environment:     tt.env,
			})

			_, err := client.SubmitCredentials(context.Background(), CredentialRequest{
				UserID: "u@x.com", FDACenter: "CDER", CompanyID: "C1",
				SubmissionType: "ANDA", SubmissionProtocol: "esg", FileCount: 1,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if calledPath != tt.wantURL {
				t.Errorf("expected path %q, got %q", tt.wantURL, calledPath)
			}
		})
	}
}

func TestSubmitCredentials_SendsBearerToken(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/as/token.oauth2" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "my-bearer-token", "token_type": "Bearer", "expires_in": 3600,
			})
			return
		}
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"core_id": "CORE-1", "temp_user": "u", "temp_password": "p",
			"esgngcode": "ESGNG210", "esgngdescription": "ok",
		})
	}))
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	_, err := client.SubmitCredentials(context.Background(), CredentialRequest{
		UserID: "u@x.com", FDACenter: "CDER", CompanyID: "C1",
		SubmissionType: "ANDA", SubmissionProtocol: "esg", FileCount: 1,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedAuth != "Bearer my-bearer-token" {
		t.Errorf("expected 'Bearer my-bearer-token', got %q", receivedAuth)
	}
}

func TestSubmitCredentials_SendsCorrectJSON(t *testing.T) {
	var receivedReq CredentialRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/as/token.oauth2" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok", "token_type": "Bearer", "expires_in": 3600,
			})
			return
		}
		json.NewDecoder(r.Body).Decode(&receivedReq)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"core_id": "CORE-1", "temp_user": "u", "temp_password": "p",
			"esgngcode": "ESGNG210", "esgngdescription": "ok",
		})
	}))
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	input := CredentialRequest{
		UserID:             "submitter@pharma.com",
		FDACenter:          "CBER",
		CompanyID:          "COMP-999",
		SubmissionType:     "NDA",
		SubmissionProtocol: "esg",
		FileCount:          5,
		Description:        "Phase 3 clinical data",
	}

	_, err := client.SubmitCredentials(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedReq.UserID != input.UserID {
		t.Errorf("user_id: expected %q, got %q", input.UserID, receivedReq.UserID)
	}
	if receivedReq.FDACenter != input.FDACenter {
		t.Errorf("fda_center: expected %q, got %q", input.FDACenter, receivedReq.FDACenter)
	}
	if receivedReq.CompanyID != input.CompanyID {
		t.Errorf("company_id: expected %q, got %q", input.CompanyID, receivedReq.CompanyID)
	}
	if receivedReq.SubmissionType != input.SubmissionType {
		t.Errorf("submission_type: expected %q, got %q", input.SubmissionType, receivedReq.SubmissionType)
	}
	if receivedReq.FileCount != input.FileCount {
		t.Errorf("file_count: expected %d, got %d", input.FileCount, receivedReq.FileCount)
	}
	if receivedReq.Description != input.Description {
		t.Errorf("description: expected %q, got %q", input.Description, receivedReq.Description)
	}
}

func TestSubmitCredentials_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/as/token.oauth2" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok", "token_type": "Bearer", "expires_in": 3600,
			})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse{
			ESGNGCode:        "ESGNG400",
			ESGNGDescription: "Invalid submission type",
		})
	}))
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	_, err := client.SubmitCredentials(context.Background(), CredentialRequest{
		UserID: "u@x.com", FDACenter: "CDER", CompanyID: "C1",
		SubmissionType: "INVALID", SubmissionProtocol: "esg", FileCount: 1,
	})
	if err == nil {
		t.Fatal("expected error for bad request, got nil")
	}
	if !strings.Contains(err.Error(), "ESGNG400") {
		t.Errorf("expected error to contain ESGNG400, got: %v", err)
	}
}

func TestSubmitCredentials_TokenFailure(t *testing.T) {
	// Server that rejects token requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{
			ESGNGCode:        "ESGNG403",
			ESGNGDescription: "Invalid credentials",
		})
	}))
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "bad-id",
		ClientSecret:    "bad-secret",
		Environment:     EnvTest,
	})

	_, err := client.SubmitCredentials(context.Background(), CredentialRequest{
		UserID: "u@x.com", FDACenter: "CDER", CompanyID: "C1",
		SubmissionType: "ANDA", SubmissionProtocol: "esg", FileCount: 1,
	})
	if err == nil {
		t.Fatal("expected error when token acquisition fails, got nil")
	}
}

// --- File Payload Tests ---

func TestGetPayload_Success(t *testing.T) {
	uploadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/forms/v1/fileupload/payload" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// No auth required for this endpoint
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"payloadId": "PL-98765",
			"links": map[string]string{
				"uploadLink": "/rest/forms/v1/fileupload/payload/PL-98765/file",
				"submitLink": "/rest/forms/v1/fileupload/payload/PL-98765/submit",
			},
		})
	}))
	defer uploadServer.Close()

	client := New(Config{
		UploadBaseURL: uploadServer.URL,
		Environment:   EnvTest,
	})

	resp, err := client.GetPayload(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.PayloadID != "PL-98765" {
		t.Errorf("expected payloadId 'PL-98765', got %q", resp.PayloadID)
	}
	if resp.Links.UploadLink != "/rest/forms/v1/fileupload/payload/PL-98765/file" {
		t.Errorf("unexpected uploadLink: %q", resp.Links.UploadLink)
	}
	if resp.Links.SubmitLink != "/rest/forms/v1/fileupload/payload/PL-98765/submit" {
		t.Errorf("unexpected submitLink: %q", resp.Links.SubmitLink)
	}
}

func TestGetPayload_NoAuth(t *testing.T) {
	var receivedAuth string
	uploadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"payloadId": "PL-1",
			"links":     map[string]string{"uploadLink": "/u", "submitLink": "/s"},
		})
	}))
	defer uploadServer.Close()

	client := New(Config{
		UploadBaseURL: uploadServer.URL,
		Environment:   EnvTest,
	})

	_, err := client.GetPayload(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedAuth != "" {
		t.Errorf("GetPayload should not send Authorization header, got %q", receivedAuth)
	}
}

func TestGetPayload_ServerError(t *testing.T) {
	uploadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errorResponse{
			ESGNGCode:        "ESGNG500",
			ESGNGDescription: "Internal server error",
		})
	}))
	defer uploadServer.Close()

	client := New(Config{
		UploadBaseURL: uploadServer.URL,
		Environment:   EnvTest,
	})

	_, err := client.GetPayload(context.Background())
	if err == nil {
		t.Fatal("expected error for server error, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected error to contain status code, got: %v", err)
	}
}

// --- File Upload Tests ---

func TestUploadFile_Success(t *testing.T) {
	// Combined server: token endpoint + upload endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/as/token.oauth2":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "upload-token", "token_type": "Bearer", "expires_in": 3600,
			})

		case r.URL.Path == "/rest/forms/v1/fileupload/payload/PL-123/file" && r.Method == http.MethodPost:
			// Verify Bearer token
			auth := r.Header.Get("Authorization")
			if auth != "Bearer upload-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// Verify multipart content type
			ct := r.Header.Get("Content-Type")
			mediaType, _, err := mime.ParseMediaType(ct)
			if err != nil || mediaType != "multipart/form-data" {
				http.Error(w, "expected multipart/form-data", http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"fileName":         "test-submission.xml",
				"fileSize":         1024,
				"esgngcode":        "ESGNG220",
				"esgngdescription": "File uploaded successfully",
			})

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		UploadBaseURL:   server.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	fileContent := strings.NewReader("<submission>test data</submission>")
	resp, err := client.UploadFile(context.Background(), "PL-123", "test-submission.xml", fileContent)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.FileName != "test-submission.xml" {
		t.Errorf("expected fileName 'test-submission.xml', got %q", resp.FileName)
	}
	if resp.FileSize != 1024 {
		t.Errorf("expected fileSize 1024, got %d", resp.FileSize)
	}
	if resp.ESGNGCode != "ESGNG220" {
		t.Errorf("expected esgngcode 'ESGNG220', got %q", resp.ESGNGCode)
	}
}

func TestUploadFile_SendsFileContent(t *testing.T) {
	var receivedFileName string
	var receivedContent string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/as/token.oauth2" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok", "token_type": "Bearer", "expires_in": 3600,
			})
			return
		}

		// Parse multipart form
		ct := r.Header.Get("Content-Type")
		_, params, _ := mime.ParseMediaType(ct)
		mr := multipart.NewReader(r.Body, params["boundary"])
		part, err := mr.NextPart()
		if err != nil {
			http.Error(w, "no multipart part", http.StatusBadRequest)
			return
		}
		receivedFileName = part.FileName()
		data, _ := io.ReadAll(part)
		receivedContent = string(data)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"fileName": receivedFileName, "fileSize": len(data),
			"esgngcode": "ESGNG220", "esgngdescription": "ok",
		})
	}))
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		UploadBaseURL:   server.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	content := "file-body-content-here"
	_, err := client.UploadFile(context.Background(), "PL-1", "data.xml", strings.NewReader(content))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedFileName != "data.xml" {
		t.Errorf("expected filename 'data.xml', got %q", receivedFileName)
	}
	if receivedContent != content {
		t.Errorf("expected content %q, got %q", content, receivedContent)
	}
}

func TestUploadFile_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/as/token.oauth2" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok", "token_type": "Bearer", "expires_in": 3600,
			})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse{
			ESGNGCode:        "ESGNG400",
			ESGNGDescription: "File too large",
		})
	}))
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		UploadBaseURL:   server.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	_, err := client.UploadFile(context.Background(), "PL-1", "big.xml", strings.NewReader("data"))
	if err == nil {
		t.Fatal("expected error for bad request, got nil")
	}
	if !strings.Contains(err.Error(), "ESGNG400") {
		t.Errorf("expected error to contain ESGNG400, got: %v", err)
	}
}

func TestUploadFile_TokenFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{
			ESGNGCode:        "ESGNG403",
			ESGNGDescription: "Bad credentials",
		})
	}))
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		UploadBaseURL:   server.URL,
		ClientID:        "bad",
		ClientSecret:    "bad",
		Environment:     EnvTest,
	})

	_, err := client.UploadFile(context.Background(), "PL-1", "f.xml", strings.NewReader("data"))
	if err == nil {
		t.Fatal("expected error when token fails, got nil")
	}
}

// --- File Submit Tests ---

func TestSubmitPayload_Success(t *testing.T) {
	uploadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/forms/v1/fileupload/payload/PL-123/submit" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req SubmitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"core_id":          "CORE-12345",
			"esgngcode":        "ESGNG230",
			"esgngdescription": "Submission successful",
		})
	}))
	defer uploadServer.Close()

	client := New(Config{
		UploadBaseURL: uploadServer.URL,
		Environment:   EnvTest,
	})

	resp, err := client.SubmitPayload(context.Background(), "PL-123", SubmitRequest{
		TempUser:       "temp_user_abc",
		TempPassword:   "temp_pass_xyz",
		SHA256Checksum: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.CoreID != "CORE-12345" {
		t.Errorf("expected core_id 'CORE-12345', got %q", resp.CoreID)
	}
	if resp.ESGNGCode != "ESGNG230" {
		t.Errorf("expected esgngcode 'ESGNG230', got %q", resp.ESGNGCode)
	}
}

func TestSubmitPayload_NoAuthHeader(t *testing.T) {
	var receivedAuth string
	uploadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"core_id": "CORE-1", "esgngcode": "ESGNG230", "esgngdescription": "ok",
		})
	}))
	defer uploadServer.Close()

	client := New(Config{
		UploadBaseURL: uploadServer.URL,
		Environment:   EnvTest,
	})

	_, err := client.SubmitPayload(context.Background(), "PL-1", SubmitRequest{
		TempUser: "u", TempPassword: "p", SHA256Checksum: "abc123",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedAuth != "" {
		t.Errorf("SubmitPayload should not send Authorization header, got %q", receivedAuth)
	}
}

func TestSubmitPayload_SendsCorrectJSON(t *testing.T) {
	var receivedReq SubmitRequest
	uploadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedReq)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"core_id": "CORE-1", "esgngcode": "ESGNG230", "esgngdescription": "ok",
		})
	}))
	defer uploadServer.Close()

	client := New(Config{
		UploadBaseURL: uploadServer.URL,
		Environment:   EnvTest,
	})

	input := SubmitRequest{
		TempUser:       "temp_user_abc",
		TempPassword:   "temp_pass_xyz",
		SHA256Checksum: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}

	_, err := client.SubmitPayload(context.Background(), "PL-99", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedReq.TempUser != input.TempUser {
		t.Errorf("temp_user: expected %q, got %q", input.TempUser, receivedReq.TempUser)
	}
	if receivedReq.TempPassword != input.TempPassword {
		t.Errorf("temp_password: expected %q, got %q", input.TempPassword, receivedReq.TempPassword)
	}
	if receivedReq.SHA256Checksum != input.SHA256Checksum {
		t.Errorf("sha256_checksum: expected %q, got %q", input.SHA256Checksum, receivedReq.SHA256Checksum)
	}
}

func TestSubmitPayload_ContentTypeJSON(t *testing.T) {
	var receivedContentType string
	uploadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"core_id": "CORE-1", "esgngcode": "ESGNG230", "esgngdescription": "ok",
		})
	}))
	defer uploadServer.Close()

	client := New(Config{
		UploadBaseURL: uploadServer.URL,
		Environment:   EnvTest,
	})

	_, err := client.SubmitPayload(context.Background(), "PL-1", SubmitRequest{
		TempUser: "u", TempPassword: "p", SHA256Checksum: "abc",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedContentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", receivedContentType)
	}
}

func TestSubmitPayload_APIError(t *testing.T) {
	uploadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorResponse{
			ESGNGCode:        "ESGNG400",
			ESGNGDescription: "Checksum mismatch",
		})
	}))
	defer uploadServer.Close()

	client := New(Config{
		UploadBaseURL: uploadServer.URL,
		Environment:   EnvTest,
	})

	_, err := client.SubmitPayload(context.Background(), "PL-1", SubmitRequest{
		TempUser: "u", TempPassword: "p", SHA256Checksum: "bad",
	})
	if err == nil {
		t.Fatal("expected error for bad request, got nil")
	}
	if !strings.Contains(err.Error(), "ESGNG400") {
		t.Errorf("expected error to contain ESGNG400, got: %v", err)
	}
}
