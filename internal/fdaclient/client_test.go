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
	"sync"
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

	fileData := "<submission>test data</submission>"
	fileContent := strings.NewReader(fileData)
	resp, err := client.UploadFile(context.Background(), "PL-123", "test-submission.xml", fileContent, int64(len(fileData)))
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
	_, err := client.UploadFile(context.Background(), "PL-1", "data.xml", strings.NewReader(content), int64(len(content)))
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

	_, err := client.UploadFile(context.Background(), "PL-1", "big.xml", strings.NewReader("data"), 4)
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

	_, err := client.UploadFile(context.Background(), "PL-1", "f.xml", strings.NewReader("data"), 4)
	if err == nil {
		t.Fatal("expected error when token fails, got nil")
	}
}

func TestUploadFile_StreamsWithoutBuffering(t *testing.T) {
	// Verifies that UploadFile streams file content via multipart framing
	// and that retries re-send the full content by seeking back to start.
	var attempts atomic.Int64
	var receivedContents []string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/as/token.oauth2" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok", "token_type": "Bearer", "expires_in": 3600,
			})
			return
		}

		n := attempts.Add(1)

		// Parse the multipart body to extract file content
		ct := r.Header.Get("Content-Type")
		_, params, _ := mime.ParseMediaType(ct)
		mr := multipart.NewReader(r.Body, params["boundary"])
		part, err := mr.NextPart()
		if err != nil {
			http.Error(w, "bad multipart", http.StatusBadRequest)
			return
		}
		data, _ := io.ReadAll(part)

		mu.Lock()
		receivedContents = append(receivedContents, string(data))
		mu.Unlock()

		// Fail first attempt with 503 to trigger retry
		if n == 1 {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"fileName": part.FileName(), "fileSize": len(data),
			"esgngcode": "ESGNG220", "esgngdescription": "ok",
		})
	}))
	defer server.Close()

	origUpload := retryUpload
	retryUpload = retryConfig{maxAttempts: 3, baseDelay: time.Millisecond, maxDelay: 5 * time.Millisecond, linear: true}
	defer func() { retryUpload = origUpload }()

	client := New(Config{
		ExternalBaseURL: server.URL,
		UploadBaseURL:   server.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	content := "streaming-file-content-no-buffering"
	_, err := client.UploadFile(context.Background(), "PL-1", "stream.xml",
		strings.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if attempts.Load() != 2 {
		t.Fatalf("expected 2 attempts (1 retry), got %d", attempts.Load())
	}

	// Both attempts should have received the full file content
	mu.Lock()
	defer mu.Unlock()
	for i, got := range receivedContents {
		if got != content {
			t.Errorf("attempt %d: expected content %q, got %q", i+1, content, got)
		}
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

// --- Submission Status Tests ---

func newStatusServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/as/token.oauth2" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "status-token", "token_type": "Bearer", "expires_in": 3600,
			})

		case strings.HasPrefix(r.URL.Path, "/api/esgng/v1/submissions/") && r.Method == http.MethodGet:
			auth := r.Header.Get("Authorization")
			if auth != "Bearer status-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			coreID := strings.TrimPrefix(r.URL.Path, "/api/esgng/v1/submissions/")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"core_id":          coreID,
				"status":           "ACCEPTED",
				"esgngcode":        "ESGNG200",
				"esgngdescription": "Submission status retrieved",
				"acknowledgements": []map[string]string{
					{"acknowledgement_id": "ACK-001", "type": "ACK1"},
					{"acknowledgement_id": "ACK-002", "type": "ACK2"},
				},
			})

		case strings.HasPrefix(r.URL.Path, "/api/esgng/v1/acknowledgements/") && r.Method == http.MethodGet:
			auth := r.Header.Get("Authorization")
			if auth != "Bearer status-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			ackID := strings.TrimPrefix(r.URL.Path, "/api/esgng/v1/acknowledgements/")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"acknowledgement_id": ackID,
				"type":               "ACK1",
				"raw_message":        "<ack>raw xml here</ack>",
				"parsed_data":        map[string]string{"status": "received"},
				"esgngcode":          "ESGNG200",
				"esgngdescription":   "Acknowledgement retrieved",
			})

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

func TestGetSubmissionStatus_Success(t *testing.T) {
	server := newStatusServer(t)
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	resp, err := client.GetSubmissionStatus(context.Background(), "CORE-12345")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.CoreID != "CORE-12345" {
		t.Errorf("expected core_id 'CORE-12345', got %q", resp.CoreID)
	}
	if resp.Status != "ACCEPTED" {
		t.Errorf("expected status 'ACCEPTED', got %q", resp.Status)
	}
	if resp.ESGNGCode != "ESGNG200" {
		t.Errorf("expected esgngcode 'ESGNG200', got %q", resp.ESGNGCode)
	}
	if len(resp.Acknowledgements) != 2 {
		t.Fatalf("expected 2 acknowledgements, got %d", len(resp.Acknowledgements))
	}
	if resp.Acknowledgements[0].AcknowledgementID != "ACK-001" {
		t.Errorf("expected first ack id 'ACK-001', got %q", resp.Acknowledgements[0].AcknowledgementID)
	}
}

func TestGetSubmissionStatus_SendsBearerToken(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/as/token.oauth2" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "my-tok", "token_type": "Bearer", "expires_in": 3600,
			})
			return
		}
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"core_id": "C1", "status": "PENDING", "esgngcode": "ESGNG200",
			"esgngdescription": "ok", "acknowledgements": []any{},
		})
	}))
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	_, err := client.GetSubmissionStatus(context.Background(), "C1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedAuth != "Bearer my-tok" {
		t.Errorf("expected 'Bearer my-tok', got %q", receivedAuth)
	}
}

func TestGetSubmissionStatus_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/as/token.oauth2" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok", "token_type": "Bearer", "expires_in": 3600,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(errorResponse{
			ESGNGCode:        "ESGNG404",
			ESGNGDescription: "Submission not found",
		})
	}))
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	_, err := client.GetSubmissionStatus(context.Background(), "NONEXISTENT")
	if err == nil {
		t.Fatal("expected error for not found, got nil")
	}
	if !strings.Contains(err.Error(), "ESGNG404") {
		t.Errorf("expected error to contain ESGNG404, got: %v", err)
	}
}

func TestGetSubmissionStatus_TokenFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{
			ESGNGCode: "ESGNG403", ESGNGDescription: "Bad credentials",
		})
	}))
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "bad",
		ClientSecret:    "bad",
		Environment:     EnvTest,
	})

	_, err := client.GetSubmissionStatus(context.Background(), "C1")
	if err == nil {
		t.Fatal("expected error when token fails, got nil")
	}
}

// --- Acknowledgement Tests ---

func TestGetAcknowledgement_Success(t *testing.T) {
	server := newStatusServer(t)
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	resp, err := client.GetAcknowledgement(context.Background(), "ACK-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.AcknowledgementID != "ACK-001" {
		t.Errorf("expected acknowledgement_id 'ACK-001', got %q", resp.AcknowledgementID)
	}
	if resp.Type != "ACK1" {
		t.Errorf("expected type 'ACK1', got %q", resp.Type)
	}
	if resp.RawMessage != "<ack>raw xml here</ack>" {
		t.Errorf("expected raw_message, got %q", resp.RawMessage)
	}
	if resp.ESGNGCode != "ESGNG200" {
		t.Errorf("expected esgngcode 'ESGNG200', got %q", resp.ESGNGCode)
	}
}

func TestGetAcknowledgement_SendsBearerToken(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/as/token.oauth2" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "ack-tok", "token_type": "Bearer", "expires_in": 3600,
			})
			return
		}
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"acknowledgement_id": "A1", "type": "ACK1", "raw_message": "",
			"parsed_data": map[string]any{}, "esgngcode": "ESGNG200", "esgngdescription": "ok",
		})
	}))
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	_, err := client.GetAcknowledgement(context.Background(), "A1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedAuth != "Bearer ack-tok" {
		t.Errorf("expected 'Bearer ack-tok', got %q", receivedAuth)
	}
}

func TestGetAcknowledgement_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/as/token.oauth2" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok", "token_type": "Bearer", "expires_in": 3600,
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(errorResponse{
			ESGNGCode:        "ESGNG404",
			ESGNGDescription: "Acknowledgement not found",
		})
	}))
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	_, err := client.GetAcknowledgement(context.Background(), "NONEXISTENT")
	if err == nil {
		t.Fatal("expected error for not found, got nil")
	}
	if !strings.Contains(err.Error(), "ESGNG404") {
		t.Errorf("expected error to contain ESGNG404, got: %v", err)
	}
}

// --- GetCompanyInfo Tests ---

// newCompanyInfoServer creates a mock FDA server that handles token + company info.
// responseBody is the raw JSON returned for GET /api/esgng/v1/companies.
func newCompanyInfoServer(t *testing.T, statusCode int, responseBody string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/as/token.oauth2" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "company-token", "token_type": "Bearer", "expires_in": 3600,
			})

		case r.URL.Path == "/api/esgng/v1/companies" && r.Method == http.MethodGet:
			auth := r.Header.Get("Authorization")
			if auth != "Bearer company-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			w.Write([]byte(responseBody))

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

func TestGetCompanyInfo_SingleObject(t *testing.T) {
	server := newCompanyInfoServer(t, http.StatusOK, `{
		"user_id": 4909,
		"user_email": "user@pharma.com",
		"company_id": 5842,
		"company_name": "Pharma Corp",
		"company_status": "ACTIVE",
		"esgngcode": "ESGNG200",
		"esgngdescription": "Success"
	}`)
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	resp, err := client.GetCompanyInfo(context.Background(), "user@pharma.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.UserID != 4909 {
		t.Errorf("expected user_id 4909, got %d", resp.UserID)
	}
	if resp.CompanyID != 5842 {
		t.Errorf("expected company_id 5842, got %d", resp.CompanyID)
	}
	if resp.CompanyName != "Pharma Corp" {
		t.Errorf("expected company_name 'Pharma Corp', got %q", resp.CompanyName)
	}
}

func TestGetCompanyInfo_ArrayResponse(t *testing.T) {
	server := newCompanyInfoServer(t, http.StatusOK, `[{
		"user_id": 1001,
		"user_email": "user@generic.com",
		"company_id": 2002,
		"company_name": "Generic Inc",
		"company_status": "ACTIVE",
		"esgngcode": "ESGNG200",
		"esgngdescription": "Success"
	}]`)
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	resp, err := client.GetCompanyInfo(context.Background(), "user@generic.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.UserID != 1001 {
		t.Errorf("expected user_id 1001, got %d", resp.UserID)
	}
	if resp.CompanyID != 2002 {
		t.Errorf("expected company_id 2002, got %d", resp.CompanyID)
	}
	if resp.CompanyName != "Generic Inc" {
		t.Errorf("expected company_name 'Generic Inc', got %q", resp.CompanyName)
	}
}

func TestGetCompanyInfo_EmptyArray(t *testing.T) {
	server := newCompanyInfoServer(t, http.StatusOK, `[]`)
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	_, err := client.GetCompanyInfo(context.Background(), "nobody@example.com")
	if err == nil {
		t.Fatal("expected error for empty array, got nil")
	}
	if !strings.Contains(err.Error(), "no company found") {
		t.Errorf("expected 'no company found' error, got: %v", err)
	}
}

func TestGetCompanyInfo_ZeroCompanyID(t *testing.T) {
	server := newCompanyInfoServer(t, http.StatusOK, `{
		"user_id": 100,
		"user_email": "user@example.com",
		"company_id": 0,
		"company_name": "",
		"company_status": ""
	}`)
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	_, err := client.GetCompanyInfo(context.Background(), "user@example.com")
	if err == nil {
		t.Fatal("expected error for zero company_id, got nil")
	}
	if !strings.Contains(err.Error(), "empty company_id") {
		t.Errorf("expected 'empty company_id' error, got: %v", err)
	}
}

func TestGetCompanyInfo_APIError(t *testing.T) {
	server := newCompanyInfoServer(t, http.StatusNotFound, `{
		"esgngcode": "ESGNG404",
		"esgngdescription": "User not found"
	}`)
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	_, err := client.GetCompanyInfo(context.Background(), "unknown@example.com")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("expected error to contain status code, got: %v", err)
	}
}

func TestGetCompanyInfo_SendsBearerAndAccept(t *testing.T) {
	var receivedAuth, receivedAccept, receivedEmail string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/as/token.oauth2" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "ci-token", "token_type": "Bearer", "expires_in": 3600,
			})
			return
		}
		receivedAuth = r.Header.Get("Authorization")
		receivedAccept = r.Header.Get("Accept")
		receivedEmail = r.URL.Query().Get("user_email")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"user_id": 1, "company_id": 1, "company_name": "X",
			"esgngcode": "ESGNG200", "esgngdescription": "ok",
		})
	}))
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	_, err := client.GetCompanyInfo(context.Background(), "test@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedAuth != "Bearer ci-token" {
		t.Errorf("expected 'Bearer ci-token', got %q", receivedAuth)
	}
	if receivedAccept != "application/json" {
		t.Errorf("expected Accept 'application/json', got %q", receivedAccept)
	}
	if receivedEmail != "test@example.com" {
		t.Errorf("expected user_email 'test@example.com', got %q", receivedEmail)
	}
}

func TestGetCompanyInfo_TokenFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{
			ESGNGCode: "ESGNG403", ESGNGDescription: "Bad credentials",
		})
	}))
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "bad",
		ClientSecret:    "bad",
		Environment:     EnvTest,
	})

	_, err := client.GetCompanyInfo(context.Background(), "test@example.com")
	if err == nil {
		t.Fatal("expected error when token fails, got nil")
	}
}

// --- Token ESGNG-in-200 Tests ---

func TestGetToken_ESGNGErrorIn200(t *testing.T) {
	// Simulates FDA returning ESGNG error with HTTP 200
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"esgngcode":        "ESGNG403",
			"esgngdescription": "Client ID is not associated with a valid user account.",
			"message":          "Bad request",
		})
	}))
	defer server.Close()

	client := New(Config{
		ExternalBaseURL: server.URL,
		ClientID:        "invalid-id",
		ClientSecret:    "some-secret",
		Environment:     EnvTest,
	})

	_, err := client.GetToken(context.Background())
	if err == nil {
		t.Fatal("expected error for ESGNG error in 200 response, got nil")
	}
	if !strings.Contains(err.Error(), "ESGNG403") {
		t.Errorf("expected error to contain ESGNG403, got: %v", err)
	}
	if !strings.Contains(err.Error(), "Client ID is not associated") {
		t.Errorf("expected error to contain description, got: %v", err)
	}
}

// --- SubmissionName in CredentialRequest ---

func TestSubmitCredentials_SendsSubmissionName(t *testing.T) {
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

	_, err := client.SubmitCredentials(context.Background(), CredentialRequest{
		UserID:             "user@x.com",
		FDACenter:          "CDER",
		CompanyID:          "C1",
		SubmissionType:     "ANDA",
		SubmissionName:     "my-report.xml",
		SubmissionProtocol: "API",
		FileCount:          1,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedReq.SubmissionName != "my-report.xml" {
		t.Errorf("expected submission_name 'my-report.xml', got %q", receivedReq.SubmissionName)
	}
}

// --- truncate helper ---

func TestTruncate(t *testing.T) {
	tests := []struct {
		input string
		n     int
		want  string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is too long", 10, "this is to..."},
		{"", 5, ""},
	}
	for _, tt := range tests {
		got := truncate(tt.input, tt.n)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.n, got, tt.want)
		}
	}
}
