//go:build integration

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kingman4/better-esg/internal/database"
	"github.com/kingman4/better-esg/internal/fdaclient"
	"github.com/kingman4/better-esg/internal/repository"
	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// mockCoreIDCounter ensures each mock FDA server returns unique core_ids
// to avoid the UNIQUE constraint on submissions.core_id.
var mockCoreIDCounter atomic.Int64

// Package-level shared test infrastructure — one container for all tests.
var (
	testDB        *sql.DB
	testContainer testcontainers.Container
	// Fixed 32-byte key for deterministic test encryption.
	testEncryptionKey = []byte("test-encryption-key-32-bytes!!")
)

func init() {
	// Pad to exactly 32 bytes
	if len(testEncryptionKey) < 32 {
		padded := make([]byte, 32)
		copy(padded, testEncryptionKey)
		testEncryptionKey = padded
	}
}

func TestMain(m *testing.M) {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "test",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(30 * time.Second),
	}

	var err error
	testContainer, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		log.Fatalf("starting container: %v", err)
	}

	host, _ := testContainer.Host(ctx)
	port, _ := testContainer.MappedPort(ctx, "5432")
	dsn := fmt.Sprintf("postgres://test:test@%s:%s/test?sslmode=disable", host, port.Port())

	testDB, err = sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("opening db: %v", err)
	}

	if err := database.RunMigrations(testDB); err != nil {
		log.Fatalf("running migrations: %v", err)
	}

	code := m.Run()

	testDB.Close()
	testContainer.Terminate(ctx)
	os.Exit(code)
}

// seedTestData inserts an org + user and returns their IDs.
// Each test gets a unique slug to avoid conflicts.
func seedTestData(t *testing.T, suffix string) (orgID, userID string) {
	t.Helper()
	ctx := context.Background()

	err := testDB.QueryRowContext(ctx,
		`INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id`,
		"Test Org "+suffix, "test-org-"+suffix,
	).Scan(&orgID)
	if err != nil {
		t.Fatalf("seeding org: %v", err)
	}

	err = testDB.QueryRowContext(ctx,
		`INSERT INTO users (org_id, email, role) VALUES ($1, $2, 'submitter') RETURNING id`,
		orgID, fmt.Sprintf("test-%s@test.com", suffix),
	).Scan(&userID)
	if err != nil {
		t.Fatalf("seeding user: %v", err)
	}

	return orgID, userID
}

// seedAPIKey creates an API key for the given org+user and returns the raw key
// for use in the Authorization header.
func seedAPIKey(t *testing.T, orgID, userID string) string {
	t.Helper()
	repo := repository.NewAPIKeyRepo(testDB)
	result, err := repo.Create(context.Background(), repository.CreateKeyParams{
		OrgID:  orgID,
		UserID: userID,
		Name:   "test-key",
		Role:   "submitter",
	})
	if err != nil {
		t.Fatalf("creating API key: %v", err)
	}
	return result.RawKey
}

// authHeader returns the Authorization header value for an API key.
func authHeader(rawKey string) string {
	return "Bearer " + rawKey
}

// newTestServer creates a Server backed by the shared DB with a nil FDA client.
// Use newTestServerWithFDA for tests that need the FDA workflow.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	return newTestServerWithFDA(t, nil)
}

// newTestServerWithFDA creates a Server backed by the shared DB
// with the given FDA client. Pass nil if FDA is not needed.
func newTestServerWithFDA(t *testing.T, fda *fdaclient.Client) *Server {
	t.Helper()
	s := &Server{
		db:          testDB,
		router:      http.NewServeMux(),
		submissions: repository.NewSubmissionRepo(testDB, testEncryptionKey),
		files:       repository.NewSubmissionFileRepo(testDB),
		apiKeys:     repository.NewAPIKeyRepo(testDB),
		acks:        repository.NewAckRepo(testDB),
		fda:         fda,
	}
	s.routes()
	return s
}

// --- Auth Middleware Tests ---

func TestAuth_MissingHeader(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/submissions", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAuth_InvalidFormat(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/submissions", nil)
	req.Header.Set("Authorization", "Basic abc123")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAuth_InvalidKey(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/submissions", nil)
	req.Header.Set("Authorization", "Bearer totally-invalid-key")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAuth_HealthNoAuth(t *testing.T) {
	srv := newTestServer(t)

	// Health endpoint should work without auth
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Submission CRUD Tests ---

func TestCreateSubmission_Success(t *testing.T) {
	srv := newTestServer(t)
	orgID, userID := seedTestData(t, "create-success")
	apiKey := seedAPIKey(t, orgID, userID)

	body := map[string]any{
		"fda_center":      "CDER",
		"submission_type": "ANDA",
		"submission_name": "Test Drug Application",
		"file_count":      3,
		"description":     "Phase 3 data",
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/submissions", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp submissionResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.ID == "" {
		t.Error("expected non-empty id")
	}
	if resp.OrgID != orgID {
		t.Errorf("expected org_id %q, got %q", orgID, resp.OrgID)
	}
	if resp.CreatedBy != userID {
		t.Errorf("expected created_by %q (from auth), got %q", userID, resp.CreatedBy)
	}
	if resp.SubmissionType != "ANDA" {
		t.Errorf("expected submission_type 'ANDA', got %q", resp.SubmissionType)
	}
	if resp.Status != "draft" {
		t.Errorf("expected status 'draft', got %q", resp.Status)
	}
	if resp.WorkflowState != "INITIALIZED" {
		t.Errorf("expected workflow_state 'INITIALIZED', got %q", resp.WorkflowState)
	}
	if resp.SubmissionProtocol != "API" {
		t.Errorf("expected default protocol 'API', got %q", resp.SubmissionProtocol)
	}
}

func TestCreateSubmission_MissingFields(t *testing.T) {
	srv := newTestServer(t)
	orgID, userID := seedTestData(t, "create-missing")
	apiKey := seedAPIKey(t, orgID, userID)

	tests := []struct {
		name string
		body map[string]any
	}{
		{"missing submission_type", map[string]any{"submission_name": "x", "file_count": 1}},
		{"missing submission_name", map[string]any{"submission_type": "ANDA", "file_count": 1}},
		{"zero file_count", map[string]any{"submission_type": "ANDA", "submission_name": "x", "file_count": 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/submissions", bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", authHeader(apiKey))
			w := httptest.NewRecorder()

			srv.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestCreateSubmission_InvalidJSON(t *testing.T) {
	srv := newTestServer(t)
	orgID, userID := seedTestData(t, "create-invalidjson")
	apiKey := seedAPIKey(t, orgID, userID)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/submissions", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestGetSubmission_Success(t *testing.T) {
	srv := newTestServer(t)
	orgID, userID := seedTestData(t, "get-success")
	apiKey := seedAPIKey(t, orgID, userID)

	sub, err := srv.submissions.Create(context.Background(), repository.CreateSubmissionParams{
		OrgID:              orgID,
		FDACenter:          "CDER",
		SubmissionType:     "ANDA",
		SubmissionName:     "Get Test",
		SubmissionProtocol: "API",
		FileCount:          1,
		CreatedBy:          userID,
	})
	if err != nil {
		t.Fatalf("creating test submission: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/submissions/%s", sub.ID), nil)
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp submissionResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.ID != sub.ID {
		t.Errorf("expected id %q, got %q", sub.ID, resp.ID)
	}
	if resp.SubmissionName != "Get Test" {
		t.Errorf("expected name 'Get Test', got %q", resp.SubmissionName)
	}
}

func TestGetSubmission_NotFound(t *testing.T) {
	srv := newTestServer(t)
	orgID, userID := seedTestData(t, "get-notfound")
	apiKey := seedAPIKey(t, orgID, userID)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/submissions/00000000-0000-0000-0000-000000000000", nil)
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetSubmission_CrossOrgIsolation(t *testing.T) {
	srv := newTestServer(t)

	// Create submission under org A
	orgA, userA := seedTestData(t, "isolation-orgA")
	sub, err := srv.submissions.Create(context.Background(), repository.CreateSubmissionParams{
		OrgID:              orgA,
		SubmissionType:     "ANDA",
		SubmissionName:     "Org A Submission",
		SubmissionProtocol: "API",
		FileCount:          1,
		CreatedBy:          userA,
	})
	if err != nil {
		t.Fatalf("creating submission: %v", err)
	}

	// Try to read it with org B's API key — should return 404
	orgB, userB := seedTestData(t, "isolation-orgB")
	apiKeyB := seedAPIKey(t, orgB, userB)

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/submissions/%s", sub.ID), nil)
	req.Header.Set("Authorization", authHeader(apiKeyB))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-org access, got %d: %s", w.Code, w.Body.String())
	}
}

func TestListSubmissions_Success(t *testing.T) {
	srv := newTestServer(t)
	orgID, userID := seedTestData(t, "list-success")
	apiKey := seedAPIKey(t, orgID, userID)

	for i := 0; i < 2; i++ {
		_, err := srv.submissions.Create(context.Background(), repository.CreateSubmissionParams{
			OrgID:              orgID,
			FDACenter:          "CDER",
			SubmissionType:     "ANDA",
			SubmissionName:     fmt.Sprintf("Submission %d", i),
			SubmissionProtocol: "API",
			FileCount:          1,
			CreatedBy:          userID,
		})
		if err != nil {
			t.Fatalf("creating test submission: %v", err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/submissions", nil)
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var results []submissionResponse
	json.NewDecoder(w.Body).Decode(&results)

	if len(results) != 2 {
		t.Errorf("expected 2 submissions, got %d", len(results))
	}
}

func TestListSubmissions_EmptyList(t *testing.T) {
	srv := newTestServer(t)
	orgID, userID := seedTestData(t, "list-empty")
	apiKey := seedAPIKey(t, orgID, userID)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/submissions", nil)
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if body != "[]\n" {
		t.Errorf("expected empty array '[]', got %q", body)
	}
}

func TestListSubmissions_Pagination(t *testing.T) {
	srv := newTestServer(t)
	orgID, userID := seedTestData(t, "list-pagination")
	apiKey := seedAPIKey(t, orgID, userID)

	for i := 0; i < 5; i++ {
		_, _ = srv.submissions.Create(context.Background(), repository.CreateSubmissionParams{
			OrgID:              orgID,
			SubmissionType:     "ANDA",
			SubmissionName:     fmt.Sprintf("Sub %d", i),
			SubmissionProtocol: "API",
			FileCount:          1,
			CreatedBy:          userID,
		})
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/submissions?limit=2&offset=0", nil)
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	var results []submissionResponse
	json.NewDecoder(w.Body).Decode(&results)

	if len(results) != 2 {
		t.Errorf("expected 2 results with limit=2, got %d", len(results))
	}
}

// --- FDA Workflow Tests ---

// newMockFDAServer creates an httptest.Server that handles OAuth token,
// credential submission, payload, file upload, and submit endpoints.
// Each call to the credential endpoint returns a unique core_id to avoid
// the UNIQUE constraint on submissions.core_id across shared-container tests.
func newMockFDAServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/as/token.oauth2" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token", "token_type": "Bearer", "expires_in": 3600,
			})

		case (r.URL.Path == "/api/esgng/v1/credentials/api/test" ||
			r.URL.Path == "/api/esgng/v1/credentials/api") && r.Method == http.MethodPost:
			n := mockCoreIDCounter.Add(1)
			coreID := fmt.Sprintf("CORE-WORKFLOW-%d", n)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"core_id":          coreID,
				"temp_user":        "tmp_u",
				"temp_password":    "tmp_p",
				"esgngcode":        "ESGNG210",
				"esgngdescription": "ok",
			})

		case r.URL.Path == "/rest/forms/v1/fileupload/payload" && r.Method == http.MethodGet:
			n := mockCoreIDCounter.Load()
			payloadID := fmt.Sprintf("PL-WORKFLOW-%d", n)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"payloadId": payloadID,
				"links": map[string]string{
					"uploadLink": fmt.Sprintf("/rest/forms/v1/fileupload/payload/%s/file", payloadID),
					"submitLink": fmt.Sprintf("/rest/forms/v1/fileupload/payload/%s/submit", payloadID),
				},
			})

		case strings.HasSuffix(r.URL.Path, "/file") && r.Method == http.MethodPost:
			// File upload endpoint
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"fileName":         "test.pdf",
				"fileSize":         1024,
				"esgngcode":        "ESGNG210",
				"esgngdescription": "ok",
			})

		case strings.HasSuffix(r.URL.Path, "/submit") && r.Method == http.MethodPost:
			// Payload submit endpoint
			n := mockCoreIDCounter.Load()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"core_id":          fmt.Sprintf("CORE-WORKFLOW-%d", n),
				"esgngcode":        "ESGNG210",
				"esgngdescription": "ok",
			})

		case strings.HasPrefix(r.URL.Path, "/api/esgng/v1/submissions/") && r.Method == http.MethodGet:
			// Status polling endpoint
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"core_id":          strings.TrimPrefix(r.URL.Path, "/api/esgng/v1/submissions/"),
				"status":           "ACCEPTED",
				"esgngcode":        "ESGNG210",
				"esgngdescription": "ok",
				"acknowledgements": []map[string]string{
					{"acknowledgement_id": "ACK-001", "type": "Technical"},
				},
			})

		case strings.HasPrefix(r.URL.Path, "/api/esgng/v1/acknowledgements/") && r.Method == http.MethodGet:
			// Acknowledgement detail endpoint
			ackID := strings.TrimPrefix(r.URL.Path, "/api/esgng/v1/acknowledgements/")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"acknowledgement_id": ackID,
				"type":               "Technical",
				"raw_message":        "<xml>ack</xml>",
				"parsed_data":        map[string]string{"result": "accepted"},
				"esgngcode":          "ESGNG210",
				"esgngdescription":   "ok",
			})

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

// setupPayloadObtainedSubmission creates a submission and advances it to payload_obtained
// state with temp credentials and payload_id set — ready for file upload.
// Returns orgID, subID, and the raw API key for auth.
func setupPayloadObtainedSubmission(t *testing.T, srv *Server, suffix string) (orgID, subID, rawKey string) {
	t.Helper()
	orgID, userID := seedTestData(t, suffix)
	rawKey = seedAPIKey(t, orgID, userID)

	sub, err := srv.submissions.Create(context.Background(), repository.CreateSubmissionParams{
		OrgID:              orgID,
		FDACenter:          "CDER",
		SubmissionType:     "ANDA",
		SubmissionName:     "Upload Test " + suffix,
		SubmissionProtocol: "API",
		FileCount:          1,
		Description:        "test",
		CreatedBy:          userID,
	})
	if err != nil {
		t.Fatalf("creating submission: %v", err)
	}

	// Set FDA fields as if handleSubmitToFDA already ran
	if err := srv.submissions.UpdateFDAFields(context.Background(), sub.ID,
		"CORE-"+suffix, "PL-"+suffix,
		"/upload/"+suffix, "/submit/"+suffix,
	); err != nil {
		t.Fatalf("updating FDA fields: %v", err)
	}
	if err := srv.submissions.SaveTempCredentials(context.Background(), sub.ID, "tmp_u", "tmp_p"); err != nil {
		t.Fatalf("saving temp credentials: %v", err)
	}
	if err := srv.submissions.UpdateStatus(context.Background(), sub.ID, "payload_obtained", "UPLOAD_PENDING"); err != nil {
		t.Fatalf("updating status: %v", err)
	}

	return orgID, sub.ID, rawKey
}

func TestSubmitToFDA_Success(t *testing.T) {
	fdaServer := newMockFDAServer(t)
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL,
		UploadBaseURL:   fdaServer.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     fdaclient.EnvTest,
	})

	srv := newTestServerWithFDA(t, fdaClient)
	orgID, userID := seedTestData(t, "workflow-success")
	apiKey := seedAPIKey(t, orgID, userID)

	// Create a draft submission
	sub, err := srv.submissions.Create(context.Background(), repository.CreateSubmissionParams{
		OrgID:              orgID,
		FDACenter:          "CDER",
		SubmissionType:     "ANDA",
		SubmissionName:     "Workflow Test",
		SubmissionProtocol: "API",
		FileCount:          1,
		Description:        "Test workflow",
		CreatedBy:          userID,
	})
	if err != nil {
		t.Fatalf("creating submission: %v", err)
	}

	body := map[string]string{
		"user_email": "submitter@pharma.com",
		"company_id": "COMP-1",
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/submissions/%s/submit", sub.ID), bytes.NewReader(b))
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp submitToFDAResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if !strings.HasPrefix(resp.CoreID, "CORE-WORKFLOW-") {
		t.Errorf("expected core_id with prefix 'CORE-WORKFLOW-', got %q", resp.CoreID)
	}
	if !strings.HasPrefix(resp.PayloadID, "PL-WORKFLOW-") {
		t.Errorf("expected payload_id with prefix 'PL-WORKFLOW-', got %q", resp.PayloadID)
	}
	if resp.Status != "payload_obtained" {
		t.Errorf("expected status 'payload_obtained', got %q", resp.Status)
	}

	// Verify DB was updated
	updated, _ := srv.submissions.GetByID(context.Background(), orgID, sub.ID)
	if !updated.CoreID.Valid || !strings.HasPrefix(updated.CoreID.String, "CORE-WORKFLOW-") {
		t.Errorf("DB core_id not updated: %v", updated.CoreID)
	}
	if !updated.PayloadID.Valid || !strings.HasPrefix(updated.PayloadID.String, "PL-WORKFLOW-") {
		t.Errorf("DB payload_id not updated: %v", updated.PayloadID)
	}
	if updated.Status != "payload_obtained" {
		t.Errorf("DB status expected 'payload_obtained', got %q", updated.Status)
	}
}

func TestSubmitToFDA_NotDraft(t *testing.T) {
	fdaServer := newMockFDAServer(t)
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL,
		UploadBaseURL:   fdaServer.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     fdaclient.EnvTest,
	})

	srv := newTestServerWithFDA(t, fdaClient)
	orgID, userID := seedTestData(t, "workflow-notdraft")
	apiKey := seedAPIKey(t, orgID, userID)

	sub, _ := srv.submissions.Create(context.Background(), repository.CreateSubmissionParams{
		OrgID: orgID, SubmissionType: "ANDA", SubmissionName: "Already Submitted",
		SubmissionProtocol: "API", FileCount: 1, CreatedBy: userID,
	})
	// Move out of draft
	srv.submissions.UpdateStatus(context.Background(), sub.ID, "initiated", "CREDENTIALS_PENDING")

	body := map[string]string{"user_email": "u@x.com", "company_id": "C1"}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/submissions/%s/submit", sub.ID), bytes.NewReader(b))
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSubmitToFDA_NotFound(t *testing.T) {
	fdaServer := newMockFDAServer(t)
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL,
		UploadBaseURL:   fdaServer.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     fdaclient.EnvTest,
	})

	srv := newTestServerWithFDA(t, fdaClient)
	orgID, userID := seedTestData(t, "workflow-notfound")
	apiKey := seedAPIKey(t, orgID, userID)

	body := map[string]string{"user_email": "u@x.com", "company_id": "C1"}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/submissions/00000000-0000-0000-0000-000000000000/submit", bytes.NewReader(b))
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSubmitToFDA_MissingFields(t *testing.T) {
	srv := newTestServer(t)
	orgID, userID := seedTestData(t, "workflow-missingfields")
	apiKey := seedAPIKey(t, orgID, userID)

	body := map[string]string{} // missing user_email and company_id
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/submissions/some-id/submit", bytes.NewReader(b))
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSubmitToFDA_FDACredentialFailure(t *testing.T) {
	// FDA server that rejects credential requests
	fdaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/as/token.oauth2" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok", "token_type": "Bearer", "expires_in": 3600,
			})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"esgngcode": "ESGNG400", "esgngdescription": "Bad request",
		})
	}))
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL,
		UploadBaseURL:   fdaServer.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     fdaclient.EnvTest,
	})

	srv := newTestServerWithFDA(t, fdaClient)
	orgID, userID := seedTestData(t, "workflow-credfail")
	apiKey := seedAPIKey(t, orgID, userID)

	sub, _ := srv.submissions.Create(context.Background(), repository.CreateSubmissionParams{
		OrgID: orgID, SubmissionType: "ANDA", SubmissionName: "Cred Fail Test",
		SubmissionProtocol: "API", FileCount: 1, CreatedBy: userID,
	})

	body := map[string]string{"user_email": "u@x.com", "company_id": "C1"}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/submissions/%s/submit", sub.ID), bytes.NewReader(b))
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d: %s", w.Code, w.Body.String())
	}

	// Verify DB status was set to failed
	updated, _ := srv.submissions.GetByID(context.Background(), orgID, sub.ID)
	if updated.Status != "failed" {
		t.Errorf("expected status 'failed' after FDA error, got %q", updated.Status)
	}
}

// --- File Upload Tests ---

// createMultipartFileRequest builds a multipart POST request with a file field.
func createMultipartFileRequest(t *testing.T, url, fieldName, fileName string, content []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile(fieldName, fileName)
	if err != nil {
		t.Fatalf("creating form file: %v", err)
	}
	if _, err := io.Copy(part, bytes.NewReader(content)); err != nil {
		t.Fatalf("writing file content: %v", err)
	}
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, url, &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func TestUploadFile_Success(t *testing.T) {
	fdaServer := newMockFDAServer(t)
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL,
		UploadBaseURL:   fdaServer.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     fdaclient.EnvTest,
	})

	srv := newTestServerWithFDA(t, fdaClient)
	orgID, subID, apiKey := setupPayloadObtainedSubmission(t, srv, "upload-success")

	fileContent := []byte("test file content for FDA submission")
	req := createMultipartFileRequest(t,
		fmt.Sprintf("/api/v1/submissions/%s/files", subID),
		"file", "test-document.pdf", fileContent)
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp uploadFileResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.FileID == "" {
		t.Error("expected non-empty file_id")
	}
	if resp.FileName != "test-document.pdf" {
		t.Errorf("expected file_name 'test-document.pdf', got %q", resp.FileName)
	}
	if resp.FileSizeBytes != int64(len(fileContent)) {
		t.Errorf("expected file_size_bytes %d, got %d", len(fileContent), resp.FileSizeBytes)
	}

	// Verify checksum matches
	expectedHash := sha256.Sum256(fileContent)
	expectedChecksum := hex.EncodeToString(expectedHash[:])
	if resp.SHA256Checksum != expectedChecksum {
		t.Errorf("expected checksum %q, got %q", expectedChecksum, resp.SHA256Checksum)
	}
	if resp.UploadStatus != "uploaded" {
		t.Errorf("expected upload_status 'uploaded', got %q", resp.UploadStatus)
	}

	// Verify DB records
	files, _ := srv.files.ListBySubmission(context.Background(), subID)
	if len(files) != 1 {
		t.Fatalf("expected 1 file record, got %d", len(files))
	}
	if files[0].UploadStatus != "uploaded" {
		t.Errorf("DB file status expected 'uploaded', got %q", files[0].UploadStatus)
	}

	// Verify submission status was updated
	updated, _ := srv.submissions.GetByID(context.Background(), orgID, subID)
	if updated.Status != "file_uploaded" {
		t.Errorf("expected submission status 'file_uploaded', got %q", updated.Status)
	}
}

func TestUploadFile_WrongStatus(t *testing.T) {
	fdaServer := newMockFDAServer(t)
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL,
		UploadBaseURL:   fdaServer.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     fdaclient.EnvTest,
	})

	srv := newTestServerWithFDA(t, fdaClient)
	orgID, userID := seedTestData(t, "upload-wrongstatus")
	apiKey := seedAPIKey(t, orgID, userID)

	// Create a draft submission (not payload_obtained)
	sub, _ := srv.submissions.Create(context.Background(), repository.CreateSubmissionParams{
		OrgID: orgID, SubmissionType: "ANDA", SubmissionName: "Draft Sub",
		SubmissionProtocol: "API", FileCount: 1, CreatedBy: userID,
	})

	req := createMultipartFileRequest(t,
		fmt.Sprintf("/api/v1/submissions/%s/files", sub.ID),
		"file", "test.pdf", []byte("data"))
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUploadFile_NotFound(t *testing.T) {
	fdaServer := newMockFDAServer(t)
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL,
		UploadBaseURL:   fdaServer.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     fdaclient.EnvTest,
	})

	srv := newTestServerWithFDA(t, fdaClient)
	orgID, userID := seedTestData(t, "upload-notfound")
	apiKey := seedAPIKey(t, orgID, userID)

	req := createMultipartFileRequest(t,
		"/api/v1/submissions/00000000-0000-0000-0000-000000000000/files",
		"file", "test.pdf", []byte("data"))
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUploadFile_ExceedsFileCount(t *testing.T) {
	fdaServer := newMockFDAServer(t)
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL,
		UploadBaseURL:   fdaServer.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     fdaclient.EnvTest,
	})

	srv := newTestServerWithFDA(t, fdaClient)
	_, subID, apiKey := setupPayloadObtainedSubmission(t, srv, "upload-exceed")

	// Upload the first file (file_count is 1)
	req := createMultipartFileRequest(t,
		fmt.Sprintf("/api/v1/submissions/%s/files", subID),
		"file", "first.pdf", []byte("first file"))
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first upload failed: %d: %s", w.Code, w.Body.String())
	}

	// Try to upload a second file — should be rejected
	req2 := createMultipartFileRequest(t,
		fmt.Sprintf("/api/v1/submissions/%s/files", subID),
		"file", "second.pdf", []byte("second file"))
	req2.Header.Set("Authorization", authHeader(apiKey))
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)

	if w2.Code != http.StatusConflict {
		t.Errorf("expected 409 for exceeding file count, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestUploadFile_FDAFailure(t *testing.T) {
	// FDA server that accepts token but rejects uploads
	fdaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/as/token.oauth2" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok", "token_type": "Bearer", "expires_in": 3600,
			})
			return
		}
		// Reject all other requests (including file uploads)
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"esgngcode": "ESGNG503", "esgngdescription": "Service unavailable",
		})
	}))
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL,
		UploadBaseURL:   fdaServer.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     fdaclient.EnvTest,
	})

	srv := newTestServerWithFDA(t, fdaClient)
	_, subID, apiKey := setupPayloadObtainedSubmission(t, srv, "upload-fdafail")

	req := createMultipartFileRequest(t,
		fmt.Sprintf("/api/v1/submissions/%s/files", subID),
		"file", "test.pdf", []byte("data"))
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d: %s", w.Code, w.Body.String())
	}

	// Verify the file record was marked as failed
	files, _ := srv.files.ListBySubmission(context.Background(), subID)
	if len(files) != 1 {
		t.Fatalf("expected 1 file record, got %d", len(files))
	}
	if files[0].UploadStatus != "failed" {
		t.Errorf("expected file status 'failed', got %q", files[0].UploadStatus)
	}
}

// --- Finalize Tests ---

func TestFinalizeSubmission_Success(t *testing.T) {
	fdaServer := newMockFDAServer(t)
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL,
		UploadBaseURL:   fdaServer.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     fdaclient.EnvTest,
	})

	srv := newTestServerWithFDA(t, fdaClient)
	orgID, subID, apiKey := setupPayloadObtainedSubmission(t, srv, "finalize-success")

	// Upload a file first (required before finalize)
	uploadReq := createMultipartFileRequest(t,
		fmt.Sprintf("/api/v1/submissions/%s/files", subID),
		"file", "submission.pdf", []byte("final file content"))
	uploadReq.Header.Set("Authorization", authHeader(apiKey))
	uploadW := httptest.NewRecorder()
	srv.ServeHTTP(uploadW, uploadReq)
	if uploadW.Code != http.StatusOK {
		t.Fatalf("upload prerequisite failed: %d: %s", uploadW.Code, uploadW.Body.String())
	}

	// Finalize
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/submissions/%s/finalize", subID), nil)
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp finalizeResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.SubmissionID != subID {
		t.Errorf("expected submission_id %q, got %q", subID, resp.SubmissionID)
	}
	if resp.Status != "submitted" {
		t.Errorf("expected status 'submitted', got %q", resp.Status)
	}
	if resp.WorkflowState != "SUBMITTED" {
		t.Errorf("expected workflow_state 'SUBMITTED', got %q", resp.WorkflowState)
	}

	// Verify DB status
	updated, _ := srv.submissions.GetByID(context.Background(), orgID, subID)
	if updated.Status != "submitted" {
		t.Errorf("DB status expected 'submitted', got %q", updated.Status)
	}
	if updated.WorkflowState != "SUBMITTED" {
		t.Errorf("DB workflow_state expected 'SUBMITTED', got %q", updated.WorkflowState)
	}
}

func TestFinalizeSubmission_WrongStatus(t *testing.T) {
	srv := newTestServer(t)
	orgID, userID := seedTestData(t, "finalize-wrongstatus")
	apiKey := seedAPIKey(t, orgID, userID)

	// Create a draft submission (not file_uploaded)
	sub, _ := srv.submissions.Create(context.Background(), repository.CreateSubmissionParams{
		OrgID: orgID, SubmissionType: "ANDA", SubmissionName: "Draft Sub",
		SubmissionProtocol: "API", FileCount: 1, CreatedBy: userID,
	})

	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/submissions/%s/finalize", sub.ID), nil)
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFinalizeSubmission_NotAllFilesUploaded(t *testing.T) {
	fdaServer := newMockFDAServer(t)
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL,
		UploadBaseURL:   fdaServer.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     fdaclient.EnvTest,
	})

	srv := newTestServerWithFDA(t, fdaClient)
	orgID, userID := seedTestData(t, "finalize-notready")
	apiKey := seedAPIKey(t, orgID, userID)

	// Create submission expecting 2 files
	sub, _ := srv.submissions.Create(context.Background(), repository.CreateSubmissionParams{
		OrgID: orgID, FDACenter: "CDER", SubmissionType: "ANDA",
		SubmissionName: "Two File Sub", SubmissionProtocol: "API",
		FileCount: 2, CreatedBy: userID,
	})

	// Set up as payload_obtained with FDA fields
	srv.submissions.UpdateFDAFields(context.Background(), sub.ID,
		"CORE-NOTREADY", "PL-NOTREADY", "/upload", "/submit")
	srv.submissions.SaveTempCredentials(context.Background(), sub.ID, "tmp_u", "tmp_p")
	srv.submissions.UpdateStatus(context.Background(), sub.ID, "payload_obtained", "UPLOAD_PENDING")

	// Upload only 1 of 2 files
	uploadReq := createMultipartFileRequest(t,
		fmt.Sprintf("/api/v1/submissions/%s/files", sub.ID),
		"file", "first.pdf", []byte("first"))
	uploadReq.Header.Set("Authorization", authHeader(apiKey))
	uploadW := httptest.NewRecorder()
	srv.ServeHTTP(uploadW, uploadReq)
	if uploadW.Code != http.StatusOK {
		t.Fatalf("first upload failed: %d: %s", uploadW.Code, uploadW.Body.String())
	}

	// Try to finalize — should fail because only 1 of 2 files uploaded
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/submissions/%s/finalize", sub.ID), nil)
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestFinalizeSubmission_FDAFailure(t *testing.T) {
	// FDA server that rejects submit
	fdaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/as/token.oauth2":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok", "token_type": "Bearer", "expires_in": 3600,
			})
		case strings.HasSuffix(r.URL.Path, "/file") && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"fileName": "test.pdf", "fileSize": 4,
				"esgngcode": "ESGNG210", "esgngdescription": "ok",
			})
		case strings.HasSuffix(r.URL.Path, "/submit"):
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"esgngcode": "ESGNG500", "esgngdescription": "FDA processing error",
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL,
		UploadBaseURL:   fdaServer.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     fdaclient.EnvTest,
	})

	srv := newTestServerWithFDA(t, fdaClient)
	orgID, subID, apiKey := setupPayloadObtainedSubmission(t, srv, "finalize-fdafail")

	// Upload a file first
	uploadReq := createMultipartFileRequest(t,
		fmt.Sprintf("/api/v1/submissions/%s/files", subID),
		"file", "test.pdf", []byte("data"))
	uploadReq.Header.Set("Authorization", authHeader(apiKey))
	uploadW := httptest.NewRecorder()
	srv.ServeHTTP(uploadW, uploadReq)
	if uploadW.Code != http.StatusOK {
		t.Fatalf("upload failed: %d: %s", uploadW.Code, uploadW.Body.String())
	}

	// Finalize — FDA submit should fail
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/submissions/%s/finalize", subID), nil)
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d: %s", w.Code, w.Body.String())
	}

	// Verify status is failed
	updated, _ := srv.submissions.GetByID(context.Background(), orgID, subID)
	if updated.Status != "failed" {
		t.Errorf("expected status 'failed', got %q", updated.Status)
	}
}

func TestSubmitToFDA_PersistsTempCredentials(t *testing.T) {
	fdaServer := newMockFDAServer(t)
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL,
		UploadBaseURL:   fdaServer.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     fdaclient.EnvTest,
	})

	srv := newTestServerWithFDA(t, fdaClient)
	orgID, userID := seedTestData(t, "workflow-tempcreds")
	apiKey := seedAPIKey(t, orgID, userID)

	sub, _ := srv.submissions.Create(context.Background(), repository.CreateSubmissionParams{
		OrgID: orgID, FDACenter: "CDER", SubmissionType: "ANDA",
		SubmissionName: "Temp Creds Test", SubmissionProtocol: "API",
		FileCount: 1, CreatedBy: userID,
	})

	body := map[string]string{
		"user_email": "u@x.com", "company_id": "C1",
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/submissions/%s/submit", sub.ID), bytes.NewReader(b))
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify temp credentials were persisted
	creds, err := srv.submissions.GetTempCredentials(context.Background(), sub.ID)
	if err != nil {
		t.Fatalf("getting temp credentials: %v", err)
	}
	if creds.TempUser != "tmp_u" {
		t.Errorf("expected temp_user 'tmp_u', got %q", creds.TempUser)
	}
	if creds.TempPassword != "tmp_p" {
		t.Errorf("expected temp_password 'tmp_p', got %q", creds.TempPassword)
	}
}

// --- Status Polling Tests ---

// setupSubmittedSubmission creates a submission in "submitted" state with a core_id set.
// Returns orgID, subID, and the raw API key for auth.
func setupSubmittedSubmission(t *testing.T, srv *Server, suffix string) (orgID, subID, rawKey string) {
	t.Helper()
	orgID, userID := seedTestData(t, suffix)
	rawKey = seedAPIKey(t, orgID, userID)

	sub, err := srv.submissions.Create(context.Background(), repository.CreateSubmissionParams{
		OrgID:              orgID,
		FDACenter:          "CDER",
		SubmissionType:     "ANDA",
		SubmissionName:     "Status Test " + suffix,
		SubmissionProtocol: "API",
		FileCount:          1,
		CreatedBy:          userID,
	})
	if err != nil {
		t.Fatalf("creating submission: %v", err)
	}

	// Set core_id and advance to submitted
	if err := srv.submissions.UpdateFDAFields(context.Background(), sub.ID,
		"CORE-STATUS-"+suffix, "PL-STATUS-"+suffix,
		"/upload/"+suffix, "/submit/"+suffix,
	); err != nil {
		t.Fatalf("updating FDA fields: %v", err)
	}
	if err := srv.submissions.UpdateStatus(context.Background(), sub.ID, "submitted", "SUBMITTED"); err != nil {
		t.Fatalf("updating status: %v", err)
	}

	return orgID, sub.ID, rawKey
}

func TestGetStatus_Success(t *testing.T) {
	fdaServer := newMockFDAServer(t)
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL,
		UploadBaseURL:   fdaServer.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     fdaclient.EnvTest,
	})

	srv := newTestServerWithFDA(t, fdaClient)
	orgID, subID, apiKey := setupSubmittedSubmission(t, srv, "status-success")

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/submissions/%s/status", subID), nil)
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp statusResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.SubmissionID != subID {
		t.Errorf("expected submission_id %q, got %q", subID, resp.SubmissionID)
	}
	if resp.FDAStatus != "ACCEPTED" {
		t.Errorf("expected fda_status 'ACCEPTED', got %q", resp.FDAStatus)
	}
	if resp.LocalStatus != "completed" {
		t.Errorf("expected local_status 'completed', got %q", resp.LocalStatus)
	}
	if resp.WorkflowState != "ACCEPTED" {
		t.Errorf("expected workflow_state 'ACCEPTED', got %q", resp.WorkflowState)
	}
	if len(resp.Acknowledgements) != 1 {
		t.Fatalf("expected 1 acknowledgement, got %d", len(resp.Acknowledgements))
	}
	if resp.Acknowledgements[0].AcknowledgementID != "ACK-001" {
		t.Errorf("expected acknowledgement_id 'ACK-001', got %q", resp.Acknowledgements[0].AcknowledgementID)
	}
	if resp.Acknowledgements[0].RawMessage != "<xml>ack</xml>" {
		t.Errorf("expected raw_message '<xml>ack</xml>', got %q", resp.Acknowledgements[0].RawMessage)
	}

	// Verify DB was updated to reflect FDA status
	updated, _ := srv.submissions.GetByID(context.Background(), orgID, subID)
	if updated.Status != "completed" {
		t.Errorf("DB status expected 'completed', got %q", updated.Status)
	}
	if updated.WorkflowState != "ACCEPTED" {
		t.Errorf("DB workflow_state expected 'ACCEPTED', got %q", updated.WorkflowState)
	}
}

func TestGetStatus_NotFound(t *testing.T) {
	srv := newTestServer(t)
	orgID, userID := seedTestData(t, "status-notfound")
	apiKey := seedAPIKey(t, orgID, userID)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/submissions/00000000-0000-0000-0000-000000000000/status", nil)
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetStatus_NoCoreID(t *testing.T) {
	srv := newTestServer(t)
	orgID, userID := seedTestData(t, "status-nocoreid")
	apiKey := seedAPIKey(t, orgID, userID)

	// Create a draft submission (no core_id)
	sub, _ := srv.submissions.Create(context.Background(), repository.CreateSubmissionParams{
		OrgID: orgID, SubmissionType: "ANDA", SubmissionName: "No Core ID",
		SubmissionProtocol: "API", FileCount: 1, CreatedBy: userID,
	})

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/submissions/%s/status", sub.ID), nil)
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetStatus_FDAFailure(t *testing.T) {
	// FDA server that accepts token but rejects status checks
	fdaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/as/token.oauth2" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok", "token_type": "Bearer", "expires_in": 3600,
			})
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"esgngcode": "ESGNG503", "esgngdescription": "Service unavailable",
		})
	}))
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL,
		UploadBaseURL:   fdaServer.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     fdaclient.EnvTest,
	})

	srv := newTestServerWithFDA(t, fdaClient)
	_, subID, apiKey := setupSubmittedSubmission(t, srv, "status-fdafail")

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/submissions/%s/status", subID), nil)
	req.Header.Set("Authorization", authHeader(apiKey))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d: %s", w.Code, w.Body.String())
	}
}
