//go:build integration

package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/kingman4/better-esg/internal/database"
	"github.com/kingman4/better-esg/internal/fdaclient"
	"github.com/kingman4/better-esg/internal/repository"
	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Package-level shared test infrastructure — one container for all tests.
var (
	testDB        *sql.DB
	testContainer testcontainers.Container
)

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
		submissions: repository.NewSubmissionRepo(testDB),
		fda:         fda,
	}
	s.routes()
	return s
}

func TestCreateSubmission_Success(t *testing.T) {
	srv := newTestServer(t)
	orgID, userID := seedTestData(t, "create-success")

	body := map[string]any{
		"org_id":          orgID,
		"fda_center":      "CDER",
		"submission_type": "ANDA",
		"submission_name": "Test Drug Application",
		"file_count":      3,
		"description":     "Phase 3 data",
		"created_by":      userID,
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/submissions", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
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

	tests := []struct {
		name string
		body map[string]any
	}{
		{"missing org_id", map[string]any{"submission_type": "ANDA", "submission_name": "x", "file_count": 1, "created_by": "uid"}},
		{"missing submission_type", map[string]any{"org_id": "oid", "submission_name": "x", "file_count": 1, "created_by": "uid"}},
		{"missing submission_name", map[string]any{"org_id": "oid", "submission_type": "ANDA", "file_count": 1, "created_by": "uid"}},
		{"missing created_by", map[string]any{"org_id": "oid", "submission_type": "ANDA", "submission_name": "x", "file_count": 1}},
		{"zero file_count", map[string]any{"org_id": "oid", "submission_type": "ANDA", "submission_name": "x", "file_count": 0, "created_by": "uid"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/submissions", bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
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

	req := httptest.NewRequest(http.MethodPost, "/api/v1/submissions", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestGetSubmission_Success(t *testing.T) {
	srv := newTestServer(t)
	orgID, userID := seedTestData(t, "get-success")

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
		fmt.Sprintf("/api/v1/submissions/%s?org_id=%s", sub.ID, orgID), nil)
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
	orgID, _ := seedTestData(t, "get-notfound")

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/submissions/00000000-0000-0000-0000-000000000000?org_id=%s", orgID), nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetSubmission_MissingOrgID(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/submissions/some-id", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestListSubmissions_Success(t *testing.T) {
	srv := newTestServer(t)
	orgID, userID := seedTestData(t, "list-success")

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

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/submissions?org_id=%s", orgID), nil)
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
	orgID, _ := seedTestData(t, "list-empty")

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/submissions?org_id=%s", orgID), nil)
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

func TestListSubmissions_MissingOrgID(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/submissions", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestListSubmissions_Pagination(t *testing.T) {
	srv := newTestServer(t)
	orgID, userID := seedTestData(t, "list-pagination")

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

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/v1/submissions?org_id=%s&limit=2&offset=0", orgID), nil)
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
// credential submission, and payload endpoints.
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
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"core_id":          "CORE-WORKFLOW-123",
				"temp_user":        "tmp_u",
				"temp_password":    "tmp_p",
				"esgngcode":        "ESGNG210",
				"esgngdescription": "ok",
			})

		case r.URL.Path == "/rest/forms/v1/fileupload/payload" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"payloadId": "PL-WORKFLOW-456",
				"links": map[string]string{
					"uploadLink": "/rest/forms/v1/fileupload/payload/PL-WORKFLOW-456/file",
					"submitLink": "/rest/forms/v1/fileupload/payload/PL-WORKFLOW-456/submit",
				},
			})

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
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
		"org_id":     orgID,
		"user_email": "submitter@pharma.com",
		"company_id": "COMP-1",
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/submissions/%s/submit", sub.ID), bytes.NewReader(b))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp submitToFDAResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.CoreID != "CORE-WORKFLOW-123" {
		t.Errorf("expected core_id 'CORE-WORKFLOW-123', got %q", resp.CoreID)
	}
	if resp.PayloadID != "PL-WORKFLOW-456" {
		t.Errorf("expected payload_id 'PL-WORKFLOW-456', got %q", resp.PayloadID)
	}
	if resp.Status != "payload_obtained" {
		t.Errorf("expected status 'payload_obtained', got %q", resp.Status)
	}

	// Verify DB was updated
	updated, _ := srv.submissions.GetByID(context.Background(), orgID, sub.ID)
	if !updated.CoreID.Valid || updated.CoreID.String != "CORE-WORKFLOW-123" {
		t.Errorf("DB core_id not updated: %v", updated.CoreID)
	}
	if !updated.PayloadID.Valid || updated.PayloadID.String != "PL-WORKFLOW-456" {
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

	sub, _ := srv.submissions.Create(context.Background(), repository.CreateSubmissionParams{
		OrgID: orgID, SubmissionType: "ANDA", SubmissionName: "Already Submitted",
		SubmissionProtocol: "API", FileCount: 1, CreatedBy: userID,
	})
	// Move out of draft
	srv.submissions.UpdateStatus(context.Background(), sub.ID, "initiated", "CREDENTIALS_PENDING")

	body := map[string]string{"org_id": orgID, "user_email": "u@x.com", "company_id": "C1"}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/submissions/%s/submit", sub.ID), bytes.NewReader(b))
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
	orgID, _ := seedTestData(t, "workflow-notfound")

	body := map[string]string{"org_id": orgID, "user_email": "u@x.com", "company_id": "C1"}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/submissions/00000000-0000-0000-0000-000000000000/submit", bytes.NewReader(b))
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSubmitToFDA_MissingFields(t *testing.T) {
	srv := newTestServer(t)

	body := map[string]string{"org_id": "x"} // missing user_email and company_id
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/submissions/some-id/submit", bytes.NewReader(b))
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

	sub, _ := srv.submissions.Create(context.Background(), repository.CreateSubmissionParams{
		OrgID: orgID, SubmissionType: "ANDA", SubmissionName: "Cred Fail Test",
		SubmissionProtocol: "API", FileCount: 1, CreatedBy: userID,
	})

	body := map[string]string{"org_id": orgID, "user_email": "u@x.com", "company_id": "C1"}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/submissions/%s/submit", sub.ID), bytes.NewReader(b))
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
