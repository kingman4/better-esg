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

// newTestServer creates a Server backed by the shared DB. No container spin-up.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	s := &Server{
		db:          testDB,
		router:      http.NewServeMux(),
		submissions: repository.NewSubmissionRepo(testDB),
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
