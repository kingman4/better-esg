//go:build integration

package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kingman4/better-esg/internal/fdaclient"
	"github.com/kingman4/better-esg/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Repository Tests ---

func TestListByWorkflowStates(t *testing.T) {
	srv := newTestServer(t)
	suffix := fmt.Sprintf("lwfs-%d", time.Now().UnixNano())
	orgID, userID := seedTestData(t, suffix)

	ctx := context.Background()

	// Create 4 submissions in different states
	createSub := func(name, status, workflow string, setCoreID bool) string {
		t.Helper()
		sub, err := srv.submissions.Create(ctx, repository.CreateSubmissionParams{
			OrgID:              orgID,
			FDACenter:          "CDER",
			SubmissionType:     "ANDA",
			SubmissionName:     name,
			SubmissionProtocol: "API",
			FileCount:          1,
			CreatedBy:          userID,
		})
		require.NoError(t, err)
		if setCoreID {
			err = srv.submissions.UpdateFDAFields(ctx, sub.ID,
				"CORE-"+name, "PL-"+name, "/upload", "/submit")
			require.NoError(t, err)
		}
		err = srv.submissions.UpdateStatus(ctx, sub.ID, status, workflow)
		require.NoError(t, err)
		return sub.ID
	}

	subSubmitted := createSub("sub-submitted-"+suffix, "submitted", "SUBMITTED", true)
	subProcessing := createSub("sub-processing-"+suffix, "submitted", "PROCESSING", true)
	_ = createSub("sub-accepted-"+suffix, "completed", "ACCEPTED", true)        // terminal — should NOT be returned
	_ = createSub("sub-no-coreid-"+suffix, "submitted", "SUBMITTED", false)      // no core_id — should NOT be returned

	subs, err := srv.submissions.ListByWorkflowStates(ctx, []string{"SUBMITTED", "PROCESSING"})
	require.NoError(t, err)

	// Collect IDs from result
	ids := make(map[string]bool)
	for _, s := range subs {
		ids[s.ID] = true
	}

	assert.True(t, ids[subSubmitted], "SUBMITTED with core_id should be returned")
	assert.True(t, ids[subProcessing], "PROCESSING with core_id should be returned")
}

// --- Poller Tests ---

// newMockFDAServerWithStatus creates a mock FDA server that returns the given status.
func newMockFDAServerWithStatus(t *testing.T, status string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/as/token.oauth2":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token", "token_type": "Bearer", "expires_in": 3600,
			})

		case strings.HasPrefix(r.URL.Path, "/api/esgng/v1/submissions/") && r.Method == http.MethodGet:
			coreID := strings.TrimPrefix(r.URL.Path, "/api/esgng/v1/submissions/")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"core_id":          coreID,
				"status":           status,
				"esgngcode":        "ESGNG210",
				"esgngdescription": "ok",
				"acknowledgements": []map[string]string{
					{"acknowledgement_id": "ACK-" + coreID, "type": "Technical"},
				},
			})

		case strings.HasPrefix(r.URL.Path, "/api/esgng/v1/acknowledgements/") && r.Method == http.MethodGet:
			ackID := strings.TrimPrefix(r.URL.Path, "/api/esgng/v1/acknowledgements/")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"acknowledgement_id": ackID,
				"type":               "Technical",
				"raw_message":        "<xml>ack</xml>",
				"parsed_data":        map[string]string{"result": "ok"},
				"esgngcode":          "ESGNG210",
				"esgngdescription":   "ok",
			})

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

// setupSubmittedSub creates a submitted submission with a unique core_id.
// Returns (subID, coreID).
func setupSubmittedSub(t *testing.T, srv *Server, orgID, userID, suffix string) (string, string) {
	t.Helper()
	ctx := context.Background()
	n := mockCoreIDCounter.Add(1)
	coreID := fmt.Sprintf("CORE-POLL-%d-%s", n, suffix)

	sub, err := srv.submissions.Create(ctx, repository.CreateSubmissionParams{
		OrgID:              orgID,
		FDACenter:          "CDER",
		SubmissionType:     "ANDA",
		SubmissionName:     "Poll Test " + suffix,
		SubmissionProtocol: "API",
		FileCount:          1,
		CreatedBy:          userID,
	})
	require.NoError(t, err)

	err = srv.submissions.UpdateFDAFields(ctx, sub.ID, coreID, "PL-"+suffix, "/upload", "/submit")
	require.NoError(t, err)

	err = srv.submissions.UpdateStatus(ctx, sub.ID, "submitted", "SUBMITTED")
	require.NoError(t, err)

	return sub.ID, coreID
}

func TestPollAllSubmissions_UpdatesStatus(t *testing.T) {
	fdaServer := newMockFDAServerWithStatus(t, "ACCEPTED")
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL,
		UploadBaseURL:   fdaServer.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     fdaclient.EnvTest,
	})

	srv := newTestServerWithFDA(t, fdaClient)
	suffix := fmt.Sprintf("poll-update-%d", time.Now().UnixNano())
	orgID, userID := seedTestData(t, suffix)

	subID1, _ := setupSubmittedSub(t, srv, orgID, userID, suffix+"-1")
	subID2, _ := setupSubmittedSub(t, srv, orgID, userID, suffix+"-2")

	// Run one poll cycle
	srv.pollAllSubmissions(context.Background())

	// Verify both submissions updated to completed/ACCEPTED
	ctx := context.Background()
	for _, subID := range []string{subID1, subID2} {
		sub, err := srv.submissions.GetByID(ctx, orgID, subID)
		require.NoError(t, err)
		assert.Equal(t, "completed", sub.Status, "subID=%s", subID)
		assert.Equal(t, "ACCEPTED", sub.WorkflowState, "subID=%s", subID)
	}
}

func TestPollAllSubmissions_SkipsOnFDAError(t *testing.T) {
	// Mock server that returns 503 for the first core_id and ACCEPTED for others
	var failCoreID atomic.Value
	fdaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/as/token.oauth2":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token", "token_type": "Bearer", "expires_in": 3600,
			})

		case strings.HasPrefix(r.URL.Path, "/api/esgng/v1/submissions/") && r.Method == http.MethodGet:
			coreID := strings.TrimPrefix(r.URL.Path, "/api/esgng/v1/submissions/")
			if v := failCoreID.Load(); v != nil && coreID == v.(string) {
				http.Error(w, "service unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"core_id": coreID, "status": "ACCEPTED",
				"esgngcode": "ESGNG210", "esgngdescription": "ok",
				"acknowledgements": []map[string]string{},
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
	suffix := fmt.Sprintf("poll-skip-%d", time.Now().UnixNano())
	orgID, userID := seedTestData(t, suffix)

	subID1, coreID1 := setupSubmittedSub(t, srv, orgID, userID, suffix+"-1")
	subID2, _ := setupSubmittedSub(t, srv, orgID, userID, suffix+"-2")

	// Make first submission's FDA call fail
	failCoreID.Store(coreID1)

	srv.pollAllSubmissions(context.Background())

	ctx := context.Background()

	// First submission should NOT have been updated (FDA error)
	sub1, err := srv.submissions.GetByID(ctx, orgID, subID1)
	require.NoError(t, err)
	assert.Equal(t, "submitted", sub1.Status, "failed sub should remain submitted")
	assert.Equal(t, "SUBMITTED", sub1.WorkflowState, "failed sub should remain SUBMITTED")

	// Second submission SHOULD have been updated
	sub2, err := srv.submissions.GetByID(ctx, orgID, subID2)
	require.NoError(t, err)
	assert.Equal(t, "completed", sub2.Status, "successful sub should be completed")
	assert.Equal(t, "ACCEPTED", sub2.WorkflowState, "successful sub should be ACCEPTED")
}

func TestPollAllSubmissions_StoresAcknowledgements(t *testing.T) {
	fdaServer := newMockFDAServerWithStatus(t, "ACCEPTED")
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL,
		UploadBaseURL:   fdaServer.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     fdaclient.EnvTest,
	})

	srv := newTestServerWithFDA(t, fdaClient)
	suffix := fmt.Sprintf("poll-ack-%d", time.Now().UnixNano())
	orgID, userID := seedTestData(t, suffix)

	subID, coreID := setupSubmittedSub(t, srv, orgID, userID, suffix)

	// Run poll
	srv.pollAllSubmissions(context.Background())

	// Verify ack was stored
	var ackCount int
	var fdaAckID, rawMessage sql.NullString
	err := testDB.QueryRowContext(context.Background(),
		`SELECT COUNT(*), MIN(fda_ack_id), MIN(raw_message) FROM acknowledgements WHERE submission_id = $1`, subID,
	).Scan(&ackCount, &fdaAckID, &rawMessage)
	require.NoError(t, err)
	assert.Equal(t, 1, ackCount)
	assert.Equal(t, "ACK-"+coreID, fdaAckID.String)
	assert.Equal(t, "<xml>ack</xml>", rawMessage.String)

	// Run poll again — should NOT create duplicate acks
	srv.pollAllSubmissions(context.Background())

	err = testDB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM acknowledgements WHERE submission_id = $1`, subID,
	).Scan(&ackCount)
	require.NoError(t, err)
	assert.Equal(t, 1, ackCount, "should not duplicate acks on re-poll")
}

func TestPollAllSubmissions_NoOpWhenNoneInFlight(t *testing.T) {
	// Track whether FDA was called
	var fdaCalled atomic.Int64
	fdaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/as/token.oauth2":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token", "token_type": "Bearer", "expires_in": 3600,
			})
		case strings.HasPrefix(r.URL.Path, "/api/esgng/v1/submissions/"):
			fdaCalled.Add(1)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"core_id": "X", "status": "ACCEPTED",
				"esgngcode": "ESGNG210", "esgngdescription": "ok",
				"acknowledgements": []map[string]string{},
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL, UploadBaseURL: fdaServer.URL,
		ClientID: "id", ClientSecret: "secret", Environment: fdaclient.EnvTest,
	})
	srv := newTestServerWithFDA(t, fdaClient)

	// No in-flight submissions — just run the poll
	srv.pollAllSubmissions(context.Background())

	assert.Equal(t, int64(0), fdaCalled.Load(), "should not call FDA when no submissions are in-flight")
}

func TestPollAllSubmissions_StateTransitions(t *testing.T) {
	// Mock FDA that returns PROCESSING on first call, ACCEPTED on second
	var callCount atomic.Int64
	fdaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/as/token.oauth2":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token", "token_type": "Bearer", "expires_in": 3600,
			})

		case strings.HasPrefix(r.URL.Path, "/api/esgng/v1/submissions/") && r.Method == http.MethodGet:
			n := callCount.Add(1)
			status := "PROCESSING"
			if n > 1 {
				status = "ACCEPTED"
			}
			coreID := strings.TrimPrefix(r.URL.Path, "/api/esgng/v1/submissions/")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"core_id": coreID, "status": status,
				"esgngcode": "ESGNG210", "esgngdescription": "ok",
				"acknowledgements": []map[string]string{},
			})

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL, UploadBaseURL: fdaServer.URL,
		ClientID: "id", ClientSecret: "secret", Environment: fdaclient.EnvTest,
	})
	srv := newTestServerWithFDA(t, fdaClient)
	suffix := fmt.Sprintf("poll-trans-%d", time.Now().UnixNano())
	orgID, userID := seedTestData(t, suffix)

	subID, _ := setupSubmittedSub(t, srv, orgID, userID, suffix)
	ctx := context.Background()

	// First poll: SUBMITTED → PROCESSING
	srv.pollAllSubmissions(ctx)
	sub, err := srv.submissions.GetByID(ctx, orgID, subID)
	require.NoError(t, err)
	assert.Equal(t, "submitted", sub.Status)
	assert.Equal(t, "PROCESSING", sub.WorkflowState)

	// Second poll: PROCESSING → ACCEPTED
	srv.pollAllSubmissions(ctx)
	sub, err = srv.submissions.GetByID(ctx, orgID, subID)
	require.NoError(t, err)
	assert.Equal(t, "completed", sub.Status)
	assert.Equal(t, "ACCEPTED", sub.WorkflowState)
}

func TestPollerStartStop(t *testing.T) {
	fdaServer := newMockFDAServerWithStatus(t, "PROCESSING")
	defer fdaServer.Close()

	fdaClient := fdaclient.New(fdaclient.Config{
		ExternalBaseURL: fdaServer.URL, UploadBaseURL: fdaServer.URL,
		ClientID: "id", ClientSecret: "secret", Environment: fdaclient.EnvTest,
	})
	srv := newTestServerWithFDA(t, fdaClient)

	ctx, cancel := context.WithCancel(context.Background())
	srv.pollerCancel = cancel
	srv.startStatusPoller(ctx, 50*time.Millisecond)

	// Let it run a couple ticks
	time.Sleep(200 * time.Millisecond)

	// Stop cleanly
	srv.stopStatusPoller()

	// Give goroutine time to exit
	time.Sleep(100 * time.Millisecond)

	// If we get here without deadlock or panic, the lifecycle is correct
}
