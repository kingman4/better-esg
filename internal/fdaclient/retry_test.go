package fdaclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- retryDo unit tests ---

func TestRetryDo_SucceedsFirstAttempt(t *testing.T) {
	var calls int
	err := retryDo(context.Background(), retryDefault, func() error {
		calls++
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, 1, calls)
}

func TestRetryDo_SucceedsAfterTransientFailures(t *testing.T) {
	var calls int
	err := retryDo(context.Background(), retryConfig{maxAttempts: 3, baseDelay: 1 * time.Millisecond, maxDelay: 10 * time.Millisecond}, func() error {
		calls++
		if calls < 3 {
			return &retryableError{err: fmt.Errorf("transient")}
		}
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, 3, calls)
}

func TestRetryDo_StopsOnPermanentError(t *testing.T) {
	var calls int
	err := retryDo(context.Background(), retryConfig{maxAttempts: 5, baseDelay: 1 * time.Millisecond, maxDelay: 10 * time.Millisecond}, func() error {
		calls++
		return &permanentError{err: fmt.Errorf("bad request")}
	})
	assert.Error(t, err)
	assert.Equal(t, 1, calls, "should stop after first permanent error")
	assert.Contains(t, err.Error(), "bad request")
}

func TestRetryDo_ExhaustsAttempts(t *testing.T) {
	var calls int
	err := retryDo(context.Background(), retryConfig{maxAttempts: 3, baseDelay: 1 * time.Millisecond, maxDelay: 10 * time.Millisecond}, func() error {
		calls++
		return &retryableError{err: fmt.Errorf("still failing")}
	})
	assert.Error(t, err)
	assert.Equal(t, 3, calls)
	assert.Contains(t, err.Error(), "after 3 attempts")
}

func TestRetryDo_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var calls int
	err := retryDo(ctx, retryConfig{maxAttempts: 10, baseDelay: 50 * time.Millisecond, maxDelay: 200 * time.Millisecond}, func() error {
		calls++
		if calls == 2 {
			cancel()
		}
		return &retryableError{err: fmt.Errorf("failing")}
	})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "should return context error")
}

func TestRetryDo_PlainErrorIsRetryable(t *testing.T) {
	var calls int
	err := retryDo(context.Background(), retryConfig{maxAttempts: 3, baseDelay: 1 * time.Millisecond, maxDelay: 10 * time.Millisecond}, func() error {
		calls++
		if calls < 3 {
			return fmt.Errorf("network error")
		}
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, 3, calls, "plain errors should be retried")
}

// --- isRetryable tests ---

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		statusCode int
		want       bool
	}{
		{200, false},
		{400, false},
		{401, false},
		{403, false},
		{404, false},
		{413, false},
		{429, true},
		{500, true},
		{502, true},
		{503, true},
		{504, true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("status_%d", tt.statusCode), func(t *testing.T) {
			assert.Equal(t, tt.want, isRetryable(tt.statusCode))
		})
	}
}

// --- backoffDelay tests ---

func TestBackoffDelay_Exponential(t *testing.T) {
	cfg := retryConfig{baseDelay: 2 * time.Second, maxDelay: 8 * time.Second}
	assert.Equal(t, 2*time.Second, backoffDelay(cfg, 0))
	assert.Equal(t, 4*time.Second, backoffDelay(cfg, 1))
	assert.Equal(t, 8*time.Second, backoffDelay(cfg, 2))
	assert.Equal(t, 8*time.Second, backoffDelay(cfg, 3), "should cap at maxDelay")
}

func TestBackoffDelay_Linear(t *testing.T) {
	cfg := retryConfig{baseDelay: 5 * time.Second, maxDelay: 25 * time.Second, linear: true}
	assert.Equal(t, 5*time.Second, backoffDelay(cfg, 0))
	assert.Equal(t, 10*time.Second, backoffDelay(cfg, 1))
	assert.Equal(t, 15*time.Second, backoffDelay(cfg, 2))
	assert.Equal(t, 20*time.Second, backoffDelay(cfg, 3))
	assert.Equal(t, 25*time.Second, backoffDelay(cfg, 4))
	assert.Equal(t, 25*time.Second, backoffDelay(cfg, 5), "should cap at maxDelay")
}

// --- FDA client integration with retry ---

func TestGetPayload_RetriesOn503(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/as/token.oauth2":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token", "token_type": "Bearer", "expires_in": 3600,
			})
		case r.URL.Path == "/rest/forms/v1/fileupload/payload":
			n := calls.Add(1)
			if n <= 2 {
				http.Error(w, "service unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"payloadId": "PL-123",
				"links":     map[string]string{"uploadLink": "/upload", "submitLink": "/submit"},
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// Use fast retry for tests
	origDefault := retryDefault
	retryDefault = retryConfig{maxAttempts: 3, baseDelay: 1 * time.Millisecond, maxDelay: 5 * time.Millisecond}
	defer func() { retryDefault = origDefault }()

	client := New(Config{
		ExternalBaseURL: srv.URL,
		UploadBaseURL:   srv.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	result, err := client.GetPayload(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "PL-123", result.PayloadID)
	assert.Equal(t, int64(3), calls.Load(), "should have made 3 calls (2 retries + 1 success)")
}

func TestSubmitCredentials_NoRetryOn400(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/as/token.oauth2":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token", "token_type": "Bearer", "expires_in": 3600,
			})
		case r.URL.Path == "/api/esgng/v1/credentials/api/test":
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"esgngcode": "ESGNG400", "esgngdescription": "invalid data",
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	origDefault := retryDefault
	retryDefault = retryConfig{maxAttempts: 3, baseDelay: 1 * time.Millisecond, maxDelay: 5 * time.Millisecond}
	defer func() { retryDefault = origDefault }()

	client := New(Config{
		ExternalBaseURL: srv.URL,
		UploadBaseURL:   srv.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	_, err := client.SubmitCredentials(context.Background(), CredentialRequest{
		UserID: "test@test.com", FDACenter: "CDER", CompanyID: "C1",
		SubmissionType: "ANDA", SubmissionProtocol: "API", FileCount: 1,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "400")
	assert.Equal(t, int64(1), calls.Load(), "should NOT retry on 400")
}

func TestFetchToken_RetriesOn503(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n <= 2 {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "recovered-token", "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	defer srv.Close()

	origToken := retryToken
	retryToken = retryConfig{maxAttempts: 4, baseDelay: 1 * time.Millisecond, maxDelay: 5 * time.Millisecond}
	defer func() { retryToken = origToken }()

	client := New(Config{
		ExternalBaseURL: srv.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	token, err := client.GetToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "recovered-token", token)
	assert.Equal(t, int64(3), calls.Load())
}

func TestGetSubmissionStatus_RetriesNetworkError(t *testing.T) {
	var calls atomic.Int64

	// Server that works on third call
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/as/token.oauth2":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-token", "token_type": "Bearer", "expires_in": 3600,
			})
		case r.URL.Path == "/api/esgng/v1/submissions/CORE-1":
			n := calls.Add(1)
			if n <= 1 {
				// Force a broken response to simulate transient error
				http.Error(w, "gateway timeout", http.StatusGatewayTimeout)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"core_id": "CORE-1", "status": "ACCEPTED",
				"esgngcode": "ESGNG210", "esgngdescription": "ok",
				"acknowledgements": []any{},
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	origDefault := retryDefault
	retryDefault = retryConfig{maxAttempts: 3, baseDelay: 1 * time.Millisecond, maxDelay: 5 * time.Millisecond}
	defer func() { retryDefault = origDefault }()

	client := New(Config{
		ExternalBaseURL: srv.URL,
		UploadBaseURL:   srv.URL,
		ClientID:        "id",
		ClientSecret:    "secret",
		Environment:     EnvTest,
	})

	result, err := client.GetSubmissionStatus(context.Background(), "CORE-1")
	require.NoError(t, err)
	assert.Equal(t, "ACCEPTED", result.Status)
	assert.Equal(t, int64(2), calls.Load())
}
