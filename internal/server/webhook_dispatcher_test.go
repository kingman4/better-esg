package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kingman4/better-esg/internal/repository"
)

func TestSignPayload(t *testing.T) {
	body := []byte(`{"id":"evt_abc","type":"submission.completed","data":{}}`)
	secret := "whsec_testsecret123"

	sig := signPayload(body, secret)

	// Verify independently
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(body)
	expected := hex.EncodeToString(h.Sum(nil))

	if sig != expected {
		t.Errorf("signPayload mismatch: got %s, want %s", sig, expected)
	}
}

func TestSignPayload_DifferentSecrets(t *testing.T) {
	body := []byte(`{"test": true}`)
	sig1 := signPayload(body, "secret-a")
	sig2 := signPayload(body, "secret-b")

	if sig1 == sig2 {
		t.Error("different secrets produced identical signatures")
	}
}

func TestSendWebhookRequest_Headers(t *testing.T) {
	var receivedHeaders http.Header
	var receivedBody []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	body := []byte(`{"id":"evt_test123","type":"webhook.test","data":{}}`)
	signature := signPayload(body, "test-secret")

	client := &http.Client{Timeout: 5 * time.Second}
	statusCode, respBody, err := sendWebhookRequest(t.Context(), client, ts.URL, body, signature)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if statusCode != 200 {
		t.Errorf("expected status 200, got %d", statusCode)
	}
	if respBody != `{"ok":true}` {
		t.Errorf("unexpected response body: %s", respBody)
	}

	// Check headers
	if ct := receivedHeaders.Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got %q", ct)
	}
	if sig := receivedHeaders.Get("X-Webhook-Signature"); sig != "sha256="+signature {
		t.Errorf("expected X-Webhook-Signature 'sha256=%s', got %q", signature, sig)
	}
	if ts := receivedHeaders.Get("X-Webhook-Timestamp"); ts == "" {
		t.Error("expected X-Webhook-Timestamp header to be set")
	}
	if wid := receivedHeaders.Get("X-Webhook-ID"); wid == "" {
		t.Error("expected X-Webhook-ID header to be set")
	}

	// Verify body is passed through
	if string(receivedBody) != string(body) {
		t.Errorf("body mismatch: got %q, want %q", receivedBody, body)
	}
}

func TestDeliverWebhook_Success(t *testing.T) {
	var callCount atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := &Server{} // no deliveries repo — logging is skipped
	wh := repository.Webhook{
		ID:     "wh-1",
		URL:    ts.URL,
		Secret: "test-secret",
	}

	body, _ := json.Marshal(webhookPayload{
		ID:   "evt_test",
		Type: "webhook.test",
		Data: map[string]any{"test": true},
	})
	payloadMap := map[string]any{"type": "webhook.test"}

	s.deliverWebhook(t.Context(), wh, body, payloadMap)

	if count := callCount.Load(); count != 1 {
		t.Errorf("expected 1 call, got %d", count)
	}
}

func TestDeliverWebhook_RetriesOnServerError(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow retry test")
	}
	var callCount atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := &Server{}
	wh := repository.Webhook{
		ID:     "wh-retry",
		URL:    ts.URL,
		Secret: "retry-secret",
	}

	body, _ := json.Marshal(webhookPayload{
		ID:   "evt_retry",
		Type: "submission.completed",
		Data: map[string]any{},
	})
	payloadMap := map[string]any{"type": "submission.completed"}

	s.deliverWebhook(t.Context(), wh, body, payloadMap)

	if count := callCount.Load(); count != 3 {
		t.Errorf("expected 3 attempts (2 failures + 1 success), got %d", count)
	}
}

func TestDeliverWebhook_StopsOn4xx(t *testing.T) {
	var callCount atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusBadRequest) // 400 — should not retry
	}))
	defer ts.Close()

	s := &Server{}
	wh := repository.Webhook{
		ID:     "wh-4xx",
		URL:    ts.URL,
		Secret: "secret",
	}

	body, _ := json.Marshal(webhookPayload{
		ID:   "evt_4xx",
		Type: "submission.failed",
		Data: map[string]any{},
	})
	payloadMap := map[string]any{"type": "submission.failed"}

	s.deliverWebhook(t.Context(), wh, body, payloadMap)

	if count := callCount.Load(); count != 1 {
		t.Errorf("expected 1 attempt (no retry on 4xx), got %d", count)
	}
}

func TestDeliverWebhook_ExhaustsRetries(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow retry test")
	}
	var callCount atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable) // 503 — always fail
	}))
	defer ts.Close()

	s := &Server{}
	wh := repository.Webhook{
		ID:     "wh-exhaust",
		URL:    ts.URL,
		Secret: "secret",
	}

	body, _ := json.Marshal(webhookPayload{
		ID:   "evt_exhaust",
		Type: "submission.completed",
		Data: map[string]any{},
	})
	payloadMap := map[string]any{"type": "submission.completed"}

	s.deliverWebhook(t.Context(), wh, body, payloadMap)

	if count := callCount.Load(); count != 3 {
		t.Errorf("expected 3 attempts (all failed), got %d", count)
	}
}

func TestNewUUID_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := newUUID()
		if seen[id] {
			t.Fatalf("duplicate UUID: %s", id)
		}
		seen[id] = true
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		input string
		n     int
		want  string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is longer", 10, "this is lo"},
		{"", 5, ""},
	}
	for _, tt := range tests {
		got := truncateString(tt.input, tt.n)
		if got != tt.want {
			t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.n, got, tt.want)
		}
	}
}

func TestValidWebhookEvents(t *testing.T) {
	expected := []string{
		"submission.created",
		"submission.submitted",
		"submission.completed",
		"submission.failed",
		"acknowledgement.received",
		"webhook.test",
	}
	for _, e := range expected {
		if !ValidWebhookEvents[e] {
			t.Errorf("expected %q to be a valid event type", e)
		}
	}
	if ValidWebhookEvents["nonexistent.event"] {
		t.Error("nonexistent.event should not be valid")
	}
}
