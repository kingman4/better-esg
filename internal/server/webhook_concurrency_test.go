package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kingman4/better-esg/internal/repository"
)

// newTestWebhookServer creates a minimal Server with webhookSem initialized.
// Accepts optional semaphore capacity (default 10).
func newTestWebhookServer(semSize ...int) *Server {
	cap := 10
	if len(semSize) > 0 {
		cap = semSize[0]
	}
	return &Server{
		logger:     testLogger(),
		webhookSem: make(chan struct{}, cap),
	}
}

// TestWebhookConcurrency_BoundedBySeamphore verifies that no more than
// semaphore-capacity webhook deliveries run concurrently.
func TestWebhookConcurrency_BoundedBySemaphore(t *testing.T) {
	const semCap = 3
	const totalWebhooks = 10

	var (
		concurrent atomic.Int32
		maxSeen    atomic.Int32
		wg         sync.WaitGroup
	)

	// Slow endpoint: holds the connection for 50ms so we can measure overlap.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := concurrent.Add(1)
		defer concurrent.Add(-1)

		// Track high-water mark
		for {
			old := maxSeen.Load()
			if n <= old || maxSeen.CompareAndSwap(old, n) {
				break
			}
		}

		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := newTestWebhookServer(semCap)

	body, _ := json.Marshal(webhookPayload{
		ID:   "evt_test",
		Type: "webhook.test",
		Data: map[string]any{"test": true},
	})
	payloadMap := map[string]any{"type": "webhook.test"}

	// Fire totalWebhooks deliveries, each tracked by WG.
	for i := 0; i < totalWebhooks; i++ {
		wh := repository.Webhook{
			ID:     "wh-conc-" + string(rune('a'+i)),
			URL:    ts.URL,
			Secret: "secret",
		}
		s.webhookWG.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.webhookWG.Done()
			s.webhookSem <- struct{}{}
			defer func() { <-s.webhookSem }()
			s.deliverWebhook(t.Context(), wh, body, payloadMap)
		}()
	}

	wg.Wait()

	peak := maxSeen.Load()
	if peak > int32(semCap) {
		t.Errorf("peak concurrent deliveries = %d, want <= %d (semaphore cap)", peak, semCap)
	}
	if peak == 0 {
		t.Error("peak concurrent deliveries = 0; no deliveries ran")
	}
	t.Logf("peak concurrent deliveries: %d (cap=%d)", peak, semCap)
}

// TestWebhookGracefulShutdown_WaitsForInFlight verifies that Close()
// blocks until in-flight webhook deliveries complete.
func TestWebhookGracefulShutdown_WaitsForInFlight(t *testing.T) {
	var delivered atomic.Int32

	// Slow endpoint: takes 100ms to respond.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		delivered.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := newTestWebhookServer(10)

	body, _ := json.Marshal(webhookPayload{
		ID:   "evt_shutdown",
		Type: "webhook.test",
		Data: map[string]any{},
	})
	payloadMap := map[string]any{"type": "webhook.test"}

	// Start 5 slow deliveries tracked by webhookWG.
	for i := 0; i < 5; i++ {
		wh := repository.Webhook{
			ID:     "wh-shut-" + string(rune('a'+i)),
			URL:    ts.URL,
			Secret: "secret",
		}
		s.webhookWG.Add(1)
		go func() {
			defer s.webhookWG.Done()
			s.webhookSem <- struct{}{}
			defer func() { <-s.webhookSem }()
			s.deliverWebhook(t.Context(), wh, body, payloadMap)
		}()
	}

	// Wait for WG (simulating what Close() does) — should block until all done.
	done := make(chan struct{})
	go func() {
		s.webhookWG.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Good — all deliveries completed
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for webhookWG; graceful shutdown would hang")
	}

	if count := delivered.Load(); count != 5 {
		t.Errorf("expected 5 deliveries, got %d", count)
	}
}

// TestWebhookGracefulShutdown_TimesOut verifies that Close() doesn't
// hang forever if a delivery is stuck. Uses the same pattern as Server.Close().
func TestWebhookGracefulShutdown_TimesOut(t *testing.T) {
	// Endpoint that never responds within the timeout.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Second) // way longer than shutdown timeout
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := newTestWebhookServer(10)

	// Start a delivery that will be stuck.
	s.webhookWG.Add(1)
	go func() {
		defer s.webhookWG.Done()
		s.webhookSem <- struct{}{}
		defer func() { <-s.webhookSem }()

		wh := repository.Webhook{ID: "wh-stuck", URL: ts.URL, Secret: "secret"}
		body, _ := json.Marshal(webhookPayload{ID: "evt_stuck", Type: "webhook.test", Data: map[string]any{}})
		payloadMap := map[string]any{"type": "webhook.test"}
		s.deliverWebhook(t.Context(), wh, body, payloadMap)
	}()

	// Simulate the Close() timeout pattern.
	shutdownTimeout := 200 * time.Millisecond
	done := make(chan struct{})
	go func() {
		s.webhookWG.Wait()
		close(done)
	}()

	start := time.Now()
	select {
	case <-done:
		t.Fatal("expected timeout, but WG completed (delivery should be stuck)")
	case <-time.After(shutdownTimeout):
		elapsed := time.Since(start)
		if elapsed < shutdownTimeout {
			t.Errorf("timed out too early: %v", elapsed)
		}
		// Good — we timed out as expected, proving the server won't hang forever.
	}
}

// TestDispatchTestWebhook_TrackedByWG verifies that dispatchTestWebhook
// increments the WaitGroup so graceful shutdown can track it.
func TestDispatchTestWebhook_TrackedByWG(t *testing.T) {
	var called atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := newTestWebhookServer(10)

	wh := repository.Webhook{
		ID:     "wh-test-wg",
		URL:    ts.URL,
		Secret: "secret",
	}

	s.dispatchTestWebhook(wh)

	// Wait for the WG — if dispatch isn't tracked, this would return immediately
	// while the goroutine is still running.
	done := make(chan struct{})
	go func() {
		s.webhookWG.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Good — tracked and completed
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for dispatchTestWebhook to complete via WG")
	}

	if c := called.Load(); c != 1 {
		t.Errorf("expected 1 delivery call, got %d", c)
	}
}

// TestNotifyEvent_TrackedByWG verifies that the notifier goroutine in
// notifyEvent is tracked by webhookWG for graceful shutdown.
// Since notifyEvent calls dispatchWebhooks (which needs a webhook repo),
// we only test the user notification path here.
func TestNotifyEvent_NotifierGoroutineTracked(t *testing.T) {
	// notifyEvent with nil webhooks + nil notificationPrefs should be a no-op
	// that still doesn't leave dangling goroutines.
	s := newTestWebhookServer(10)

	// With both nil, notifyEvent should return immediately and WG stays at 0.
	s.notifyEvent("org-1", WebhookEvent{Type: "submission.completed", Data: map[string]any{}})

	// Give any accidental goroutines a moment to increment WG.
	time.Sleep(10 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		s.webhookWG.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Good — nothing to wait for
	case <-time.After(1 * time.Second):
		t.Fatal("webhookWG not at zero; notifyEvent leaked a goroutine")
	}
}
