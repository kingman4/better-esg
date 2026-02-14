package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/kingman4/better-esg/internal/repository"
)

// WebhookEvent describes an event to dispatch to registered webhooks.
type WebhookEvent struct {
	Type string         // e.g. "submission.completed"
	Data map[string]any // event-specific payload data
}

// ValidWebhookEvents lists the event types webhooks can subscribe to.
var ValidWebhookEvents = map[string]bool{
	"submission.created":       true,
	"submission.submitted":     true,
	"submission.completed":     true,
	"submission.failed":        true,
	"acknowledgement.received": true,
	"webhook.test":             true, // synthetic test event
}

// webhookPayload is the JSON body sent to external webhook URLs.
type webhookPayload struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	CreatedAt time.Time      `json:"created_at"`
	Data      map[string]any `json:"data"`
}

// dispatchWebhooks finds all active webhooks for the org + event type,
// then delivers the payload asynchronously. Never blocks the caller.
func (s *Server) dispatchWebhooks(orgID string, event WebhookEvent) {
	if s.webhooks == nil {
		return // webhooks not configured
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		webhooks, err := s.webhooks.ListActiveForEvent(ctx, orgID, event.Type)
		if err != nil {
			log.Printf("webhook: failed to list webhooks for org %s event %s: %v", orgID, event.Type, err)
			return
		}
		if len(webhooks) == 0 {
			return
		}

		payload := webhookPayload{
			ID:        fmt.Sprintf("evt_%s", newUUID()),
			Type:      event.Type,
			CreatedAt: time.Now().UTC(),
			Data:      event.Data,
		}

		body, err := json.Marshal(payload)
		if err != nil {
			log.Printf("webhook: failed to marshal payload: %v", err)
			return
		}

		payloadMap := map[string]any{
			"id":         payload.ID,
			"type":       payload.Type,
			"created_at": payload.CreatedAt,
			"data":       payload.Data,
		}

		for i := range webhooks {
			wh := webhooks[i]
			go s.deliverWebhook(ctx, wh, body, payloadMap)
		}
	}()
}

// deliverWebhook sends the payload to a single webhook with retry.
// Retries up to 3 times with exponential backoff (2s, 4s, 8s).
func (s *Server) deliverWebhook(ctx context.Context, wh repository.Webhook, body []byte, payloadMap map[string]any) {
	const maxAttempts = 3
	delays := []time.Duration{0, 2 * time.Second, 4 * time.Second}

	signature := signPayload(body, wh.Secret)
	client := &http.Client{Timeout: 5 * time.Second}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(delays[attempt-1]):
			}
		}

		statusCode, respBody, err := sendWebhookRequest(ctx, client, wh.URL, body, signature)

		delivered := err == nil && statusCode >= 200 && statusCode < 300
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		} else if !delivered {
			errMsg = fmt.Sprintf("HTTP %d", statusCode)
		}

		// Log the attempt (best-effort — don't fail the delivery loop on log errors)
		if s.deliveries != nil {
			if logErr := s.deliveries.LogDelivery(ctx, repository.LogDeliveryParams{
				WebhookID:    wh.ID,
				EventType:    payloadMap["type"].(string),
				Payload:      payloadMap,
				StatusCode:   statusCode,
				ResponseBody: truncateString(respBody, 1024),
				Error:        errMsg,
				Attempt:      attempt,
				Delivered:    delivered,
			}); logErr != nil {
				log.Printf("webhook: failed to log delivery for webhook %s: %v", wh.ID, logErr)
			}
		}

		if delivered {
			return
		}

		// Don't retry on 4xx (client error) — it won't help
		if statusCode >= 400 && statusCode < 500 {
			log.Printf("webhook: permanent failure for %s → %s: HTTP %d", wh.ID, wh.URL, statusCode)
			return
		}

		log.Printf("webhook: attempt %d/%d failed for %s → %s: %s", attempt, maxAttempts, wh.ID, wh.URL, errMsg)
	}

	log.Printf("webhook: exhausted retries for %s → %s", wh.ID, wh.URL)
}

// sendWebhookRequest sends a signed POST to the webhook URL.
// Returns (statusCode, responseBody, error). statusCode is 0 on network error.
func sendWebhookRequest(ctx context.Context, client *http.Client, url string, body []byte, signature string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Signature", "sha256="+signature)
	// Parse the event ID from the payload for the header
	var p struct{ ID string `json:"id"` }
	json.Unmarshal(body, &p)
	req.Header.Set("X-Webhook-ID", p.ID)
	req.Header.Set("X-Webhook-Timestamp", time.Now().UTC().Format(time.RFC3339))

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return resp.StatusCode, string(respBytes), nil
}

// dispatchTestWebhook sends a synthetic test event directly to a single webhook.
// Unlike dispatchWebhooks, this bypasses event type matching.
func (s *Server) dispatchTestWebhook(wh repository.Webhook) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		payload := webhookPayload{
			ID:        fmt.Sprintf("evt_%s", newUUID()),
			Type:      "webhook.test",
			CreatedAt: time.Now().UTC(),
			Data: map[string]any{
				"webhook_id": wh.ID,
				"message":    "This is a test webhook delivery.",
			},
		}

		body, err := json.Marshal(payload)
		if err != nil {
			log.Printf("webhook: failed to marshal test payload: %v", err)
			return
		}

		payloadMap := map[string]any{
			"id":         payload.ID,
			"type":       payload.Type,
			"created_at": payload.CreatedAt,
			"data":       payload.Data,
		}

		s.deliverWebhook(ctx, wh, body, payloadMap)
	}()
}

// signPayload computes HMAC-SHA256 of the body using the webhook secret.
func signPayload(body []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// newUUID generates a random UUID v4 without external dependencies.
func newUUID() string {
	b := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, b)
	// Set version 4 and variant bits
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// truncateString returns at most n bytes of s.
func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
