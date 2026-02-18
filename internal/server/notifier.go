package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// ValidNotificationEvents lists the event types users can subscribe to.
// This is a superset check — a subset of ValidWebhookEvents (no webhook.test).
var ValidNotificationEvents = map[string]bool{
	"submission.created":       true,
	"submission.submitted":     true,
	"submission.completed":     true,
	"submission.failed":        true,
	"acknowledgement.received": true,
}

// notifyEvent dispatches an event to both org-scoped webhooks and user-scoped
// notification preferences. All delivery is asynchronous and best-effort.
func (s *Server) notifyEvent(orgID string, event WebhookEvent) {
	// 1. Org-scoped webhooks (existing infrastructure)
	s.dispatchWebhooks(orgID, event)

	// 2. User-scoped notification preferences
	if s.notificationPrefs == nil {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		prefs, err := s.notificationPrefs.ListActiveByOrgAndEvent(ctx, orgID, event.Type)
		if err != nil {
			s.logger.Error("notifier: failed to list notification preferences", "org_id", orgID, "event", event.Type, "error", err)
			return
		}

		for _, pref := range prefs {
			switch pref.Channel {
			case "email":
				s.logger.Info("notifier: email notification (stub)", "user_id", pref.UserID, "event", event.Type)
			case "slack":
				s.logger.Info("notifier: slack notification (stub)", "user_id", pref.UserID, "event", event.Type)
			case "webhook":
				if !pref.WebhookURL.Valid || pref.WebhookURL.String == "" {
					s.logger.Warn("notifier: webhook preference missing URL", "user_id", pref.UserID)
					continue
				}
				secret := ""
				if pref.WebhookSecret.Valid {
					secret = pref.WebhookSecret.String
				}
				s.deliverUserWebhook(ctx, pref.UserID, pref.WebhookURL.String, secret, event)
			default:
				s.logger.Warn("notifier: unknown channel", "channel", pref.Channel, "user_id", pref.UserID)
			}
		}
	}()
}

// deliverUserWebhook sends a webhook event to a user's personal webhook URL.
// Reuses the same payload format and signing as org-scoped webhooks.
func (s *Server) deliverUserWebhook(ctx context.Context, userID, url, secret string, event WebhookEvent) {
	payload := webhookPayload{
		ID:        "evt_" + newUUID(),
		Type:      event.Type,
		CreatedAt: time.Now().UTC(),
		Data:      event.Data,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		s.logger.Error("notifier: failed to marshal payload", "user_id", userID, "error", err)
		return
	}

	signature := ""
	if secret != "" {
		signature = signPayload(body, secret)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	statusCode, _, err := sendWebhookRequest(ctx, client, url, body, signature)
	if err != nil {
		s.logger.Error("notifier: user webhook delivery failed", "user_id", userID, "url", url, "error", err)
		return
	}
	if statusCode < 200 || statusCode >= 300 {
		s.logger.Warn("notifier: user webhook non-2xx response", "user_id", userID, "url", url, "status_code", statusCode)
	}
}

// mapWorkflowToEvent maps a workflow state to a notification event type.
// Returns "" for states that don't generate notifications.
func mapWorkflowToEvent(workflowState string) string {
	switch workflowState {
	case "SUBMITTED":
		return "submission.submitted"
	case "COMPLETED":
		return "submission.completed"
	case "FAILED":
		return "submission.failed"
	default:
		return ""
	}
}
