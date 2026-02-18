package server

import (
	"encoding/json"
	"net/http"

	"github.com/kingman4/better-esg/internal/repository"
)

// --- Request/Response types ---

type createNotifPrefRequest struct {
	Channel       string   `json:"channel"`
	Events        []string `json:"events"`
	WebhookURL    string   `json:"webhook_url,omitempty"`
	WebhookSecret string   `json:"webhook_secret,omitempty"`
	IsActive      *bool    `json:"is_active,omitempty"`
}

type updateNotifPrefRequest struct {
	Events        *[]string `json:"events,omitempty"`
	WebhookURL    *string   `json:"webhook_url,omitempty"`
	WebhookSecret *string   `json:"webhook_secret,omitempty"`
	IsActive      *bool     `json:"is_active,omitempty"`
}

type notifPrefResponse struct {
	ID            string   `json:"id"`
	UserID        string   `json:"user_id"`
	Channel       string   `json:"channel"`
	Events        []string `json:"events"`
	WebhookURL    *string  `json:"webhook_url,omitempty"`
	WebhookSecret *string  `json:"webhook_secret,omitempty"`
	IsActive      bool     `json:"is_active"`
	CreatedAt     string   `json:"created_at"`
	UpdatedAt     string   `json:"updated_at"`
}

func toNotifPrefResponse(np *repository.NotificationPreference) notifPrefResponse {
	resp := notifPrefResponse{
		ID:        np.ID,
		UserID:    np.UserID,
		Channel:   np.Channel,
		Events:    np.Events,
		IsActive:  np.IsActive,
		CreatedAt: np.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt: np.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
	if np.WebhookURL.Valid {
		resp.WebhookURL = &np.WebhookURL.String
	}
	// Never expose the full secret — omit from responses
	return resp
}

// validChannels lists the allowed notification channels.
var validChannels = map[string]bool{
	"email":   true,
	"slack":   true,
	"webhook": true,
}

// --- Handlers ---

// handleCreateNotificationPref handles POST /api/v1/notifications/preferences.
// Users manage their own preferences; the user_id comes from auth context.
func (s *Server) handleCreateNotificationPref(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	var req createNotifPrefRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if !validChannels[req.Channel] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "channel must be one of: email, slack, webhook"})
		return
	}

	if len(req.Events) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one event is required"})
		return
	}

	for _, evt := range req.Events {
		if !ValidNotificationEvents[evt] {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid event type: " + evt})
			return
		}
	}

	if req.Channel == "webhook" && req.WebhookURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "webhook_url is required for webhook channel"})
		return
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	np, err := s.notificationPrefs.Create(r.Context(), repository.CreateNotificationPrefParams{
		UserID:        userID,
		Channel:       req.Channel,
		Events:        req.Events,
		WebhookURL:    req.WebhookURL,
		WebhookSecret: req.WebhookSecret,
		IsActive:      isActive,
	})
	if err != nil {
		s.logger.Error("failed to create notification preference", "user_id", userID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create notification preference"})
		return
	}

	s.audit(r, "create_notification_pref", "notification_preference", np.ID, map[string]any{
		"channel": req.Channel,
		"events":  req.Events,
	})

	writeJSON(w, http.StatusCreated, toNotifPrefResponse(np))
}

// handleListNotificationPrefs handles GET /api/v1/notifications/preferences.
func (s *Server) handleListNotificationPrefs(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	prefs, err := s.notificationPrefs.ListByUser(r.Context(), userID)
	if err != nil {
		s.logger.Error("failed to list notification preferences", "user_id", userID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list notification preferences"})
		return
	}

	resp := make([]notifPrefResponse, len(prefs))
	for i := range prefs {
		resp[i] = toNotifPrefResponse(&prefs[i])
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleGetNotificationPref handles GET /api/v1/notifications/preferences/{channel}.
func (s *Server) handleGetNotificationPref(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	channel := r.PathValue("channel")

	if !validChannels[channel] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid channel"})
		return
	}

	np, err := s.notificationPrefs.GetByUserAndChannel(r.Context(), userID, channel)
	if err != nil {
		s.logger.Error("failed to get notification preference", "user_id", userID, "channel", channel, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get notification preference"})
		return
	}
	if np == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "notification preference not found"})
		return
	}

	writeJSON(w, http.StatusOK, toNotifPrefResponse(np))
}

// handleUpdateNotificationPref handles PATCH /api/v1/notifications/preferences/{channel}.
func (s *Server) handleUpdateNotificationPref(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	channel := r.PathValue("channel")

	if !validChannels[channel] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid channel"})
		return
	}

	var req updateNotifPrefRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	// Validate events if provided
	if req.Events != nil {
		if len(*req.Events) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "at least one event is required"})
			return
		}
		for _, evt := range *req.Events {
			if !ValidNotificationEvents[evt] {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid event type: " + evt})
				return
			}
		}
	}

	np, err := s.notificationPrefs.Update(r.Context(), userID, channel, repository.UpdateNotificationPrefParams{
		Events:        req.Events,
		WebhookURL:    req.WebhookURL,
		WebhookSecret: req.WebhookSecret,
		IsActive:      req.IsActive,
	})
	if err != nil {
		s.logger.Error("failed to update notification preference", "user_id", userID, "channel", channel, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update notification preference"})
		return
	}
	if np == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "notification preference not found"})
		return
	}

	s.audit(r, "update_notification_pref", "notification_preference", np.ID, nil)

	writeJSON(w, http.StatusOK, toNotifPrefResponse(np))
}

// handleDeleteNotificationPref handles DELETE /api/v1/notifications/preferences/{channel}.
func (s *Server) handleDeleteNotificationPref(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	channel := r.PathValue("channel")

	if !validChannels[channel] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid channel"})
		return
	}

	if err := s.notificationPrefs.Delete(r.Context(), userID, channel); err != nil {
		s.logger.Error("failed to delete notification preference", "user_id", userID, "channel", channel, "error", err)
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "notification preference not found"})
		return
	}

	s.audit(r, "delete_notification_pref", "notification_preference", "", map[string]any{
		"channel": channel,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
