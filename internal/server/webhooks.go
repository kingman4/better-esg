package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/kingman4/better-esg/internal/repository"
)

// --- Request/Response types ---

type createWebhookRequest struct {
	URL         string   `json:"url"`
	Secret      string   `json:"secret,omitempty"` // auto-generated if empty
	Events      []string `json:"events"`
	Description string   `json:"description,omitempty"`
}

type webhookResponse struct {
	ID          string   `json:"id"`
	OrgID       string   `json:"org_id"`
	URL         string   `json:"url"`
	Secret      string   `json:"secret"` // masked
	Events      []string `json:"events"`
	IsActive    bool     `json:"is_active"`
	Description *string  `json:"description,omitempty"`
	CreatedBy   string   `json:"created_by"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

func toWebhookResponse(w *repository.Webhook, showSecret bool) any {
	var desc *string
	if w.Description.Valid {
		desc = &w.Description.String
	}
	secret := w.Secret
	if !showSecret {
		// Show only first 8 chars
		if len(secret) > 8 {
			secret = secret[:8] + "..."
		}
	}
	return webhookResponse{
		ID:          w.ID,
		OrgID:       w.OrgID,
		URL:         w.URL,
		Secret:      secret,
		Events:      w.Events,
		IsActive:    w.IsActive,
		Description: desc,
		CreatedBy:   w.CreatedBy,
		CreatedAt:   w.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   w.UpdatedAt.Format(time.RFC3339),
	}
}

// --- Handlers ---

func (s *Server) handleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	orgID := orgIDFromContext(r.Context())
	userID := userIDFromContext(r.Context())

	var req createWebhookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url is required"})
		return
	}
	if len(req.Events) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "events is required (at least one event type)"})
		return
	}

	// Validate event types
	for _, e := range req.Events {
		if !ValidWebhookEvents[e] || e == "webhook.test" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid event type: " + e,
			})
			return
		}
	}

	// Auto-generate secret if not provided
	secret := req.Secret
	if secret == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Printf("error generating webhook secret: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate secret"})
			return
		}
		secret = "whsec_" + hex.EncodeToString(b)
	}

	wh, err := s.webhooks.Create(r.Context(), repository.CreateWebhookParams{
		OrgID:       orgID,
		URL:         req.URL,
		Secret:      secret,
		Events:      req.Events,
		Description: req.Description,
		CreatedBy:   userID,
	})
	if err != nil {
		log.Printf("error creating webhook: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create webhook"})
		return
	}

	// Show full secret only on create
	writeJSON(w, http.StatusCreated, toWebhookResponse(wh, true))
}

func (s *Server) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	orgID := orgIDFromContext(r.Context())

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	offset := 0
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	webhooks, err := s.webhooks.ListByOrg(r.Context(), orgID, limit, offset)
	if err != nil {
		log.Printf("error listing webhooks: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list webhooks"})
		return
	}

	results := make([]any, 0, len(webhooks))
	for i := range webhooks {
		results = append(results, toWebhookResponse(&webhooks[i], false))
	}

	writeJSON(w, http.StatusOK, results)
}

func (s *Server) handleGetWebhook(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing webhook id"})
		return
	}

	orgID := orgIDFromContext(r.Context())
	wh, err := s.webhooks.GetByID(r.Context(), orgID, id)
	if err != nil {
		log.Printf("error getting webhook: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get webhook"})
		return
	}
	if wh == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "webhook not found"})
		return
	}

	writeJSON(w, http.StatusOK, toWebhookResponse(wh, false))
}

func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing webhook id"})
		return
	}

	orgID := orgIDFromContext(r.Context())
	if err := s.webhooks.Delete(r.Context(), orgID, id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "webhook not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing webhook id"})
		return
	}

	orgID := orgIDFromContext(r.Context())
	wh, err := s.webhooks.GetByID(r.Context(), orgID, id)
	if err != nil {
		log.Printf("error getting webhook for test: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get webhook"})
		return
	}
	if wh == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "webhook not found"})
		return
	}

	// Deliver directly to this specific webhook (bypass event matching)
	s.dispatchTestWebhook(*wh)

	writeJSON(w, http.StatusOK, map[string]string{"status": "test event dispatched"})
}
