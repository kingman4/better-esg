package server

import (
	"encoding/json"
	"log"
	"net/http"
)

// statusResponse is the JSON response for GET /api/v1/submissions/{id}/status.
type statusResponse struct {
	SubmissionID     string                    `json:"submission_id"`
	CoreID           string                    `json:"core_id"`
	FDAStatus        string                    `json:"fda_status"`
	LocalStatus      string                    `json:"local_status"`
	WorkflowState    string                    `json:"workflow_state"`
	Acknowledgements []acknowledgementResponse `json:"acknowledgements"`
}

// acknowledgementResponse is a single acknowledgement with full details.
type acknowledgementResponse struct {
	AcknowledgementID string         `json:"acknowledgement_id"`
	Type              string         `json:"type"`
	RawMessage        string         `json:"raw_message,omitempty"`
	ParsedData        map[string]any `json:"parsed_data,omitempty"`
}

// handleGetStatus handles GET /api/v1/submissions/{id}/status.
// Polls the FDA for the current submission status and fetches any acknowledgements.
// Updates the local DB status to reflect what FDA reports.
func (s *Server) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing submission id"})
		return
	}

	orgID := orgIDFromContext(r.Context())

	sub, err := s.submissions.GetByID(r.Context(), orgID, id)
	if err != nil {
		log.Printf("error getting submission %s: %v", id, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get submission"})
		return
	}
	if sub == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "submission not found"})
		return
	}

	if !sub.CoreID.Valid {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "submission has no core_id — submit to FDA first",
		})
		return
	}

	// Poll FDA for current status
	fdaStatus, err := s.fda.GetSubmissionStatus(r.Context(), sub.CoreID.String)
	if err != nil {
		log.Printf("FDA status check failed for %s (core_id=%s): %v", id, sub.CoreID.String, err)
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": "FDA status check failed: " + sanitizeError(err),
		})
		return
	}

	// Fetch full details for each acknowledgement
	acks := make([]acknowledgementResponse, 0, len(fdaStatus.Acknowledgements))
	for _, ref := range fdaStatus.Acknowledgements {
		ack, err := s.fda.GetAcknowledgement(r.Context(), ref.AcknowledgementID)
		if err != nil {
			log.Printf("error fetching acknowledgement %s for submission %s: %v",
				ref.AcknowledgementID, id, err)
			// Include partial info rather than failing the whole request
			acks = append(acks, acknowledgementResponse{
				AcknowledgementID: ref.AcknowledgementID,
				Type:              ref.Type,
			})
			continue
		}
		acks = append(acks, acknowledgementResponse{
			AcknowledgementID: ack.AcknowledgementID,
			Type:              ack.Type,
			RawMessage:        ack.RawMessage,
			ParsedData:        ack.ParsedData,
		})
	}

	// Map FDA status to local status + workflow state
	localStatus, workflowState := mapFDAStatus(fdaStatus.Status)

	// Update local DB if status changed
	if sub.Status != localStatus || sub.WorkflowState != workflowState {
		userID := userIDFromContext(r.Context())
		if err := s.transitionState(r.Context(), id, sub.WorkflowState, localStatus, workflowState, &userID, ""); err != nil {
			log.Printf("error updating local status for %s: %v", id, err)
		}
	}

	writeJSON(w, http.StatusOK, statusResponse{
		SubmissionID:     id,
		CoreID:           sub.CoreID.String,
		FDAStatus:        fdaStatus.Status,
		LocalStatus:      localStatus,
		WorkflowState:    workflowState,
		Acknowledgements: acks,
	})
}

// storedAckResponse is the JSON response for a locally stored acknowledgement.
type storedAckResponse struct {
	ID               string         `json:"id"`
	FDAAckID         string         `json:"fda_ack_id,omitempty"`
	AckType          string         `json:"ack_type"`
	Status           string         `json:"status"`
	RawMessage       string         `json:"raw_message,omitempty"`
	ParsedData       map[string]any `json:"parsed_data,omitempty"`
	ESGNGCode        string         `json:"esgng_code,omitempty"`
	ReceivedAt       string         `json:"received_at"`
}

// handleListAcknowledgements handles GET /api/v1/submissions/{id}/acknowledgements.
// Returns all locally stored acknowledgements for a submission (populated by the poller).
func (s *Server) handleListAcknowledgements(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing submission id"})
		return
	}

	orgID := orgIDFromContext(r.Context())

	// Verify submission exists and belongs to the org
	sub, err := s.submissions.GetByID(r.Context(), orgID, id)
	if err != nil {
		log.Printf("error getting submission %s: %v", id, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get submission"})
		return
	}
	if sub == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "submission not found"})
		return
	}

	acks, err := s.acks.ListBySubmission(r.Context(), id)
	if err != nil {
		log.Printf("error listing acknowledgements for %s: %v", id, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list acknowledgements"})
		return
	}

	results := make([]storedAckResponse, 0, len(acks))
	for _, a := range acks {
		resp := storedAckResponse{
			ID:         a.ID,
			AckType:    a.AckType,
			Status:     a.Status,
			ReceivedAt: a.ReceivedAt.Format("2006-01-02T15:04:05Z"),
		}
		if a.FDAAckID.Valid {
			resp.FDAAckID = a.FDAAckID.String
		}
		if a.RawMessage.Valid {
			resp.RawMessage = a.RawMessage.String
		}
		if a.ESGNGCode.Valid {
			resp.ESGNGCode = a.ESGNGCode.String
		}
		if a.ParsedDataJSON.Valid {
			var parsed map[string]any
			if err := json.Unmarshal([]byte(a.ParsedDataJSON.String), &parsed); err == nil {
				resp.ParsedData = parsed
			}
		}
		results = append(results, resp)
	}

	writeJSON(w, http.StatusOK, results)
}

// mapFDAStatus translates an FDA status string to our local status and workflow state.
func mapFDAStatus(fdaStatus string) (localStatus, workflowState string) {
	switch fdaStatus {
	case "RECEIVED":
		return "submitted", "SUBMITTED"
	case "PROCESSING":
		return "submitted", "PROCESSING"
	case "ACCEPTED":
		return "completed", "ACCEPTED"
	case "REJECTED":
		return "failed", "REJECTED"
	default:
		return "submitted", "UNKNOWN_FDA_STATUS"
	}
}

