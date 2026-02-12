package server

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/kingman4/better-esg/internal/fdaclient"
)

// submitToFDARequest is the JSON body for POST /api/v1/submissions/{id}/submit.
type submitToFDARequest struct {
	OrgID     string `json:"org_id"`
	UserEmail string `json:"user_email"`
	CompanyID string `json:"company_id"`
}

// submitToFDAResponse is the JSON response after triggering the FDA workflow.
type submitToFDAResponse struct {
	SubmissionID  string `json:"submission_id"`
	CoreID        string `json:"core_id"`
	PayloadID     string `json:"payload_id"`
	Status        string `json:"status"`
	WorkflowState string `json:"workflow_state"`
}

// handleSubmitToFDA initiates the FDA submission workflow:
// 1. Validate the submission is in draft status
// 2. Submit credentials to FDA → get core_id + temp credentials
// 3. Persist temp credentials for later use in finalize step
// 4. Get payload ID from FDA upload API
// 5. Update DB with FDA fields (core_id, payload_id, links)
//
// After this handler returns, the caller should upload files via
// POST /api/v1/submissions/{id}/files, then finalize via
// POST /api/v1/submissions/{id}/finalize.
func (s *Server) handleSubmitToFDA(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing submission id"})
		return
	}

	var req submitToFDARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.OrgID == "" || req.UserEmail == "" || req.CompanyID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "org_id, user_email, and company_id are required",
		})
		return
	}

	// 1. Look up submission and verify it's in draft status
	sub, err := s.submissions.GetByID(r.Context(), req.OrgID, id)
	if err != nil {
		log.Printf("error getting submission %s: %v", id, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get submission"})
		return
	}
	if sub == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "submission not found"})
		return
	}
	if sub.Status != "draft" {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "submission is not in draft status (current: " + sub.Status + ")",
		})
		return
	}

	// Update status to initiated
	if err := s.submissions.UpdateStatus(r.Context(), id, "initiated", "CREDENTIALS_PENDING"); err != nil {
		log.Printf("error updating status for %s: %v", id, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update submission status"})
		return
	}

	// 2. Submit credentials to FDA
	credResp, err := s.fda.SubmitCredentials(r.Context(), fdaclient.CredentialRequest{
		UserID:             req.UserEmail,
		FDACenter:          stringOrDefault(sub.FDACenter.String, "CDER"),
		CompanyID:          req.CompanyID,
		SubmissionType:     sub.SubmissionType,
		SubmissionProtocol: sub.SubmissionProtocol,
		FileCount:          sub.FileCount,
		Description:        sub.Description.String,
	})
	if err != nil {
		log.Printf("FDA credential submission failed for %s: %v", id, err)
		s.submissions.UpdateStatus(r.Context(), id, "failed", "CREDENTIALS_FAILED")
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": "FDA credential submission failed: " + sanitizeError(err),
		})
		return
	}

	// Persist temp credentials for use during finalize step
	if err := s.submissions.SaveTempCredentials(r.Context(), id, credResp.TempUser, credResp.TempPassword); err != nil {
		log.Printf("error saving temp credentials for %s: %v", id, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save credentials"})
		return
	}

	if err := s.submissions.UpdateStatus(r.Context(), id, "credentials_generated", "PAYLOAD_PENDING"); err != nil {
		log.Printf("error updating status for %s: %v", id, err)
	}

	// 3. Get payload ID from FDA upload API
	payloadResp, err := s.fda.GetPayload(r.Context())
	if err != nil {
		log.Printf("FDA payload request failed for %s: %v", id, err)
		s.submissions.UpdateStatus(r.Context(), id, "failed", "PAYLOAD_FAILED")
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": "FDA payload request failed: " + sanitizeError(err),
		})
		return
	}

	// 4. Persist FDA fields to DB
	if err := s.submissions.UpdateFDAFields(r.Context(), id,
		credResp.CoreID, payloadResp.PayloadID,
		payloadResp.Links.UploadLink, payloadResp.Links.SubmitLink,
	); err != nil {
		log.Printf("error updating FDA fields for %s: %v", id, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save FDA data"})
		return
	}

	if err := s.submissions.UpdateStatus(r.Context(), id, "payload_obtained", "UPLOAD_PENDING"); err != nil {
		log.Printf("error updating status for %s: %v", id, err)
	}

	writeJSON(w, http.StatusOK, submitToFDAResponse{
		SubmissionID:  id,
		CoreID:        credResp.CoreID,
		PayloadID:     payloadResp.PayloadID,
		Status:        "payload_obtained",
		WorkflowState: "UPLOAD_PENDING",
	})
}

// sanitizeError returns the error message without exposing internal details.
// In production, this would strip sensitive info. For now, pass through FDA error codes.
func sanitizeError(err error) string {
	msg := err.Error()
	// Only expose FDA error codes, not internal details
	if strings.Contains(msg, "ESGNG") {
		return msg
	}
	return "internal error"
}

func stringOrDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
