package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/kingman4/better-esg/internal/fdaclient"
)

// submitToFDARequest is the JSON body for POST /api/v1/submissions/{id}/submit.
// All fields are optional — if omitted, the server uses FDA_USER_EMAIL from config
// to auto-resolve user_id and company_id via the FDA GetCompanyInfo API.
type submitToFDARequest struct {
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

	orgID := orgIDFromContext(r.Context())

	// Parse optional request body (user_email / company_id overrides)
	var req submitToFDARequest
	json.NewDecoder(r.Body).Decode(&req) // ignore errors — body is optional

	// Resolve user_email: request body → server config
	userEmail := req.UserEmail
	if userEmail == "" {
		userEmail = s.fdaUserEmail
	}
	if userEmail == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "user_email not provided and FDA_USER_EMAIL not configured",
		})
		return
	}

	// 1. Look up submission and verify it's in draft status
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
	if sub.Status != "draft" {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "submission is not in draft status (current: " + sub.Status + ")",
		})
		return
	}

	// Update status to initiated
	userID := userIDFromContext(r.Context())
	if err := s.transitionState(r.Context(), orgID, id, sub.WorkflowState, "initiated", "CREDENTIALS_PENDING", &userID, ""); err != nil {
		log.Printf("error updating status for %s: %v", id, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update submission status"})
		return
	}

	// 2a. Resolve FDA user_id and company_id
	fdaUserID := req.UserEmail   // fallback: use email as user_id (legacy behavior)
	fdaCompanyID := req.CompanyID

	if fdaCompanyID == "" {
		// Auto-resolve via GetCompanyInfo
		companyInfo, err := s.fda.GetCompanyInfo(r.Context(), userEmail)
		if err != nil {
			log.Printf("FDA GetCompanyInfo failed for %s: %v", userEmail, err)
			s.transitionState(r.Context(), orgID, id, "CREDENTIALS_PENDING", "failed", "CREDENTIALS_FAILED", &userID, err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error": "failed to resolve FDA company info: " + sanitizeError(err),
			})
			return
		}
		fdaUserID = fmt.Sprintf("%d", companyInfo.UserID)
		fdaCompanyID = fmt.Sprintf("%d", companyInfo.CompanyID)
		log.Printf("resolved FDA IDs for %s: user_id=%s company_id=%s (%s)",
			userEmail, fdaUserID, fdaCompanyID, companyInfo.CompanyName)
	}

	// 2b. Submit credentials to FDA
	credResp, err := s.fda.SubmitCredentials(r.Context(), fdaclient.CredentialRequest{
		UserID:             fdaUserID,
		FDACenter:          stringOrDefault(sub.FDACenter.String, "CDER"),
		CompanyID:          fdaCompanyID,
		SubmissionType:     sub.SubmissionType,
		SubmissionName:     sub.SubmissionName,
		SubmissionProtocol: sub.SubmissionProtocol,
		FileCount:          sub.FileCount,
		Description:        sub.Description.String,
	})
	if err != nil {
		log.Printf("FDA credential submission failed for %s: %v", id, err)
		s.transitionState(r.Context(), orgID, id, "CREDENTIALS_PENDING", "failed", "CREDENTIALS_FAILED", &userID, err.Error())
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

	if err := s.transitionState(r.Context(), orgID, id, "CREDENTIALS_PENDING", "credentials_generated", "PAYLOAD_PENDING", &userID, ""); err != nil {
		log.Printf("error updating status for %s: %v", id, err)
	}

	// 3. Get payload ID from FDA upload API
	payloadResp, err := s.fda.GetPayload(r.Context())
	if err != nil {
		log.Printf("FDA payload request failed for %s: %v", id, err)
		s.transitionState(r.Context(), orgID, id, "PAYLOAD_PENDING", "failed", "PAYLOAD_FAILED", &userID, err.Error())
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

	if err := s.transitionState(r.Context(), orgID, id, "PAYLOAD_PENDING", "payload_obtained", "UPLOAD_PENDING", &userID, ""); err != nil {
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

// sanitizeError returns the error message with internal Go details stripped.
// Preserves HTTP status codes and FDA error descriptions. Strips stack traces
// and internal error wrapping that would confuse API consumers.
func sanitizeError(err error) string {
	msg := err.Error()
	// Strip nested Go error wrapping prefixes (e.g. "acquiring token for company info: ")
	// but preserve the actual FDA/HTTP error at the end
	if idx := strings.LastIndex(msg, "returned "); idx >= 0 {
		return msg[idx:]
	}
	// Pass through FDA error codes as-is
	if strings.Contains(msg, "ESGNG") {
		return msg
	}
	return msg
}

func stringOrDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
