package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/kingman4/better-esg/internal/repository"
)

// createSubmissionRequest is the JSON body for POST /api/v1/submissions.
type createSubmissionRequest struct {
	OrgID              string `json:"org_id"`
	FDACenter          string `json:"fda_center"`
	SubmissionType     string `json:"submission_type"`
	SubmissionName     string `json:"submission_name"`
	SubmissionProtocol string `json:"submission_protocol"`
	FileCount          int    `json:"file_count"`
	Description        string `json:"description"`
	CreatedBy          string `json:"created_by"`
}

// submissionResponse is the JSON response for a single submission.
type submissionResponse struct {
	ID                 string  `json:"id"`
	OrgID              string  `json:"org_id"`
	CoreID             *string `json:"core_id,omitempty"`
	FDACenter          *string `json:"fda_center,omitempty"`
	SubmissionType     string  `json:"submission_type"`
	SubmissionName     string  `json:"submission_name"`
	SubmissionProtocol string  `json:"submission_protocol"`
	FileCount          int     `json:"file_count"`
	Description        *string `json:"description,omitempty"`
	Status             string  `json:"status"`
	WorkflowState      string  `json:"workflow_state"`
	PayloadID          *string `json:"payload_id,omitempty"`
	CreatedBy          string  `json:"created_by"`
	CreatedAt          string  `json:"created_at"`
	UpdatedAt          string  `json:"updated_at"`
}

func toSubmissionResponse(s *repository.Submission) submissionResponse {
	resp := submissionResponse{
		ID:                 s.ID,
		OrgID:              s.OrgID,
		SubmissionType:     s.SubmissionType,
		SubmissionName:     s.SubmissionName,
		SubmissionProtocol: s.SubmissionProtocol,
		FileCount:          s.FileCount,
		Status:             s.Status,
		WorkflowState:      s.WorkflowState,
		CreatedBy:          s.CreatedBy,
		CreatedAt:          s.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:          s.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
	if s.CoreID.Valid {
		resp.CoreID = &s.CoreID.String
	}
	if s.FDACenter.Valid {
		resp.FDACenter = &s.FDACenter.String
	}
	if s.Description.Valid {
		resp.Description = &s.Description.String
	}
	if s.PayloadID.Valid {
		resp.PayloadID = &s.PayloadID.String
	}
	return resp
}

func (s *Server) handleCreateSubmission(w http.ResponseWriter, r *http.Request) {
	var req createSubmissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	// Basic validation
	if req.OrgID == "" || req.SubmissionType == "" || req.SubmissionName == "" || req.CreatedBy == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "org_id, submission_type, submission_name, and created_by are required",
		})
		return
	}
	if req.FileCount < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "file_count must be at least 1",
		})
		return
	}

	protocol := req.SubmissionProtocol
	if protocol == "" {
		protocol = "API"
	}

	sub, err := s.submissions.Create(r.Context(), repository.CreateSubmissionParams{
		OrgID:              req.OrgID,
		FDACenter:          req.FDACenter,
		SubmissionType:     req.SubmissionType,
		SubmissionName:     req.SubmissionName,
		SubmissionProtocol: protocol,
		FileCount:          req.FileCount,
		Description:        req.Description,
		CreatedBy:          req.CreatedBy,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create submission"})
		return
	}

	writeJSON(w, http.StatusCreated, toSubmissionResponse(sub))
}

func (s *Server) handleGetSubmission(w http.ResponseWriter, r *http.Request) {
	// Extract {id} from path: /api/v1/submissions/{id}
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing submission id"})
		return
	}

	// org_id from query param (will be from auth context later)
	orgID := r.URL.Query().Get("org_id")
	if orgID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "org_id query parameter is required"})
		return
	}

	sub, err := s.submissions.GetByID(r.Context(), orgID, id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get submission"})
		return
	}
	if sub == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "submission not found"})
		return
	}

	writeJSON(w, http.StatusOK, toSubmissionResponse(sub))
}

func (s *Server) handleListSubmissions(w http.ResponseWriter, r *http.Request) {
	orgID := r.URL.Query().Get("org_id")
	if orgID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "org_id query parameter is required"})
		return
	}

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

	subs, err := s.submissions.ListByOrg(r.Context(), orgID, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list submissions"})
		return
	}

	// Ensure we return [] not null for empty lists
	results := make([]submissionResponse, 0, len(subs))
	for i := range subs {
		results = append(results, toSubmissionResponse(&subs[i]))
	}

	writeJSON(w, http.StatusOK, results)
}

// extractSubmissionID is a helper for extracting {id} from URL paths.
// Used when Go 1.22+ path value isn't available (e.g., in tests with older patterns).
func extractSubmissionID(path string) string {
	// /api/v1/submissions/{id}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}
