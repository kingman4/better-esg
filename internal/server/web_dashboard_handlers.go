package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"

	"github.com/kingman4/better-esg/internal/repository"
	"github.com/kingman4/better-esg/internal/views/pages"
)

// handleDashboard renders the main dashboard page with submission stats.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	orgID := orgIDFromContext(r.Context())
	userID := userIDFromContext(r.Context())

	// Look up user email for the nav bar
	user, err := s.users.GetByID(r.Context(), orgID, userID)
	userEmail := ""
	if err == nil && user != nil {
		userEmail = user.Email
	}

	// Get workflow state counts
	stateCounts, err := s.submissions.CountByWorkflowState(r.Context(), orgID)
	if err != nil {
		s.logger.Error("dashboard: failed to count submissions", "error", err)
		stateCounts = map[string]int{}
	}

	totalCount := 0
	for _, n := range stateCounts {
		totalCount += n
	}

	// Get recent submissions (limit 10)
	subs, err := s.submissions.ListByOrg(r.Context(), orgID, 10, 0)
	if err != nil {
		s.logger.Error("dashboard: failed to list submissions", "error", err)
	}

	recentSubs := make([]pages.RecentSubmission, 0, len(subs))
	for _, sub := range subs {
		recentSubs = append(recentSubs, pages.RecentSubmission{
			ID:            sub.ID,
			Name:          sub.SubmissionName,
			Type:          sub.SubmissionType,
			WorkflowState: sub.WorkflowState,
			CreatedAt:     sub.CreatedAt.Format("Jan 02, 2006"),
		})
	}

	pages.DashboardPage(pages.DashboardData{
		Env:         s.fdaEnvironment,
		UserEmail:   userEmail,
		StateCounts: stateCounts,
		RecentSubs:  recentSubs,
		TotalCount:  totalCount,
	}).Render(r.Context(), w)
}

// handleSubmissionsList renders the full submissions list page.
func (s *Server) handleSubmissionsList(w http.ResponseWriter, r *http.Request) {
	orgID := orgIDFromContext(r.Context())
	userID := userIDFromContext(r.Context())

	// Look up user email for the nav bar
	user, err := s.users.GetByID(r.Context(), orgID, userID)
	userEmail := ""
	if err == nil && user != nil {
		userEmail = user.Email
	}

	// Get all submissions (limit 100)
	subs, err := s.submissions.ListByOrg(r.Context(), orgID, 100, 0)
	if err != nil {
		s.logger.Error("submissions list: failed to list submissions", "error", err)
	}

	subsList := make([]pages.RecentSubmission, 0, len(subs))
	for _, sub := range subs {
		subsList = append(subsList, pages.RecentSubmission{
			ID:            sub.ID,
			Name:          sub.SubmissionName,
			Type:          sub.SubmissionType,
			WorkflowState: sub.WorkflowState,
			CreatedAt:     sub.CreatedAt.Format("Jan 02, 2006"),
		})
	}

	pages.SubmissionsPage(pages.SubmissionsData{
		Env:         s.fdaEnvironment,
		UserEmail:   userEmail,
		Submissions: subsList,
		TotalCount:  len(subsList),
	}).Render(r.Context(), w)
}

// handleSubmissionDetail renders a single submission's detail page.
func (s *Server) handleSubmissionDetail(w http.ResponseWriter, r *http.Request) {
	orgID := orgIDFromContext(r.Context())
	userID := userIDFromContext(r.Context())
	subID := r.PathValue("id")

	// Look up user email for the nav bar
	user, err := s.users.GetByID(r.Context(), orgID, userID)
	userEmail := ""
	if err == nil && user != nil {
		userEmail = user.Email
	}

	sub, err := s.submissions.GetByID(r.Context(), orgID, subID)
	if err != nil {
		s.logger.Error("submission detail: failed to get submission", "id", subID, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if sub == nil {
		http.Error(w, "Submission not found", http.StatusNotFound)
		return
	}

	data := s.buildDetailData(r.Context(), sub, userEmail)

	pages.SubmissionDetailPage(data).Render(r.Context(), w)
}

// buildDetailData constructs SubmissionDetailData from a Submission, including workflow log.
func (s *Server) buildDetailData(ctx context.Context, sub *repository.Submission, userEmail string) pages.SubmissionDetailData {
	data := pages.SubmissionDetailData{
		Env:           s.fdaEnvironment,
		UserEmail:     userEmail,
		ID:            sub.ID,
		Name:          sub.SubmissionName,
		Type:          sub.SubmissionType,
		Protocol:      sub.SubmissionProtocol,
		FileCount:     sub.FileCount,
		Status:        sub.Status,
		WorkflowState: sub.WorkflowState,
		CreatedBy:     sub.CreatedBy,
		CreatedAt:     sub.CreatedAt.Format("Jan 02, 2006 3:04 PM"),
	}
	if sub.FDACenter.Valid {
		data.FDACenter = sub.FDACenter.String
	}
	if sub.Description.Valid {
		data.Description = sub.Description.String
	}
	if sub.SubmittedAt.Valid {
		data.SubmittedAt = sub.SubmittedAt.Time.Format("Jan 02, 2006 3:04 PM")
	}
	if sub.CompletedAt.Valid {
		data.CompletedAt = sub.CompletedAt.Time.Format("Jan 02, 2006 3:04 PM")
	}

	// Fetch workflow log for timeline and error display
	logEntries, err := s.workflowLog.ListBySubmission(ctx, sub.ID)
	if err == nil {
		for _, e := range logEntries {
			step := pages.WorkflowStep{
				FromState: e.FromState,
				ToState:   e.ToState,
				CreatedAt: e.CreatedAt,
			}
			if e.ErrorDetails.Valid {
				step.Error = e.ErrorDetails.String
				data.ErrorMessage = e.ErrorDetails.String // last error wins
			}
			data.WorkflowLog = append(data.WorkflowLog, step)
		}
	}

	return data
}

// handleSubmissionStatus returns just the status fragment for HTMX polling.
func (s *Server) handleSubmissionStatus(w http.ResponseWriter, r *http.Request) {
	orgID := orgIDFromContext(r.Context())
	subID := r.PathValue("id")

	sub, err := s.submissions.GetByID(r.Context(), orgID, subID)
	if err != nil || sub == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	data := s.buildDetailData(r.Context(), sub, "")
	pages.SubmissionStatusFragment(data).Render(r.Context(), w)
}

// handleRetrySubmission resets a failed submission back to INITIALIZED and re-triggers the workflow.
func (s *Server) handleRetrySubmission(w http.ResponseWriter, r *http.Request) {
	orgID := orgIDFromContext(r.Context())
	userID := userIDFromContext(r.Context())
	subID := r.PathValue("id")

	sub, err := s.submissions.GetByID(r.Context(), orgID, subID)
	if err != nil {
		s.logger.Error("retry: failed to get submission", "id", subID, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if sub == nil {
		http.Error(w, "Submission not found", http.StatusNotFound)
		return
	}

	// Only allow retry from failed states
	if sub.Status != "failed" {
		http.Error(w, "Submission is not in a failed state", http.StatusBadRequest)
		return
	}

	// Reset to INITIALIZED so the workflow can restart
	if err := s.transitionState(r.Context(), subID, sub.WorkflowState, "draft", "INITIALIZED", &userID, "manual retry"); err != nil {
		s.logger.Error("retry: failed to reset state", "id", subID, "error", err)
		http.Error(w, "Failed to reset submission", http.StatusInternalServerError)
		return
	}

	// Re-trigger the async workflow
	go s.submitWorkflowAsync(subID, orgID, userID)

	http.Redirect(w, r, "/dashboard/submissions/"+subID, http.StatusFound)
}

// handleCreateSubmissionPage renders the create submission form.
func (s *Server) handleCreateSubmissionPage(w http.ResponseWriter, r *http.Request) {
	orgID := orgIDFromContext(r.Context())
	userID := userIDFromContext(r.Context())

	user, err := s.users.GetByID(r.Context(), orgID, userID)
	userEmail := ""
	if err == nil && user != nil {
		userEmail = user.Email
	}

	pages.CreateSubmissionPage(pages.CreateSubmissionData{
		Env:       s.fdaEnvironment,
		UserEmail: userEmail,
	}).Render(r.Context(), w)
}

// handleWebCreateSubmission processes the create submission form POST.
// It parses a multipart form, creates the submission with file_count auto-calculated
// from uploaded files, saves files to storage, and records them in the database.
func (s *Server) handleWebCreateSubmission(w http.ResponseWriter, r *http.Request) {
	orgID := orgIDFromContext(r.Context())
	userID := userIDFromContext(r.Context())

	user, err := s.users.GetByID(r.Context(), orgID, userID)
	userEmail := ""
	if err == nil && user != nil {
		userEmail = user.Email
	}

	// Parse multipart form — limit to 512MB total
	if err := r.ParseMultipartForm(512 << 20); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		pages.CreateSubmissionPage(pages.CreateSubmissionData{
			Env:       s.fdaEnvironment,
			UserEmail: userEmail,
			Error:     "Invalid form data",
		}).Render(r.Context(), w)
		return
	}

	name := r.FormValue("name")
	subType := r.FormValue("submission_type")
	fdaCenter := r.FormValue("fda_center")

	// Validate required fields
	if name == "" || subType == "" || fdaCenter == "" {
		w.WriteHeader(http.StatusBadRequest)
		pages.CreateSubmissionPage(pages.CreateSubmissionData{
			Env:       s.fdaEnvironment,
			UserEmail: userEmail,
			Error:     "Submission name, FDA center, and type are required",
			Name:      name,
			Type:      subType,
			FDACenter: fdaCenter,
			Desc:      r.FormValue("description"),
		}).Render(r.Context(), w)
		return
	}

	// Validate center/type combination against FDA spec
	if !IsValidCenterType(fdaCenter, subType) {
		w.WriteHeader(http.StatusBadRequest)
		pages.CreateSubmissionPage(pages.CreateSubmissionData{
			Env:       s.fdaEnvironment,
			UserEmail: userEmail,
			Error:     "Invalid FDA center / submission type combination",
			Name:      name,
			Type:      subType,
			FDACenter: fdaCenter,
			Desc:      r.FormValue("description"),
		}).Render(r.Context(), w)
		return
	}

	// Validate files are provided
	uploadedFiles := r.MultipartForm.File["files"]
	if len(uploadedFiles) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		pages.CreateSubmissionPage(pages.CreateSubmissionData{
			Env:       s.fdaEnvironment,
			UserEmail: userEmail,
			Error:     "At least one file is required",
			Name:      name,
			Type:      subType,
			FDACenter: fdaCenter,
			Desc:      r.FormValue("description"),
		}).Render(r.Context(), w)
		return
	}

	// Create submission — file_count auto-calculated, protocol defaults to "API"
	sub, err := s.submissions.Create(r.Context(), repository.CreateSubmissionParams{
		OrgID:              orgID,
		FDACenter:          fdaCenter,
		SubmissionType:     subType,
		SubmissionName:     name,
		SubmissionProtocol: "API",
		FileCount:          len(uploadedFiles),
		Description:        r.FormValue("description"),
		CreatedBy:          userID,
	})
	if err != nil {
		s.logger.Error("create submission: failed", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		pages.CreateSubmissionPage(pages.CreateSubmissionData{
			Env:       s.fdaEnvironment,
			UserEmail: userEmail,
			Error:     "Failed to create submission",
			Name:      name,
			Type:      subType,
			FDACenter: fdaCenter,
			Desc:      r.FormValue("description"),
		}).Render(r.Context(), w)
		return
	}

	// Save each uploaded file to storage and record in DB
	for _, fh := range uploadedFiles {
		file, err := fh.Open()
		if err != nil {
			s.logger.Error("create submission: failed to open uploaded file", "file", fh.Filename, "error", err)
			continue
		}

		storageKey := sub.ID + "/" + fh.Filename
		hasher := sha256.New()
		written, err := s.storage.Save(r.Context(), storageKey, io.TeeReader(file, hasher))
		file.Close()
		if err != nil {
			s.logger.Error("create submission: failed to save file", "file", fh.Filename, "error", err)
			continue
		}

		checksum := hex.EncodeToString(hasher.Sum(nil))
		mimeType := fh.Header.Get("Content-Type")
		if mimeType == "" {
			mimeType = "application/octet-stream"
		}

		_, err = s.files.Create(r.Context(), repository.CreateFileParams{
			SubmissionID:   sub.ID,
			FileName:       fh.Filename,
			FileSizeBytes:  written,
			SHA256Checksum: checksum,
			MimeType:       mimeType,
			StoragePath:    storageKey,
			StorageBackend: "local_fs",
		})
		if err != nil {
			s.logger.Error("create submission: failed to record file", "file", fh.Filename, "error", err)
			s.storage.Delete(r.Context(), storageKey)
		}
	}

	// Kick off the full FDA workflow in the background (credentials → upload → finalize).
	// The user is redirected to the detail page immediately and sees status progress.
	go s.submitWorkflowAsync(sub.ID, orgID, userID)

	http.Redirect(w, r, "/dashboard/submissions/"+sub.ID, http.StatusFound)
}
