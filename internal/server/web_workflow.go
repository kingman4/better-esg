package server

import (
	"context"
	"fmt"

	"github.com/kingman4/better-esg/internal/fdaclient"
)

// submitWorkflowAsync runs the full FDA submission workflow in a background goroutine.
// It takes a submission that already has files saved locally and moves it through:
// credentials → payload → upload files to FDA → finalize.
//
// On any error, the submission transitions to the appropriate *_FAILED state with
// error details logged. The detail page shows live progress as states update.
func (s *Server) submitWorkflowAsync(submissionID, orgID, userID string) {
	ctx := context.Background()
	log := s.logger.With("submission_id", submissionID, "workflow", "auto_submit")

	// Helper to transition state and bail on error
	fail := func(fromWorkflow, failedStatus, failedWorkflow string, err error) {
		log.Error("workflow failed", "state", failedWorkflow, "error", err)
		s.transitionState(ctx, submissionID, fromWorkflow, failedStatus, failedWorkflow, &userID, err.Error())
	}

	// --- Step 1: Resolve FDA company info ---
	if s.fdaUserEmail == "" {
		fail("INITIALIZED", "failed", "CREDENTIALS_FAILED",
			fmt.Errorf("FDA_USER_EMAIL not configured — cannot auto-submit"))
		return
	}

	if err := s.transitionState(ctx, submissionID, "INITIALIZED", "initiated", "CREDENTIALS_PENDING", &userID, ""); err != nil {
		log.Error("failed to transition to CREDENTIALS_PENDING", "error", err)
		return
	}

	companyInfo, err := s.fda.GetCompanyInfo(ctx, s.fdaUserEmail)
	if err != nil {
		fail("CREDENTIALS_PENDING", "failed", "CREDENTIALS_FAILED", fmt.Errorf("GetCompanyInfo: %w", err))
		return
	}

	fdaUserID := fmt.Sprintf("%d", companyInfo.UserID)
	fdaCompanyID := fmt.Sprintf("%d", companyInfo.CompanyID)
	log.Info("resolved FDA IDs", "fda_user_id", fdaUserID, "fda_company_id", fdaCompanyID)

	// --- Step 2: Submit credentials to FDA ---
	sub, err := s.submissions.GetByID(ctx, orgID, submissionID)
	if err != nil || sub == nil {
		fail("CREDENTIALS_PENDING", "failed", "CREDENTIALS_FAILED", fmt.Errorf("failed to load submission: %w", err))
		return
	}

	credReq := fdaclient.CredentialRequest{
		UserID:             fdaUserID,
		FDACenter:          sub.FDACenter.String,
		CompanyID:          fdaCompanyID,
		SubmissionType:     sub.SubmissionType,
		SubmissionName:     sub.SubmissionName,
		SubmissionProtocol: sub.SubmissionProtocol,
		FileCount:          sub.FileCount,
		Description:        sub.Description.String,
	}
	log.Info("submitting credentials to FDA",
		"fda_center", credReq.FDACenter,
		"submission_type", credReq.SubmissionType,
		"submission_protocol", credReq.SubmissionProtocol,
		"description", credReq.Description,
		"user_id", credReq.UserID,
		"company_id", credReq.CompanyID,
		"file_count", credReq.FileCount,
	)
	credResp, err := s.fda.SubmitCredentials(ctx, credReq)
	if err != nil {
		fail("CREDENTIALS_PENDING", "failed", "CREDENTIALS_FAILED", fmt.Errorf("SubmitCredentials: %w", err))
		return
	}

	// --- Step 3: Save temp credentials ---
	if err := s.submissions.SaveTempCredentials(ctx, submissionID, credResp.TempUser, credResp.TempPassword); err != nil {
		fail("CREDENTIALS_PENDING", "failed", "CREDENTIALS_FAILED", fmt.Errorf("SaveTempCredentials: %w", err))
		return
	}

	s.transitionState(ctx, submissionID, "CREDENTIALS_PENDING", "credentials_generated", "PAYLOAD_PENDING", &userID, "")

	// --- Step 4: Get payload from FDA ---
	payloadResp, err := s.fda.GetPayload(ctx)
	if err != nil {
		fail("PAYLOAD_PENDING", "failed", "PAYLOAD_FAILED", fmt.Errorf("GetPayload: %w", err))
		return
	}

	// --- Step 5: Persist FDA fields ---
	if err := s.submissions.UpdateFDAFields(ctx, submissionID,
		credResp.CoreID, payloadResp.PayloadID,
		payloadResp.UploadFileLink, payloadResp.SubmitFormLink,
	); err != nil {
		fail("PAYLOAD_PENDING", "failed", "PAYLOAD_FAILED", fmt.Errorf("UpdateFDAFields: %w", err))
		return
	}

	s.transitionState(ctx, submissionID, "PAYLOAD_PENDING", "payload_obtained", "UPLOAD_PENDING", &userID, "")
	log.Info("FDA payload obtained",
		"core_id", credResp.CoreID,
		"payload_id", payloadResp.PayloadID,
		"upload_link", payloadResp.UploadFileLink,
		"submit_link", payloadResp.SubmitFormLink,
	)

	// --- Step 6: Upload each file to FDA ---
	files, err := s.files.ListBySubmission(ctx, submissionID)
	if err != nil {
		fail("UPLOAD_PENDING", "failed", "UPLOAD_FAILED", fmt.Errorf("ListBySubmission: %w", err))
		return
	}

	currentWorkflow := "UPLOAD_PENDING"
	for i, f := range files {
		reader, err := s.storage.Open(ctx, f.StoragePath)
		if err != nil {
			fail(currentWorkflow, "failed", "UPLOAD_FAILED",
				fmt.Errorf("open file %q from storage: %w", f.FileName, err))
			return
		}

		_, fdaErr := s.fda.UploadFile(ctx, payloadResp.PayloadID, f.FileName, reader, f.FileSizeBytes)
		reader.Close()
		if fdaErr != nil {
			s.files.UpdateStatus(ctx, f.ID, "failed")
			fail(currentWorkflow, "failed", "UPLOAD_FAILED",
				fmt.Errorf("UploadFile %q: %w", f.FileName, fdaErr))
			return
		}

		s.files.UpdateStatus(ctx, f.ID, "uploaded")
		log.Info("file uploaded to FDA", "file", f.FileName, "progress", fmt.Sprintf("%d/%d", i+1, len(files)))

		// Transition to FILES_UPLOADING on first file
		if i == 0 {
			s.transitionState(ctx, submissionID, "UPLOAD_PENDING", "file_uploaded", "FILES_UPLOADING", &userID, "")
			currentWorkflow = "FILES_UPLOADING"
		}
	}

	// --- Step 7: Finalize — compute checksum and submit payload ---
	s.transitionState(ctx, submissionID, "FILES_UPLOADING", "file_uploaded", "SUBMIT_PENDING", &userID, "")

	checksum := computeCombinedChecksum(files)

	creds, err := s.submissions.GetTempCredentials(ctx, submissionID)
	if err != nil {
		fail("SUBMIT_PENDING", "failed", "SUBMIT_FAILED", fmt.Errorf("GetTempCredentials: %w", err))
		return
	}

	_, fdaErr := s.fda.SubmitPayload(ctx, payloadResp.PayloadID, fdaclient.SubmitRequest{
		TempUser:       creds.TempUser,
		TempPassword:   creds.TempPassword,
		SHA256Checksum: checksum,
	})
	if fdaErr != nil {
		fail("SUBMIT_PENDING", "failed", "SUBMIT_FAILED", fmt.Errorf("SubmitPayload: %w", fdaErr))
		return
	}

	// --- Step 8: Done ---
	s.transitionState(ctx, submissionID, "SUBMIT_PENDING", "submitted", "SUBMITTED", &userID, "")

	s.auditSystem(ctx, orgID, "auto_submit_complete", "submission", submissionID, map[string]any{
		"core_id":    credResp.CoreID,
		"payload_id": payloadResp.PayloadID,
		"file_count": len(files),
		"checksum":   checksum,
	})

	log.Info("submission auto-submitted to FDA",
		"core_id", credResp.CoreID,
		"payload_id", payloadResp.PayloadID,
		"files", len(files))
}
