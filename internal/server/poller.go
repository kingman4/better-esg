package server

import (
	"context"
	"time"

	"github.com/kingman4/better-esg/internal/repository"
)

// pollableStates are the workflow states that need background FDA polling.
var pollableStates = []string{"SUBMITTED", "UPLOADING_TO_FDA", "SUBMITTED_TO_CENTER", "PROCESSING"}

// startStatusPoller launches a background goroutine that periodically polls FDA
// for all in-flight submissions and updates the local DB.
func (s *Server) startStatusPoller(ctx context.Context, interval time.Duration) {
	s.logger.Info("starting status poller", "interval", interval)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				s.logger.Info("stopping status poller")
				return
			case <-ticker.C:
				s.pollAllSubmissions(ctx)
			}
		}
	}()
}

// stopStatusPoller cancels the poller's context, causing the goroutine to exit.
func (s *Server) stopStatusPoller() {
	if s.pollerCancel != nil {
		s.pollerCancel()
	}
}

// pollAllSubmissions queries the DB for all in-flight submissions and polls FDA for each.
func (s *Server) pollAllSubmissions(ctx context.Context) {
	subs, err := s.submissions.ListByWorkflowStates(ctx, pollableStates)
	if err != nil {
		s.logger.Error("poller: failed to list in-flight submissions", "error", err)
		return
	}
	if len(subs) == 0 {
		return
	}

	s.logger.Info("poller: polling in-flight submissions", "count", len(subs))

	for i := range subs {
		if ctx.Err() != nil {
			return
		}
		s.pollSubmission(ctx, &subs[i])
	}
}

// pollSubmission polls FDA for a single submission, updates the DB status,
// and stores any new acknowledgements.
func (s *Server) pollSubmission(ctx context.Context, sub *repository.Submission) {
	coreID := sub.CoreID.String

	fdaStatus, err := s.fda.GetSubmissionStatus(ctx, coreID)
	if err != nil {
		s.logger.Error("poller: FDA status check failed", "submission_id", sub.ID, "core_id", coreID, "error", err)
		return
	}

	// Map FDA status to local values
	localStatus, workflowState := mapFDAStatus(fdaStatus.Status)

	// Update local DB if status changed
	if sub.Status != localStatus || sub.WorkflowState != workflowState {
		if err := s.transitionState(ctx, sub.ID, sub.WorkflowState, localStatus, workflowState, nil, ""); err != nil {
			s.logger.Error("poller: failed to update status", "submission_id", sub.ID, "error", err)
		} else {
			s.logger.Info("poller: submission status changed",
				"submission_id", sub.ID, "core_id", coreID,
				"fda_status", fdaStatus.Status,
				"old_status", sub.Status, "new_status", localStatus,
				"old_workflow", sub.WorkflowState, "new_workflow", workflowState)
		}
	}

	// Fetch and store acknowledgements
	for _, ref := range fdaStatus.Acknowledgements {
		ack, err := s.fda.GetAcknowledgement(ctx, ref.AcknowledgementID)
		if err != nil {
			s.logger.Error("poller: failed to fetch acknowledgement", "ack_id", ref.AcknowledgementID, "submission_id", sub.ID, "error", err)
			continue
		}

		if err := s.acks.Insert(ctx, repository.InsertAckParams{
			SubmissionID: sub.ID,
			FDAAckID:     ack.AcknowledgementID,
			AckType:      ack.Type,
			Status:       fdaStatus.Status,
			RawMessage:   ack.RawMessage,
			ParsedData:   ack.ParsedData,
			ESGNGCode:    ack.ESGNGCode,
		}); err != nil {
			s.logger.Error("poller: failed to store acknowledgement", "ack_id", ack.AcknowledgementID, "submission_id", sub.ID, "error", err)
		} else {
			s.auditSystem(ctx, sub.OrgID, "receive_acknowledgement", "acknowledgement", ack.AcknowledgementID, map[string]any{
				"submission_id": sub.ID,
				"ack_type":      ack.Type,
				"status":        fdaStatus.Status,
			})
			s.notifyEvent(sub.OrgID, WebhookEvent{
				Type: "acknowledgement.received",
				Data: map[string]any{"submission_id": sub.ID, "ack_id": ack.AcknowledgementID, "ack_type": ack.Type},
			})
		}
	}
}
