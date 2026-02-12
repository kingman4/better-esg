package server

import (
	"context"
	"log"
	"time"

	"github.com/kingman4/better-esg/internal/repository"
)

// pollableStates are the workflow states that need background FDA polling.
var pollableStates = []string{"SUBMITTED", "PROCESSING"}

// startStatusPoller launches a background goroutine that periodically polls FDA
// for all in-flight submissions and updates the local DB.
func (s *Server) startStatusPoller(ctx context.Context, interval time.Duration) {
	log.Printf("starting status poller (interval: %v)", interval)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Println("stopping status poller")
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
		log.Printf("poller: failed to list in-flight submissions: %v", err)
		return
	}
	if len(subs) == 0 {
		return
	}

	log.Printf("poller: polling %d in-flight submission(s)", len(subs))

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
		log.Printf("poller: FDA status check failed for submission %s (core_id=%s): %v", sub.ID, coreID, err)
		return
	}

	// Map FDA status to local values
	localStatus, workflowState := mapFDAStatus(fdaStatus.Status)

	// Update local DB if status changed
	if sub.Status != localStatus || sub.WorkflowState != workflowState {
		if err := s.transitionState(ctx, sub.ID, sub.WorkflowState, localStatus, workflowState, nil, ""); err != nil {
			log.Printf("poller: failed to update status for submission %s: %v", sub.ID, err)
		} else {
			log.Printf("poller: submission %s (core_id=%s): %s/%s → %s/%s",
				sub.ID, coreID, sub.Status, sub.WorkflowState, localStatus, workflowState)
		}
	}

	// Fetch and store acknowledgements
	for _, ref := range fdaStatus.Acknowledgements {
		ack, err := s.fda.GetAcknowledgement(ctx, ref.AcknowledgementID)
		if err != nil {
			log.Printf("poller: failed to fetch acknowledgement %s for submission %s: %v",
				ref.AcknowledgementID, sub.ID, err)
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
			log.Printf("poller: failed to store acknowledgement %s for submission %s: %v",
				ack.AcknowledgementID, sub.ID, err)
		}
	}
}
