// Package pages contains templ page components for the web UI.
// Template functions are generated from .templ files via `templ generate`.
package pages

import "strings"

// LoginData holds the data for the login page.
type LoginData struct {
	Env            string // "prod" or "test"
	Error          string
	Email          string
	OrgSlug        string
	MFARequired    bool
	MFAToken       string
	MFASetupNeeded bool
}

// DashboardData holds everything needed to render the dashboard.
type DashboardData struct {
	Env         string // "prod" or "test"
	UserEmail   string
	StateCounts map[string]int
	RecentSubs  []RecentSubmission
	TotalCount  int
}

// RecentSubmission is a lightweight struct for the recent submissions table.
type RecentSubmission struct {
	ID            string
	Name          string
	Type          string
	WorkflowState string
	CreatedAt     string
}

// SubmissionsData holds everything needed to render the submissions list page.
type SubmissionsData struct {
	Env         string // "prod" or "test"
	UserEmail   string
	Submissions []RecentSubmission
	TotalCount  int
}

// WorkflowStep represents a single workflow state transition for the timeline.
type WorkflowStep struct {
	FromState string
	ToState   string
	Error     string
	CreatedAt string
}

// SubmissionDetailData holds everything needed to render the submission detail page.
type SubmissionDetailData struct {
	Env           string // "prod" or "test"
	UserEmail     string
	ID            string
	Name          string
	Type          string
	Protocol      string
	FDACenter     string
	Description   string
	FileCount     int
	Status        string
	WorkflowState string
	CreatedBy     string
	CreatedAt     string
	SubmittedAt   string
	CompletedAt   string
	ErrorMessage  string         // latest workflow error (if failed)
	WorkflowLog   []WorkflowStep // workflow state transitions
}

// DisplayLabel returns a user-friendly label for the current workflow state.
func (d SubmissionDetailData) DisplayLabel() string {
	return workflowDisplayLabel(d.WorkflowState)
}

// IsTerminal returns true if the workflow is in a final state (no more polling needed).
func (d SubmissionDetailData) IsTerminal() bool {
	switch d.WorkflowState {
	case "ACCEPTED", "REJECTED", "COMPLETED", "FDA_ERROR":
		return true
	}
	return isFailedWorkflow(d.WorkflowState)
}

// CreateSubmissionData holds the data for the create submission form.
type CreateSubmissionData struct {
	Env       string // "prod" or "test"
	UserEmail string
	Error     string
	Name      string
	Type      string
	FDACenter string
	Desc      string
}

func badgeClass(state string) string {
	switch state {
	case "INITIALIZED":
		return "badge-draft"
	case "SUBMITTED", "UPLOADING_TO_FDA", "SUBMITTED_TO_CENTER", "PROCESSING":
		return "badge-submitted"
	case "ACCEPTED", "COMPLETED":
		return "badge-completed"
	case "REJECTED", "FDA_ERROR":
		return "badge-failed"
	default:
		if isFailedWorkflow(state) {
			return "badge-failed"
		}
		if strings.HasPrefix(state, "UNKNOWN_FDA_STATUS:") {
			return "badge-submitted"
		}
		return "badge-processing"
	}
}

func isFailedWorkflow(state string) bool {
	return state == "FAILED" || (len(state) > 6 && state[len(state)-6:] == "FAILED")
}

// workflowDisplayLabel returns a user-friendly label for a workflow state.
func workflowDisplayLabel(state string) string {
	switch state {
	case "INITIALIZED":
		return "Initialized"
	case "CREDENTIALS_PENDING":
		return "Authenticating with FDA"
	case "CREDENTIALS_FAILED":
		return "FDA Authentication Failed"
	case "PAYLOAD_PENDING":
		return "Requesting Payload ID"
	case "PAYLOAD_FAILED":
		return "Payload Request Failed"
	case "UPLOAD_PENDING":
		return "Preparing File Upload"
	case "FILES_UPLOADING":
		return "Uploading Files to FDA"
	case "UPLOAD_FAILED":
		return "File Upload Failed"
	case "SUBMIT_PENDING":
		return "Finalizing Submission"
	case "SUBMIT_FAILED":
		return "Submission Failed"
	case "SUBMITTED":
		return "Sent to FDA Gateway"
	case "UPLOADING_TO_FDA":
		return "FDA Receiving Files"
	case "SUBMITTED_TO_CENTER":
		return "Routed to FDA Center"
	case "PROCESSING":
		return "Under FDA Review"
	case "ACCEPTED":
		return "Accepted by FDA"
	case "REJECTED":
		return "Rejected by FDA"
	case "FDA_ERROR":
		return "FDA Error"
	default:
		if strings.HasPrefix(state, "UNKNOWN_FDA_STATUS:") {
			return "FDA: " + state[len("UNKNOWN_FDA_STATUS:"):]
		}
		return state
	}
}

// ProgressStep represents one step in the workflow progress indicator.
type ProgressStep struct {
	Label  string // e.g. "Authenticate", "Upload Files"
	Status string // "completed", "current", "upcoming", "failed"
}

// WorkflowProgress returns the ordered steps with their status relative to the current state.
func WorkflowProgress(workflowState string) []ProgressStep {
	// Define the happy-path steps and which workflow states map to each step index.
	type stepDef struct {
		label  string
		states []string // workflow states that mean "we are at this step"
	}
	steps := []stepDef{
		{"Authenticate", []string{"CREDENTIALS_PENDING"}},
		{"Upload Files", []string{"PAYLOAD_PENDING", "UPLOAD_PENDING", "FILES_UPLOADING"}},
		{"Submit", []string{"SUBMIT_PENDING", "SUBMITTED"}},
		{"FDA Receiving", []string{"UPLOADING_TO_FDA"}},
		{"Routed to Center", []string{"SUBMITTED_TO_CENTER"}},
		{"FDA Review", []string{"PROCESSING"}},
		{"Decision", []string{"ACCEPTED", "REJECTED"}},
	}

	// Find which step the current state belongs to.
	currentIdx := -1
	isFailed := isFailedWorkflow(workflowState)
	for i, s := range steps {
		for _, ws := range s.states {
			if ws == workflowState {
				currentIdx = i
				break
			}
		}
		if currentIdx >= 0 {
			break
		}
	}

	// INITIALIZED is before step 0
	if workflowState == "INITIALIZED" {
		currentIdx = -1 // all steps are upcoming
	}

	// For failed states, find the step that failed based on suffix
	failedIdx := -1
	if isFailed {
		switch {
		case strings.HasPrefix(workflowState, "CREDENTIALS"):
			failedIdx = 0
		case strings.HasPrefix(workflowState, "PAYLOAD") || strings.HasPrefix(workflowState, "UPLOAD"):
			failedIdx = 1
		case strings.HasPrefix(workflowState, "SUBMIT"):
			failedIdx = 2
		default:
			failedIdx = currentIdx
		}
		currentIdx = failedIdx
	}

	// FDA_ERROR or unknown → show as far as we know
	if workflowState == "FDA_ERROR" {
		currentIdx = 5 // FDA Review step
		isFailed = true
		failedIdx = 5
	}
	if strings.HasPrefix(workflowState, "UNKNOWN_FDA_STATUS:") {
		currentIdx = 5 // best guess: somewhere in FDA review
	}

	result := make([]ProgressStep, len(steps))
	for i, s := range steps {
		switch {
		case isFailed && i == failedIdx:
			result[i] = ProgressStep{Label: s.label, Status: "failed"}
		case i < currentIdx:
			result[i] = ProgressStep{Label: s.label, Status: "completed"}
		case i == currentIdx:
			result[i] = ProgressStep{Label: s.label, Status: "current"}
		default:
			result[i] = ProgressStep{Label: s.label, Status: "upcoming"}
		}
	}
	// Terminal success: mark decision as completed
	if workflowState == "ACCEPTED" || workflowState == "COMPLETED" {
		for i := range result {
			result[i].Status = "completed"
		}
	}
	return result
}

// WorkflowLabel is a helper for list views to show friendly labels.
func WorkflowLabel(state string) string {
	return workflowDisplayLabel(state)
}

// progressStepContainerClass returns the CSS class for a progress step container.
func progressStepContainerClass(index, total int) string {
	if index < total-1 {
		return "flex items-center flex-1"
	}
	return "flex items-center"
}

// progressLabelClass returns the CSS class for a progress step label.
func progressLabelClass(status string) string {
	switch status {
	case "completed":
		return "mt-2 text-xs font-medium text-green-700 text-center"
	case "current":
		return "mt-2 text-xs font-semibold text-green-800 text-center"
	case "failed":
		return "mt-2 text-xs font-medium text-red-600 text-center"
	default:
		return "mt-2 text-xs font-medium text-gray-400 text-center"
	}
}

// progressLineClass returns the CSS class for the connector line between progress steps.
func progressLineClass(status string) string {
	if status == "completed" || status == "current" {
		return "flex-1 h-0.5 bg-green-300 mx-2 mt-4 self-start"
	}
	return "flex-1 h-0.5 bg-gray-200 mx-2 mt-4 self-start"
}

// workflowStatusHint returns a short explanation of what's happening at the current step.
func workflowStatusHint(state string) string {
	switch state {
	case "INITIALIZED":
		return "Waiting to start submission workflow"
	case "CREDENTIALS_PENDING":
		return "Authenticating with the FDA gateway"
	case "PAYLOAD_PENDING":
		return "Requesting a payload slot from FDA"
	case "UPLOAD_PENDING", "FILES_UPLOADING":
		return "Uploading submission files to FDA"
	case "SUBMIT_PENDING":
		return "Finalizing and submitting to FDA"
	case "SUBMITTED":
		return "Submission sent, waiting for FDA to acknowledge"
	case "UPLOADING_TO_FDA":
		return "FDA is receiving and processing uploaded files"
	case "SUBMITTED_TO_CENTER":
		return "Routed to the review center, awaiting FDA review"
	case "PROCESSING":
		return "Under active review by the FDA center"
	default:
		if strings.HasPrefix(state, "UNKNOWN_FDA_STATUS:") {
			return "Awaiting updated status from FDA"
		}
		return ""
	}
}

func countFailed(counts map[string]int) int {
	total := 0
	for state, n := range counts {
		if len(state) > 6 && state[len(state)-6:] == "FAILED" {
			total += n
		}
		if state == "FAILED" {
			total += n
		}
	}
	return total
}
