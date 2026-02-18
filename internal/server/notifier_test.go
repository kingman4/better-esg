package server

import "testing"

func TestMapWorkflowToEvent(t *testing.T) {
	tests := []struct {
		workflow string
		want     string
	}{
		{"SUBMITTED", "submission.submitted"},
		{"COMPLETED", "submission.completed"},
		{"FAILED", "submission.failed"},
		{"DRAFT", ""},
		{"PROCESSING", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.workflow, func(t *testing.T) {
			got := mapWorkflowToEvent(tt.workflow)
			if got != tt.want {
				t.Errorf("mapWorkflowToEvent(%q) = %q, want %q", tt.workflow, got, tt.want)
			}
		})
	}
}

func TestValidNotificationEvents_AllExpected(t *testing.T) {
	expected := []string{
		"submission.created",
		"submission.submitted",
		"submission.completed",
		"submission.failed",
		"acknowledgement.received",
	}

	for _, evt := range expected {
		if !ValidNotificationEvents[evt] {
			t.Errorf("expected ValidNotificationEvents to contain %q", evt)
		}
	}

	// Shouldn't contain webhook.test (that's org-webhook only)
	if ValidNotificationEvents["webhook.test"] {
		t.Error("ValidNotificationEvents should not contain 'webhook.test'")
	}
}
