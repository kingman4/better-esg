CREATE TABLE audit_logs (
  id BIGSERIAL,
  org_id UUID NOT NULL,
  user_id UUID,
  action VARCHAR(100) NOT NULL,
  -- create_submission, update_submission, download_ack, etc.
  entity_type VARCHAR(100) NOT NULL,
  -- submission, file, credential, acknowledgement
  entity_id VARCHAR(255),
  request_ip INET,
  user_agent VARCHAR(2048),
  details_json JSONB,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- Create initial partition for current month
-- Additional partitions should be created by a scheduled job
CREATE TABLE audit_logs_default PARTITION OF audit_logs DEFAULT;

CREATE INDEX idx_audit_logs_org ON audit_logs(org_id);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at DESC);

CREATE TABLE workflow_state_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  submission_id UUID NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
  from_state VARCHAR(50) NOT NULL,
  to_state VARCHAR(50) NOT NULL,
  triggered_by UUID,
  error_details TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_workflow_state_log_submission ON workflow_state_log(submission_id);
CREATE INDEX idx_workflow_state_log_created ON workflow_state_log(created_at DESC);
