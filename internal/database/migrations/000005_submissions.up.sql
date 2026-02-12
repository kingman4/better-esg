CREATE TABLE submissions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  -- FDA-assigned identifier returned from credential submission
  core_id VARCHAR(100) UNIQUE,
  -- Submission metadata (sent to FDA credential endpoint)
  fda_center VARCHAR(100),
  submission_type VARCHAR(100) NOT NULL,
  submission_name VARCHAR(500) NOT NULL,
  submission_protocol VARCHAR(50) NOT NULL DEFAULT 'API',
  file_count INTEGER NOT NULL,
  total_size_bytes BIGINT,
  description TEXT,
  -- Workflow state
  status VARCHAR(50) NOT NULL DEFAULT 'draft',
  -- draft, initiated, credentials_generated, payload_obtained,
  -- file_uploaded, submitted, completed, failed
  workflow_state VARCHAR(50) NOT NULL DEFAULT 'INITIALIZED',
  -- Encrypted temp credentials (from FDA credential response)
  temp_user_encrypted VARCHAR(512),
  temp_password_encrypted VARCHAR(512),
  temp_credentials_key_id VARCHAR(100),
  -- File upload metadata (from FDA payload/upload responses)
  payload_id VARCHAR(255),
  upload_file_link VARCHAR(2048),
  submit_form_link VARCHAR(2048),
  -- Audit timestamps
  created_by UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  submitted_at TIMESTAMP,
  completed_at TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  -- Flexible metadata
  metadata_json JSONB DEFAULT '{}',
  UNIQUE (org_id, core_id)
);

CREATE INDEX idx_submissions_org_status ON submissions(org_id, status);
CREATE INDEX idx_submissions_org_created ON submissions(org_id, created_at DESC);
CREATE INDEX idx_submissions_workflow_state ON submissions(workflow_state);

CREATE TRIGGER update_submissions_timestamp
  BEFORE UPDATE ON submissions
  FOR EACH ROW EXECUTE FUNCTION update_timestamp();

CREATE TABLE submission_files (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  submission_id UUID NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
  file_name VARCHAR(500) NOT NULL,
  file_size_bytes BIGINT NOT NULL,
  sha256_checksum VARCHAR(64) NOT NULL,
  mime_type VARCHAR(100),
  storage_path VARCHAR(2048) NOT NULL,
  storage_backend VARCHAR(50) NOT NULL DEFAULT 's3',
  -- s3, local_fs, azure_blob, gcs
  upload_status VARCHAR(50) NOT NULL DEFAULT 'pending',
  -- pending, uploading, draft, submitted, acknowledged
  uploaded_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_submission_files_submission ON submission_files(submission_id);
CREATE INDEX idx_submission_files_status ON submission_files(upload_status);

CREATE TRIGGER update_submission_files_timestamp
  BEFORE UPDATE ON submission_files
  FOR EACH ROW EXECUTE FUNCTION update_timestamp();
