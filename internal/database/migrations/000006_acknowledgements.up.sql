CREATE TABLE acknowledgements (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  submission_id UUID NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
  ack_type VARCHAR(10) NOT NULL,
  -- ACK1 (upload received), ACK2 (submitted to center), ACK3 (center validation file)
  status VARCHAR(50) NOT NULL,
  -- Upload Received, Submitted to Center, etc.
  raw_message TEXT,
  parsed_data_json JSONB,
  file_storage_path VARCHAR(2048),
  esgng_code VARCHAR(20),
  created_by_fda VARCHAR(100),
  received_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_acknowledgements_submission ON acknowledgements(submission_id);
CREATE INDEX idx_acknowledgements_type ON acknowledgements(ack_type);
CREATE INDEX idx_acknowledgements_status ON acknowledgements(status);
