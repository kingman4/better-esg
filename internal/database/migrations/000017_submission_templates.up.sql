CREATE TABLE submission_templates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  fda_center VARCHAR(100),
  submission_type VARCHAR(100) NOT NULL,
  submission_protocol VARCHAR(50) NOT NULL DEFAULT 'API',
  default_file_count INTEGER NOT NULL DEFAULT 1,
  is_active BOOLEAN DEFAULT true,
  created_by UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_submission_templates_org ON submission_templates(org_id) WHERE is_active = true;

CREATE TRIGGER update_submission_templates_timestamp
  BEFORE UPDATE ON submission_templates
  FOR EACH ROW EXECUTE FUNCTION update_timestamp();
