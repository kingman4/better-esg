CREATE TABLE fda_credentials (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  -- Encrypted fields (AES-256-GCM, stored as base64)
  client_id_encrypted VARCHAR(512) NOT NULL,
  secret_key_encrypted VARCHAR(512) NOT NULL,
  encryption_key_id VARCHAR(100) NOT NULL,
  -- Metadata
  environment VARCHAR(20) NOT NULL DEFAULT 'prod',
  is_active BOOLEAN DEFAULT true,
  created_by UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  rotated_at TIMESTAMP,
  UNIQUE (org_id, environment)
);

CREATE INDEX idx_fda_credentials_org_active ON fda_credentials(org_id, is_active);
