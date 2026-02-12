-- API keys for authenticating API requests.
-- Raw keys are never stored — only their SHA-256 hash.
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash VARCHAR(64) NOT NULL UNIQUE,      -- SHA-256 hex digest of the raw key
    key_prefix VARCHAR(12) NOT NULL,            -- first 8 chars of raw key for identification
    name VARCHAR(255) NOT NULL DEFAULT 'default',
    role VARCHAR(50) NOT NULL DEFAULT 'submitter',
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_api_keys_hash_active ON api_keys(key_hash) WHERE is_active = true;
CREATE INDEX idx_api_keys_org ON api_keys(org_id);
CREATE INDEX idx_api_keys_user ON api_keys(user_id);
