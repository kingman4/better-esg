-- Org-scoped webhook subscriptions for event notifications.
-- Replaces the user-scoped notification_preferences table (000008) with
-- a multi-tenant design that supports multiple webhooks per organization.

CREATE TABLE webhooks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  url VARCHAR(2048) NOT NULL,
  secret VARCHAR(255) NOT NULL,
  events JSONB NOT NULL DEFAULT '[]',
  is_active BOOLEAN DEFAULT true,
  description TEXT,
  created_by UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_webhooks_org_active ON webhooks(org_id) WHERE is_active = true;

CREATE TRIGGER update_webhooks_timestamp
  BEFORE UPDATE ON webhooks
  FOR EACH ROW EXECUTE FUNCTION update_timestamp();

-- Delivery log for debugging and retry tracking.
CREATE TABLE webhook_deliveries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_id UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  event_type VARCHAR(50) NOT NULL,
  payload JSONB NOT NULL,
  status_code INTEGER,
  response_body TEXT,
  error TEXT,
  attempt INTEGER NOT NULL DEFAULT 1,
  delivered_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);
