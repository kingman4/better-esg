-- Add FDA acknowledgement ID column for deduplication during background polling.
-- Partial unique index: only enforced when fda_ack_id is set (existing rows may be NULL).
ALTER TABLE acknowledgements ADD COLUMN fda_ack_id VARCHAR(255);
CREATE UNIQUE INDEX idx_ack_fda_id ON acknowledgements(fda_ack_id) WHERE fda_ack_id IS NOT NULL;
