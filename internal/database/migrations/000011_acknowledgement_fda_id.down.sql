DROP INDEX IF EXISTS idx_ack_fda_id;
ALTER TABLE acknowledgements DROP COLUMN IF EXISTS fda_ack_id;
