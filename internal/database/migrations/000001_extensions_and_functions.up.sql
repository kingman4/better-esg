-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Utility function: auto-update updated_at timestamp on row modification
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
