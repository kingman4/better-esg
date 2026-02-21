-- Add last_polled_at to track when each submission was last polled by the background poller.
-- Used for exponential backoff: submissions that have been in-flight longer are polled less frequently.
ALTER TABLE submissions ADD COLUMN last_polled_at TIMESTAMP;
