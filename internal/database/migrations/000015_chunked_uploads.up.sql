CREATE TABLE upload_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
    file_name VARCHAR(500) NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    chunk_size_bytes INT NOT NULL DEFAULT 5242880,
    total_chunks INT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'uploading',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE upload_chunks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    upload_session_id UUID NOT NULL REFERENCES upload_sessions(id) ON DELETE CASCADE,
    chunk_index INT NOT NULL,
    chunk_size_bytes BIGINT NOT NULL,
    sha256_checksum VARCHAR(64) NOT NULL,
    storage_path VARCHAR(2048) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(upload_session_id, chunk_index)
);

CREATE INDEX idx_upload_sessions_submission ON upload_sessions(submission_id);
CREATE INDEX idx_upload_chunks_session ON upload_chunks(upload_session_id);

CREATE TRIGGER update_upload_sessions_timestamp
    BEFORE UPDATE ON upload_sessions
    FOR EACH ROW EXECUTE FUNCTION update_timestamp();
