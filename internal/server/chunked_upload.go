package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/kingman4/better-esg/internal/repository"
	"github.com/kingman4/better-esg/internal/storage"
)

const (
	minChunkSize = 1 << 20           // 1 MB
	maxFileSize  = 1 << 40           // 1 TB
	defaultChunk = 5 * (1 << 20)     // 5 MB
)

// --- Request / Response types ---

type initiateUploadRequest struct {
	FileName       string `json:"file_name"`
	FileSizeBytes  int64  `json:"file_size_bytes"`
	ChunkSizeBytes int    `json:"chunk_size_bytes"`
}

type initiateUploadResponse struct {
	UploadID       string `json:"upload_id"`
	ChunkSizeBytes int    `json:"chunk_size_bytes"`
	TotalChunks    int    `json:"total_chunks"`
}

type chunkResponse struct {
	ChunkIndex int    `json:"chunk_index"`
	SizeBytes  int64  `json:"size_bytes"`
	SHA256     string `json:"sha256"`
}

type uploadProgressResponse struct {
	UploadID       string `json:"upload_id"`
	FileName       string `json:"file_name"`
	FileSizeBytes  int64  `json:"file_size_bytes"`
	TotalChunks    int    `json:"total_chunks"`
	ChunksReceived []int  `json:"chunks_received"`
	Status         string `json:"status"`
}

// --- Handlers ---

// handleInitiateUpload handles POST /api/v1/submissions/{id}/uploads.
// Creates a new chunked upload session for a file.
func (s *Server) handleInitiateUpload(w http.ResponseWriter, r *http.Request) {
	subID := r.PathValue("id")
	if subID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing submission id"})
		return
	}

	orgID := orgIDFromContext(r.Context())

	sub, err := s.submissions.GetByID(r.Context(), orgID, subID)
	if err != nil {
		s.logger.Error("failed to get submission", "submission_id", subID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get submission"})
		return
	}
	if sub == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "submission not found"})
		return
	}

	if sub.Status != "payload_obtained" && sub.Status != "file_uploaded" {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "submission must be in payload_obtained or file_uploaded status (current: " + sub.Status + ")",
		})
		return
	}

	// Check file count limit
	totalFiles, _, err := s.files.CountBySubmission(r.Context(), subID)
	if err != nil {
		s.logger.Error("failed to count files", "submission_id", subID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to check file count"})
		return
	}
	if totalFiles >= sub.FileCount {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": fmt.Sprintf("all %d files already uploaded", sub.FileCount),
		})
		return
	}

	var req initiateUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	if req.FileName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file_name is required"})
		return
	}
	if req.FileSizeBytes <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file_size_bytes must be positive"})
		return
	}
	if req.FileSizeBytes > maxFileSize {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("file_size_bytes exceeds maximum (%d bytes)", maxFileSize),
		})
		return
	}

	chunkSize := req.ChunkSizeBytes
	if chunkSize == 0 {
		chunkSize = defaultChunk
	}
	if chunkSize < minChunkSize {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("chunk_size_bytes must be at least %d (1 MB)", minChunkSize),
		})
		return
	}
	if int64(chunkSize) > req.FileSizeBytes {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "chunk_size_bytes must not exceed file_size_bytes",
		})
		return
	}

	totalChunks := int((req.FileSizeBytes + int64(chunkSize) - 1) / int64(chunkSize))

	session, err := s.uploadSessions.Create(r.Context(), subID, req.FileName, req.FileSizeBytes, chunkSize, totalChunks)
	if err != nil {
		s.logger.Error("failed to create upload session", "submission_id", subID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create upload session"})
		return
	}

	s.audit(r, "initiate_chunked_upload", "upload_session", session.ID, map[string]any{
		"submission_id":    subID,
		"file_name":        req.FileName,
		"file_size_bytes":  req.FileSizeBytes,
		"chunk_size_bytes": chunkSize,
		"total_chunks":     totalChunks,
	})

	writeJSON(w, http.StatusOK, initiateUploadResponse{
		UploadID:       session.ID,
		ChunkSizeBytes: chunkSize,
		TotalChunks:    totalChunks,
	})
}

// handleUploadChunk handles PUT /api/v1/submissions/{id}/uploads/{uploadId}/chunks/{index}.
// Accepts raw binary body for a single chunk.
func (s *Server) handleUploadChunk(w http.ResponseWriter, r *http.Request) {
	subID := r.PathValue("id")
	uploadID := r.PathValue("uploadId")
	indexStr := r.PathValue("index")

	if subID == "" || uploadID == "" || indexStr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing path parameters"})
		return
	}

	chunkIndex, err := strconv.Atoi(indexStr)
	if err != nil || chunkIndex < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid chunk index"})
		return
	}

	session, err := s.uploadSessions.GetByID(r.Context(), uploadID)
	if err != nil {
		s.logger.Error("failed to get upload session", "upload_id", uploadID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get upload session"})
		return
	}
	if session == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "upload session not found"})
		return
	}
	if session.SubmissionID != subID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "upload session not found"})
		return
	}
	if session.Status != "uploading" {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "upload session is not in uploading status (current: " + session.Status + ")",
		})
		return
	}
	if chunkIndex >= session.TotalChunks {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("chunk index %d out of range [0, %d)", chunkIndex, session.TotalChunks),
		})
		return
	}

	// Save chunk to storage with SHA-256 computation
	storageKey := fmt.Sprintf("%s/.chunks/%s/%d", subID, uploadID, chunkIndex)
	hasher := sha256.New()
	written, err := s.storage.Save(r.Context(), storageKey, io.TeeReader(r.Body, hasher))
	if err != nil {
		s.logger.Error("failed to save chunk", "key", storageKey, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save chunk"})
		return
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))

	// Record in DB (upsert for idempotency)
	_, err = s.uploadSessions.RecordChunk(r.Context(), uploadID, chunkIndex, written, checksum, storageKey)
	if err != nil {
		s.logger.Error("failed to record chunk", "upload_id", uploadID, "chunk_index", chunkIndex, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to record chunk"})
		return
	}

	writeJSON(w, http.StatusOK, chunkResponse{
		ChunkIndex: chunkIndex,
		SizeBytes:  written,
		SHA256:     checksum,
	})
}

// handleGetUploadProgress handles GET /api/v1/submissions/{id}/uploads/{uploadId}.
// Returns which chunks have been received for resume support.
func (s *Server) handleGetUploadProgress(w http.ResponseWriter, r *http.Request) {
	subID := r.PathValue("id")
	uploadID := r.PathValue("uploadId")

	if subID == "" || uploadID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing path parameters"})
		return
	}

	session, err := s.uploadSessions.GetByID(r.Context(), uploadID)
	if err != nil {
		s.logger.Error("failed to get upload session", "upload_id", uploadID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get upload session"})
		return
	}
	if session == nil || session.SubmissionID != subID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "upload session not found"})
		return
	}

	chunks, err := s.uploadSessions.ListChunks(r.Context(), uploadID)
	if err != nil {
		s.logger.Error("failed to list chunks", "upload_id", uploadID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list chunks"})
		return
	}

	received := make([]int, 0, len(chunks))
	for _, c := range chunks {
		received = append(received, c.ChunkIndex)
	}

	writeJSON(w, http.StatusOK, uploadProgressResponse{
		UploadID:       session.ID,
		FileName:       session.FileName,
		FileSizeBytes:  session.FileSizeBytes,
		TotalChunks:    session.TotalChunks,
		ChunksReceived: received,
		Status:         session.Status,
	})
}

// handleCompleteUpload handles POST /api/v1/submissions/{id}/uploads/{uploadId}/complete.
// Reassembles chunks, verifies integrity, creates submission_files record, and uploads to FDA.
func (s *Server) handleCompleteUpload(w http.ResponseWriter, r *http.Request) {
	subID := r.PathValue("id")
	uploadID := r.PathValue("uploadId")

	if subID == "" || uploadID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing path parameters"})
		return
	}

	orgID := orgIDFromContext(r.Context())

	sub, err := s.submissions.GetByID(r.Context(), orgID, subID)
	if err != nil {
		s.logger.Error("failed to get submission", "submission_id", subID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get submission"})
		return
	}
	if sub == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "submission not found"})
		return
	}

	if sub.Status != "payload_obtained" && sub.Status != "file_uploaded" {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "submission must be in payload_obtained or file_uploaded status (current: " + sub.Status + ")",
		})
		return
	}

	if !sub.PayloadID.Valid {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "submission has no payload_id"})
		return
	}

	session, err := s.uploadSessions.GetByID(r.Context(), uploadID)
	if err != nil {
		s.logger.Error("failed to get upload session", "upload_id", uploadID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get upload session"})
		return
	}
	if session == nil || session.SubmissionID != subID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "upload session not found"})
		return
	}
	if session.Status != "uploading" {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "upload session is not in uploading status (current: " + session.Status + ")",
		})
		return
	}

	chunks, err := s.uploadSessions.ListChunks(r.Context(), uploadID)
	if err != nil {
		s.logger.Error("failed to list chunks", "upload_id", uploadID, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list chunks"})
		return
	}

	// Validate completeness
	if err := validateChunks(session, chunks); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Reassemble chunks into final file
	finalKey := subID + "/" + session.FileName
	written, checksum, err := s.reassembleChunks(r.Context(), subID, uploadID, session, chunks, finalKey)
	if err != nil {
		s.logger.Error("chunk reassembly failed", "upload_id", uploadID, "error", err)
		s.uploadSessions.UpdateStatus(r.Context(), uploadID, "failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "chunk reassembly failed"})
		return
	}

	// Record as submission_files entry
	fileRecord, err := s.files.Create(r.Context(), repository.CreateFileParams{
		SubmissionID:   subID,
		FileName:       session.FileName,
		FileSizeBytes:  written,
		SHA256Checksum: checksum,
		MimeType:       "application/octet-stream",
		StoragePath:    finalKey,
		StorageBackend: "chunked_upload",
	})
	if err != nil {
		s.logger.Error("failed to record file", "submission_id", subID, "error", err)
		s.uploadSessions.UpdateStatus(r.Context(), uploadID, "failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to record file"})
		return
	}

	// Stream to FDA
	fdaFile, err := s.storage.Open(r.Context(), finalKey)
	if err != nil {
		s.logger.Error("failed to open reassembled file", "key", finalKey, "error", err)
		s.files.UpdateStatus(r.Context(), fileRecord.ID, "failed")
		s.uploadSessions.UpdateStatus(r.Context(), uploadID, "failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read file for FDA upload"})
		return
	}
	defer fdaFile.Close()

	_, fdaErr := s.fda.UploadFile(r.Context(), sub.PayloadID.String, session.FileName, fdaFile, written)
	if fdaErr != nil {
		s.logger.Error("FDA file upload failed", "file_name", session.FileName, "submission_id", subID, "error", fdaErr)
		s.files.UpdateStatus(r.Context(), fileRecord.ID, "failed")
		s.uploadSessions.UpdateStatus(r.Context(), uploadID, "failed")
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": "FDA file upload failed: " + sanitizeError(fdaErr),
		})
		return
	}

	// Success — mark everything as complete
	s.files.UpdateStatus(r.Context(), fileRecord.ID, "uploaded")
	s.uploadSessions.UpdateStatus(r.Context(), uploadID, "completed")

	// Transition submission state on first file upload
	if sub.Status == "payload_obtained" {
		userID := userIDFromContext(r.Context())
		s.transitionState(r.Context(), subID, sub.WorkflowState, "file_uploaded", "FILES_UPLOADING", &userID, "")
	}

	// Best-effort cleanup of chunk files
	s.cleanupChunks(r.Context(), subID, uploadID, chunks)

	s.audit(r, "complete_chunked_upload", "file", fileRecord.ID, map[string]any{
		"submission_id": subID,
		"upload_id":     uploadID,
		"file_name":     session.FileName,
		"size_bytes":    written,
		"sha256":        checksum,
		"total_chunks":  session.TotalChunks,
	})

	writeJSON(w, http.StatusOK, uploadFileResponse{
		FileID:         fileRecord.ID,
		FileName:       session.FileName,
		FileSizeBytes:  written,
		SHA256Checksum: checksum,
		UploadStatus:   "uploaded",
	})
}

// --- Reassembly ---

// validateChunks checks that all expected chunks are present and sizes add up.
func validateChunks(session *repository.UploadSession, chunks []repository.UploadChunk) error {
	if len(chunks) != session.TotalChunks {
		return fmt.Errorf("expected %d chunks, got %d", session.TotalChunks, len(chunks))
	}

	// Verify contiguous indices and sum sizes
	present := make(map[int]bool, len(chunks))
	var totalSize int64
	for _, c := range chunks {
		present[c.ChunkIndex] = true
		totalSize += c.ChunkSizeBytes
	}
	for i := 0; i < session.TotalChunks; i++ {
		if !present[i] {
			return fmt.Errorf("missing chunk %d", i)
		}
	}

	if totalSize != session.FileSizeBytes {
		return fmt.Errorf("chunk sizes total %d bytes, expected %d", totalSize, session.FileSizeBytes)
	}

	return nil
}

// reassembleChunks reads chunks in order from storage, saves as a single file,
// and computes the SHA-256 checksum during the write.
func (s *Server) reassembleChunks(ctx context.Context, subID, uploadID string, session *repository.UploadSession, chunks []repository.UploadChunk, finalKey string) (int64, string, error) {
	reader := &multiChunkReader{
		ctx:      ctx,
		store:    s.storage,
		subID:    subID,
		uploadID: uploadID,
		total:    session.TotalChunks,
	}

	hasher := sha256.New()
	written, err := s.storage.Save(ctx, finalKey, io.TeeReader(reader, hasher))
	if err != nil {
		// Close any open chunk handle on error
		reader.closeCurrentChunk()
		return 0, "", fmt.Errorf("saving reassembled file: %w", err)
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))
	return written, checksum, nil
}

// multiChunkReader implements io.Reader by reading chunks sequentially from storage.
// Opens one chunk at a time, reads it fully, closes it, then moves to the next.
type multiChunkReader struct {
	ctx      context.Context
	store    storage.Store
	subID    string
	uploadID string
	total    int
	current  int
	reader   storage.ReadSeekCloser
}

func (m *multiChunkReader) Read(p []byte) (int, error) {
	for {
		// If we've read all chunks, signal EOF
		if m.current >= m.total && m.reader == nil {
			return 0, io.EOF
		}

		// Open next chunk if needed
		if m.reader == nil {
			key := fmt.Sprintf("%s/.chunks/%s/%d", m.subID, m.uploadID, m.current)
			r, err := m.store.Open(m.ctx, key)
			if err != nil {
				return 0, fmt.Errorf("opening chunk %d: %w", m.current, err)
			}
			m.reader = r
		}

		n, err := m.reader.Read(p)
		if err == io.EOF {
			// This chunk is done — close and advance
			m.reader.Close()
			m.reader = nil
			m.current++
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (m *multiChunkReader) closeCurrentChunk() {
	if m.reader != nil {
		m.reader.Close()
		m.reader = nil
	}
}

// cleanupChunks deletes chunk files from storage. Best-effort — errors are logged.
func (s *Server) cleanupChunks(ctx context.Context, subID, uploadID string, chunks []repository.UploadChunk) {
	for _, c := range chunks {
		key := fmt.Sprintf("%s/.chunks/%s/%d", subID, uploadID, c.ChunkIndex)
		if err := s.storage.Delete(ctx, key); err != nil {
			s.logger.Warn("failed to delete chunk file", "key", key, "error", err)
		}
	}
}
