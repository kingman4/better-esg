package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kingman4/better-esg/internal/repository"
)

// --- handleInitiateUpload tests ---

func TestInitiateUpload_MissingSubmissionID(t *testing.T) {
	s := stubServer()
	body, _ := json.Marshal(initiateUploadRequest{FileName: "test.xml", FileSizeBytes: 1000000})
	req := httptest.NewRequest("POST", "/api/v1/submissions//uploads", bytes.NewReader(body))
	// Don't set path value — tests empty id check
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleInitiateUpload(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleUploadChunk tests ---

func TestUploadChunk_InvalidChunkIndex(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("PUT", "/api/v1/submissions/sub-1/uploads/up-1/chunks/abc", bytes.NewReader([]byte("data")))
	req.SetPathValue("id", "sub-1")
	req.SetPathValue("uploadId", "up-1")
	req.SetPathValue("index", "abc")
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleUploadChunk(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "invalid chunk index" {
		t.Errorf("unexpected error: %q", resp["error"])
	}
}

func TestUploadChunk_NegativeIndex(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("PUT", "/api/v1/submissions/sub-1/uploads/up-1/chunks/-1", bytes.NewReader([]byte("data")))
	req.SetPathValue("id", "sub-1")
	req.SetPathValue("uploadId", "up-1")
	req.SetPathValue("index", "-1")
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleUploadChunk(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestUploadChunk_MissingPathParams(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("PUT", "/api/v1/submissions/sub-1/uploads/up-1/chunks/0", bytes.NewReader([]byte("data")))
	// Don't set any path values
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleUploadChunk(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleGetUploadProgress tests ---

func TestGetUploadProgress_MissingParams(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("GET", "/api/v1/submissions/sub-1/uploads/up-1", nil)
	// Don't set path values
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleGetUploadProgress(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestGetUploadProgress_MissingUploadId(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("GET", "/api/v1/submissions/sub-1/uploads/", nil)
	req.SetPathValue("id", "sub-1")
	// uploadId not set
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleGetUploadProgress(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- handleCompleteUpload tests ---

func TestCompleteUpload_MissingParams(t *testing.T) {
	s := stubServer()
	req := httptest.NewRequest("POST", "/api/v1/submissions/sub-1/uploads/up-1/complete", nil)
	// Don't set path values
	ctx := withAuthContext(req.Context(), "org-1", "user-1", "admin")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleCompleteUpload(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- validateChunks tests ---

func TestValidateChunks_AllPresent(t *testing.T) {
	session := &repository.UploadSession{
		FileSizeBytes: 15000000,
		TotalChunks:   3,
	}
	chunks := []repository.UploadChunk{
		{ChunkIndex: 0, ChunkSizeBytes: 5000000},
		{ChunkIndex: 1, ChunkSizeBytes: 5000000},
		{ChunkIndex: 2, ChunkSizeBytes: 5000000},
	}

	if err := validateChunks(session, chunks); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestValidateChunks_MissingChunk(t *testing.T) {
	session := &repository.UploadSession{
		FileSizeBytes: 15000000,
		TotalChunks:   3,
	}
	chunks := []repository.UploadChunk{
		{ChunkIndex: 0, ChunkSizeBytes: 5000000},
		{ChunkIndex: 2, ChunkSizeBytes: 5000000},
	}

	err := validateChunks(session, chunks)
	if err == nil {
		t.Error("expected error for missing chunk")
	}
}

func TestValidateChunks_WrongTotalSize(t *testing.T) {
	session := &repository.UploadSession{
		FileSizeBytes: 15000000,
		TotalChunks:   3,
	}
	chunks := []repository.UploadChunk{
		{ChunkIndex: 0, ChunkSizeBytes: 5000000},
		{ChunkIndex: 1, ChunkSizeBytes: 5000000},
		{ChunkIndex: 2, ChunkSizeBytes: 4000000}, // short
	}

	err := validateChunks(session, chunks)
	if err == nil {
		t.Error("expected error for size mismatch")
	}
}

func TestValidateChunks_DuplicateIndex(t *testing.T) {
	session := &repository.UploadSession{
		FileSizeBytes: 10000000,
		TotalChunks:   2,
	}
	chunks := []repository.UploadChunk{
		{ChunkIndex: 0, ChunkSizeBytes: 5000000},
		{ChunkIndex: 0, ChunkSizeBytes: 5000000}, // duplicate
	}

	err := validateChunks(session, chunks)
	if err == nil {
		t.Error("expected error for duplicate/missing chunk")
	}
}

func TestValidateChunks_LastChunkSmaller(t *testing.T) {
	// File is 12MB, chunks are 5MB each: 5+5+2 = 12
	session := &repository.UploadSession{
		FileSizeBytes: 12000000,
		TotalChunks:   3,
	}
	chunks := []repository.UploadChunk{
		{ChunkIndex: 0, ChunkSizeBytes: 5000000},
		{ChunkIndex: 1, ChunkSizeBytes: 5000000},
		{ChunkIndex: 2, ChunkSizeBytes: 2000000},
	}

	if err := validateChunks(session, chunks); err != nil {
		t.Errorf("expected no error for valid last chunk, got %v", err)
	}
}

// --- Total chunks calculation ---

func TestTotalChunksCalculation(t *testing.T) {
	tests := []struct {
		fileSize  int64
		chunkSize int
		expected  int
	}{
		{10000000, 5000000, 2},   // exactly 2 chunks
		{10000001, 5000000, 3},   // 2 full + 1 partial
		{5000000, 5000000, 1},    // exactly 1 chunk
		{1, 1048576, 1},          // tiny file, 1 chunk
		{12000000, 5000000, 3},   // 5+5+2
	}

	for _, tt := range tests {
		totalChunks := int((tt.fileSize + int64(tt.chunkSize) - 1) / int64(tt.chunkSize))
		if totalChunks != tt.expected {
			t.Errorf("file=%d chunk=%d: expected %d chunks, got %d",
				tt.fileSize, tt.chunkSize, tt.expected, totalChunks)
		}
	}
}
