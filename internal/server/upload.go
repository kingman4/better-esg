package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kingman4/better-esg/internal/fdaclient"
	"github.com/kingman4/better-esg/internal/repository"
)

// uploadFileResponse is the JSON response after uploading a file to a submission.
type uploadFileResponse struct {
	FileID         string `json:"file_id"`
	FileName       string `json:"file_name"`
	FileSizeBytes  int64  `json:"file_size_bytes"`
	SHA256Checksum string `json:"sha256_checksum"`
	UploadStatus   string `json:"upload_status"`
}

// finalizeResponse is the JSON response after finalizing a submission.
type finalizeResponse struct {
	SubmissionID  string `json:"submission_id"`
	CoreID        string `json:"core_id"`
	Status        string `json:"status"`
	WorkflowState string `json:"workflow_state"`
}

// handleUploadFile handles POST /api/v1/submissions/{id}/files.
// Accepts a multipart file upload, computes SHA-256, saves to temp storage,
// records in submission_files, and streams the file to FDA.
func (s *Server) handleUploadFile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing submission id"})
		return
	}

	orgID := orgIDFromContext(r.Context())

	// Look up the submission
	sub, err := s.submissions.GetByID(r.Context(), orgID, id)
	if err != nil {
		log.Printf("error getting submission %s: %v", id, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get submission"})
		return
	}
	if sub == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "submission not found"})
		return
	}

	// Must be in payload_obtained or file_uploaded state
	if sub.Status != "payload_obtained" && sub.Status != "file_uploaded" {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "submission must be in payload_obtained or file_uploaded status to upload files (current: " + sub.Status + ")",
		})
		return
	}

	if !sub.PayloadID.Valid {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "submission has no payload_id"})
		return
	}

	// Check file count limit
	totalFiles, _, err := s.files.CountBySubmission(r.Context(), id)
	if err != nil {
		log.Printf("error counting files for %s: %v", id, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to check file count"})
		return
	}
	if totalFiles >= sub.FileCount {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": fmt.Sprintf("all %d files already uploaded", sub.FileCount),
		})
		return
	}

	// Parse multipart — limit to 1GB per request
	if err := r.ParseMultipartForm(1 << 30); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid multipart form: " + err.Error()})
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing file field"})
		return
	}
	defer file.Close()

	// Save to temp directory and compute SHA-256 simultaneously
	tempDir := filepath.Join(os.TempDir(), "esg-uploads", id)
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		log.Printf("error creating temp dir for %s: %v", id, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create temp storage"})
		return
	}

	tempPath := filepath.Join(tempDir, header.Filename)
	tempFile, err := os.Create(tempPath)
	if err != nil {
		log.Printf("error creating temp file %s: %v", tempPath, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save file"})
		return
	}

	hasher := sha256.New()
	written, err := io.Copy(tempFile, io.TeeReader(file, hasher))
	tempFile.Close()
	if err != nil {
		os.Remove(tempPath)
		log.Printf("error writing temp file %s: %v", tempPath, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save file"})
		return
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))

	// Detect MIME type from Content-Type header of the part
	mimeType := header.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	// Record in DB
	fileRecord, err := s.files.Create(r.Context(), repository.CreateFileParams{
		SubmissionID:   id,
		FileName:       header.Filename,
		FileSizeBytes:  written,
		SHA256Checksum: checksum,
		MimeType:       mimeType,
		StoragePath:    tempPath,
		StorageBackend: "local_fs",
	})
	if err != nil {
		os.Remove(tempPath)
		log.Printf("error recording file for %s: %v", id, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to record file"})
		return
	}

	// Stream to FDA
	fdaFile, err := os.Open(tempPath)
	if err != nil {
		log.Printf("error reopening temp file %s: %v", tempPath, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read file for FDA upload"})
		return
	}
	defer fdaFile.Close()

	_, fdaErr := s.fda.UploadFile(r.Context(), sub.PayloadID.String, header.Filename, fdaFile)
	if fdaErr != nil {
		log.Printf("FDA upload failed for file %s on submission %s: %v", header.Filename, id, fdaErr)
		s.files.UpdateStatus(r.Context(), fileRecord.ID, "failed")
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": "FDA file upload failed: " + sanitizeError(fdaErr),
		})
		return
	}

	// Mark file as uploaded
	if err := s.files.UpdateStatus(r.Context(), fileRecord.ID, "uploaded"); err != nil {
		log.Printf("error updating file status for %s: %v", fileRecord.ID, err)
	}

	// Update submission status if this is the first file upload
	if sub.Status == "payload_obtained" {
		if err := s.submissions.UpdateStatus(r.Context(), id, "file_uploaded", "FILES_UPLOADING"); err != nil {
			log.Printf("error updating submission status for %s: %v", id, err)
		}
	}

	writeJSON(w, http.StatusOK, uploadFileResponse{
		FileID:         fileRecord.ID,
		FileName:       header.Filename,
		FileSizeBytes:  written,
		SHA256Checksum: checksum,
		UploadStatus:   "uploaded",
	})
}

// handleFinalizeSubmission handles POST /api/v1/submissions/{id}/finalize.
// Verifies all expected files are uploaded, then calls SubmitPayload on the FDA API.
func (s *Server) handleFinalizeSubmission(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing submission id"})
		return
	}

	orgID := orgIDFromContext(r.Context())

	sub, err := s.submissions.GetByID(r.Context(), orgID, id)
	if err != nil {
		log.Printf("error getting submission %s: %v", id, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get submission"})
		return
	}
	if sub == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "submission not found"})
		return
	}

	if sub.Status != "file_uploaded" {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "submission must be in file_uploaded status to finalize (current: " + sub.Status + ")",
		})
		return
	}

	// Verify all expected files are uploaded
	totalFiles, uploadedFiles, err := s.files.CountBySubmission(r.Context(), id)
	if err != nil {
		log.Printf("error counting files for %s: %v", id, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to verify files"})
		return
	}
	if totalFiles < sub.FileCount || uploadedFiles < sub.FileCount {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": fmt.Sprintf("expected %d files, got %d uploaded (%d total)", sub.FileCount, uploadedFiles, totalFiles),
		})
		return
	}

	// Load temp credentials
	creds, err := s.submissions.GetTempCredentials(r.Context(), id)
	if err != nil {
		log.Printf("error loading temp credentials for %s: %v", id, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to load credentials"})
		return
	}

	// Compute combined checksum from all file checksums
	files, err := s.files.ListBySubmission(r.Context(), id)
	if err != nil {
		log.Printf("error listing files for %s: %v", id, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list files"})
		return
	}

	checksum := computeCombinedChecksum(files)

	if err := s.submissions.UpdateStatus(r.Context(), id, "file_uploaded", "SUBMIT_PENDING"); err != nil {
		log.Printf("error updating status for %s: %v", id, err)
	}

	// Submit payload to FDA
	_, fdaErr := s.fda.SubmitPayload(r.Context(), sub.PayloadID.String, fdaclient.SubmitRequest{
		TempUser:       creds.TempUser,
		TempPassword:   creds.TempPassword,
		SHA256Checksum: checksum,
	})
	if fdaErr != nil {
		log.Printf("FDA submit failed for %s: %v", id, fdaErr)
		s.submissions.UpdateStatus(r.Context(), id, "failed", "SUBMIT_FAILED")
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": "FDA submission failed: " + sanitizeError(fdaErr),
		})
		return
	}

	if err := s.submissions.UpdateStatus(r.Context(), id, "submitted", "SUBMITTED"); err != nil {
		log.Printf("error updating final status for %s: %v", id, err)
	}

	writeJSON(w, http.StatusOK, finalizeResponse{
		SubmissionID:  id,
		CoreID:        sub.CoreID.String,
		Status:        "submitted",
		WorkflowState: "SUBMITTED",
	})
}

// computeCombinedChecksum computes a combined SHA-256 from individual file checksums.
// Files are sorted by name for deterministic results.
func computeCombinedChecksum(files []repository.SubmissionFile) string {
	if len(files) == 1 {
		return files[0].SHA256Checksum
	}

	// Sort by filename for deterministic ordering
	sort.Slice(files, func(i, j int) bool {
		return files[i].FileName < files[j].FileName
	})

	var checksums []string
	for _, f := range files {
		checksums = append(checksums, f.SHA256Checksum)
	}

	combined := sha256.Sum256([]byte(strings.Join(checksums, "")))
	return hex.EncodeToString(combined[:])
}
