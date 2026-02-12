package server

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"github.com/kingman4/better-esg/internal/database"
	"github.com/kingman4/better-esg/internal/fdaclient"
	"github.com/kingman4/better-esg/internal/repository"
	_ "github.com/lib/pq"
)

// Server is the HTTP server that handles API requests.
type Server struct {
	db          *sql.DB
	router      *http.ServeMux
	submissions *repository.SubmissionRepo
	files       *repository.SubmissionFileRepo
	apiKeys     *repository.APIKeyRepo
	fda         *fdaclient.Client
}

// Config holds the parameters needed to create a Server.
type Config struct {
	DatabaseURL        string
	FDAExternalBaseURL string
	FDAUploadBaseURL   string
	FDAClientID        string
	FDAClientSecret    string
	FDAEnvironment     string // "prod" or "test"
	EncryptionKey      []byte // 32 bytes for AES-256-GCM
}

// New creates a new Server, runs migrations, and sets up routes.
func New(cfg Config) (*Server, error) {
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	if err := database.RunMigrations(db); err != nil {
		return nil, err
	}

	fdaEnv := fdaclient.EnvTest
	if cfg.FDAEnvironment == "prod" {
		fdaEnv = fdaclient.EnvProd
	}

	s := &Server{
		db:          db,
		router:      http.NewServeMux(),
		submissions: repository.NewSubmissionRepo(db, cfg.EncryptionKey),
		files:       repository.NewSubmissionFileRepo(db),
		apiKeys:     repository.NewAPIKeyRepo(db),
		fda: fdaclient.New(fdaclient.Config{
			ExternalBaseURL: cfg.FDAExternalBaseURL,
			UploadBaseURL:   cfg.FDAUploadBaseURL,
			ClientID:        cfg.FDAClientID,
			ClientSecret:    cfg.FDAClientSecret,
			Environment:     fdaEnv,
		}),
	}
	s.routes()
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) Close() error {
	return s.db.Close()
}

func (s *Server) routes() {
	// Public endpoints
	s.router.HandleFunc("GET /health", s.handleHealth)

	// Authenticated API endpoints
	s.router.HandleFunc("POST /api/v1/submissions", s.withAuth(s.handleCreateSubmission))
	s.router.HandleFunc("GET /api/v1/submissions/{id}", s.withAuth(s.handleGetSubmission))
	s.router.HandleFunc("GET /api/v1/submissions", s.withAuth(s.handleListSubmissions))
	s.router.HandleFunc("POST /api/v1/submissions/{id}/submit", s.withAuth(s.handleSubmitToFDA))
	s.router.HandleFunc("POST /api/v1/submissions/{id}/files", s.withAuth(s.handleUploadFile))
	s.router.HandleFunc("POST /api/v1/submissions/{id}/finalize", s.withAuth(s.handleFinalizeSubmission))
	s.router.HandleFunc("GET /api/v1/submissions/{id}/status", s.withAuth(s.handleGetStatus))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	dbStatus := "ok"
	if err := s.db.Ping(); err != nil {
		dbStatus = err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "ok",
		"database": dbStatus,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("error encoding response: %v", err)
	}
}
