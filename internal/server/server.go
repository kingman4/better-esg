package server

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"github.com/kingman4/better-esg/internal/database"
	"github.com/kingman4/better-esg/internal/repository"
	_ "github.com/lib/pq"
)

// Server is the HTTP server that handles API requests.
type Server struct {
	db          *sql.DB
	router      *http.ServeMux
	submissions *repository.SubmissionRepo
}

// New creates a new Server, runs migrations, and sets up routes.
func New(databaseURL string) (*Server, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	if err := database.RunMigrations(db); err != nil {
		return nil, err
	}

	s := &Server{
		db:          db,
		router:      http.NewServeMux(),
		submissions: repository.NewSubmissionRepo(db),
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
	s.router.HandleFunc("GET /health", s.handleHealth)
	s.router.HandleFunc("POST /api/v1/submissions", s.handleCreateSubmission)
	s.router.HandleFunc("GET /api/v1/submissions/{id}", s.handleGetSubmission)
	s.router.HandleFunc("GET /api/v1/submissions", s.handleListSubmissions)
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
