package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

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
	users       *repository.UserRepo
	acks        *repository.AckRepo
	workflowLog *repository.WorkflowLogRepo
	auditLog    *repository.AuditLogRepo
	webhooks    *repository.WebhookRepo
	deliveries  *repository.WebhookDeliveryRepo
	logger      *slog.Logger
	fda          *fdaclient.Client
	fdaUserEmail string // for auto-resolving user_id + company_id via GetCompanyInfo

	// When true, API key auth is skipped and a default org/user is used.
	authDisabled bool
	defaultOrgID string
	defaultUserID string

	pollerCancel context.CancelFunc
}

// Config holds the parameters needed to create a Server.
type Config struct {
	DatabaseURL        string
	FDAExternalBaseURL string
	FDAUploadBaseURL   string
	FDAClientID        string
	FDAClientSecret    string
	FDAEnvironment     string        // "prod" or "test"
	FDAUserEmail       string        // email for auto-resolving user_id + company_id
	EncryptionKey      []byte        // 32 bytes for AES-256-GCM
	StatusPollInterval time.Duration // how often to poll FDA for in-flight submissions (0 = disabled)
	Logger             *slog.Logger  // structured logger (nil = slog.Default())
	AuthDisabled       bool          // when true, skip API key auth and use a default org/user
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

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		db:          db,
		router:      http.NewServeMux(),
		submissions: repository.NewSubmissionRepo(db, cfg.EncryptionKey),
		files:       repository.NewSubmissionFileRepo(db),
		apiKeys:     repository.NewAPIKeyRepo(db),
		users:       repository.NewUserRepo(db),
		acks:        repository.NewAckRepo(db),
		workflowLog: repository.NewWorkflowLogRepo(db),
		auditLog:    repository.NewAuditLogRepo(db),
		webhooks:    repository.NewWebhookRepo(db),
		deliveries:  repository.NewWebhookDeliveryRepo(db),
		fda: fdaclient.New(fdaclient.Config{
			ExternalBaseURL: cfg.FDAExternalBaseURL,
			UploadBaseURL:   cfg.FDAUploadBaseURL,
			ClientID:        cfg.FDAClientID,
			ClientSecret:    cfg.FDAClientSecret,
			Environment:     fdaEnv,
		}),
		fdaUserEmail: cfg.FDAUserEmail,
		logger:       logger,
	}
	if cfg.AuthDisabled {
		if err := s.initDefaultOrgUser(); err != nil {
			return nil, fmt.Errorf("initializing default org/user: %w", err)
		}
		s.logger.Info("auth disabled, using default org/user")
	}
	s.routes()

	if cfg.StatusPollInterval > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		s.pollerCancel = cancel
		s.startStatusPoller(ctx, cfg.StatusPollInterval)
	}

	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) Close() error {
	s.stopStatusPoller()
	return s.db.Close()
}

func (s *Server) routes() {
	// Public endpoints
	s.router.HandleFunc("GET /health", s.handleHealth)

	// Submissions — write: admin + submitter, read: all authenticated roles
	s.router.HandleFunc("POST /api/v1/submissions", s.withAuth(s.canWrite(s.handleCreateSubmission)))
	s.router.HandleFunc("GET /api/v1/submissions/{id}", s.withAuth(s.handleGetSubmission))
	s.router.HandleFunc("GET /api/v1/submissions", s.withAuth(s.handleListSubmissions))
	s.router.HandleFunc("POST /api/v1/submissions/{id}/submit", s.withAuth(s.canWrite(s.handleSubmitToFDA)))
	s.router.HandleFunc("POST /api/v1/submissions/{id}/files", s.withAuth(s.canWrite(s.handleUploadFile)))
	s.router.HandleFunc("POST /api/v1/submissions/{id}/finalize", s.withAuth(s.canWrite(s.handleFinalizeSubmission)))
	s.router.HandleFunc("GET /api/v1/submissions/{id}/status", s.withAuth(s.handleGetStatus))
	s.router.HandleFunc("GET /api/v1/submissions/{id}/acknowledgements", s.withAuth(s.handleListAcknowledgements))

	// Webhooks — write/delete/test: admin only, read: all authenticated roles
	s.router.HandleFunc("POST /api/v1/webhooks", s.withAuth(s.adminOnly(s.handleCreateWebhook)))
	s.router.HandleFunc("GET /api/v1/webhooks", s.withAuth(s.handleListWebhooks))
	s.router.HandleFunc("GET /api/v1/webhooks/{id}", s.withAuth(s.handleGetWebhook))
	s.router.HandleFunc("DELETE /api/v1/webhooks/{id}", s.withAuth(s.adminOnly(s.handleDeleteWebhook)))
	s.router.HandleFunc("POST /api/v1/webhooks/{id}/test", s.withAuth(s.adminOnly(s.handleTestWebhook)))

	// Audit logs — admin + reviewer only
	s.router.HandleFunc("GET /api/v1/audit-logs", s.withAuth(s.requireRole(s.handleListAuditLogs, "admin", "reviewer")))

	// User management — admin only
	s.router.HandleFunc("POST /api/v1/users", s.withAuth(s.adminOnly(s.handleCreateUser)))
	s.router.HandleFunc("GET /api/v1/users", s.withAuth(s.adminOnly(s.handleListUsers)))
	s.router.HandleFunc("GET /api/v1/users/{id}", s.withAuth(s.adminOnly(s.handleGetUser)))
	s.router.HandleFunc("PATCH /api/v1/users/{id}", s.withAuth(s.adminOnly(s.handleUpdateUser)))
	s.router.HandleFunc("DELETE /api/v1/users/{id}", s.withAuth(s.adminOnly(s.handleDeleteUser)))

	// API key management — admin only
	s.router.HandleFunc("POST /api/v1/api-keys", s.withAuth(s.adminOnly(s.handleCreateAPIKey)))
	s.router.HandleFunc("GET /api/v1/api-keys", s.withAuth(s.adminOnly(s.handleListAPIKeys)))
	s.router.HandleFunc("DELETE /api/v1/api-keys/{id}", s.withAuth(s.adminOnly(s.handleRevokeAPIKey)))
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

// initDefaultOrgUser ensures a default organization and user exist for
// auth-disabled mode. Stores their IDs on the server so withAuth can
// inject them into every request context.
func (s *Server) initDefaultOrgUser() error {
	ctx := context.Background()

	err := s.db.QueryRowContext(ctx,
		`INSERT INTO organizations (name, slug) VALUES ('Default', 'default')
		 ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`).Scan(&s.defaultOrgID)
	if err != nil {
		return fmt.Errorf("creating default organization: %w", err)
	}

	err = s.db.QueryRowContext(ctx,
		`INSERT INTO users (org_id, email, role) VALUES ($1, 'admin@localhost', 'admin')
		 ON CONFLICT (org_id, email) DO UPDATE SET role = EXCLUDED.role
		 RETURNING id`, s.defaultOrgID).Scan(&s.defaultUserID)
	if err != nil {
		return fmt.Errorf("creating default user: %w", err)
	}

	s.authDisabled = true
	return nil
}

// transitionState updates the submission's status/workflow_state and logs
// the transition to workflow_state_log. triggeredBy is nil for system actions (e.g. poller).
// Log failures are warned but don't fail the transition.
func (s *Server) transitionState(ctx context.Context, subID, fromWorkflow, newStatus, newWorkflow string, triggeredBy *string, errDetails string) error {
	if err := s.submissions.UpdateStatus(ctx, subID, newStatus, newWorkflow); err != nil {
		return err
	}
	if err := s.workflowLog.Insert(ctx, subID, fromWorkflow, newWorkflow, triggeredBy, errDetails); err != nil {
		s.logger.Warn("failed to log workflow transition",
			"from", fromWorkflow, "to", newWorkflow, "submission_id", subID, "error", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
	}
}
