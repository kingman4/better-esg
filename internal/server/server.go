package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/kingman4/better-esg/internal/auth"
	"github.com/kingman4/better-esg/internal/database"
	"github.com/kingman4/better-esg/internal/fdaclient"
	"github.com/kingman4/better-esg/internal/repository"
	"github.com/kingman4/better-esg/internal/storage"
	_ "github.com/lib/pq"
)

// Server is the HTTP server that handles API requests.
type Server struct {
	db            *sql.DB
	router        *http.ServeMux
	submissions   *repository.SubmissionRepo
	files         *repository.SubmissionFileRepo
	apiKeys       *repository.APIKeyRepo
	users         *repository.UserRepo
	orgs          *repository.OrgRepo
	refreshTokens *repository.RefreshTokenRepo
	acks          *repository.AckRepo
	workflowLog   *repository.WorkflowLogRepo
	auditLog      *repository.AuditLogRepo
	webhooks      *repository.WebhookRepo
	deliveries        *repository.WebhookDeliveryRepo
	uploadSessions    *repository.UploadSessionRepo
	backupCodes       *repository.BackupCodeRepo
	notificationPrefs *repository.NotificationPreferenceRepo
	templates         *repository.SubmissionTemplateRepo
	storage           storage.Store
	staticFS          fs.FS
	logger            *slog.Logger
	fda           *fdaclient.Client
	fdaUserEmail  string // for auto-resolving user_id + company_id via GetCompanyInfo
	jwtSecret     string // HS256 signing key for JWT tokens

	// MFA temp secrets: holds unconfirmed TOTP secrets between setup and confirm calls.
	// Key: userID (string), Value: tempMFASecret.
	mfaTempSecrets sync.Map

	// "prod" or "test" — shown in the web UI so users know which FDA environment they target.
	fdaEnvironment string

	// When true, API key auth is skipped and a default org/user is used.
	authDisabled  bool
	defaultOrgID  string
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
	StorageBackend     string        // "local" (default) or "s3"
	StoragePath        string        // base directory for file storage (default: "./data/uploads")
	S3Bucket           string        // S3 bucket name (required when StorageBackend = "s3")
	S3Prefix           string        // optional S3 key prefix (default: "uploads/")
	S3Region           string        // AWS region (default: from AWS_REGION env)
	S3Endpoint         string        // custom endpoint for S3-compatible services
	JWTSecret          string        // HS256 signing key for JWT tokens (min 32 chars)
	AuthDisabled       bool          // when true, skip API key auth and use a default org/user
	StaticFS           fs.FS         // embedded static assets for web UI (nil = web UI disabled)
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

	var store storage.Store
	switch cfg.StorageBackend {
	case "s3":
		awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
			func(o *awsconfig.LoadOptions) error {
				if cfg.S3Region != "" {
					o.Region = cfg.S3Region
				}
				return nil
			},
		)
		if err != nil {
			return nil, fmt.Errorf("loading AWS config: %w", err)
		}
		var s3Opts []func(*s3.Options)
		if cfg.S3Endpoint != "" {
			s3Opts = append(s3Opts, func(o *s3.Options) {
				o.BaseEndpoint = &cfg.S3Endpoint
				o.UsePathStyle = true // required for most S3-compatible services
			})
		}
		s3Client := s3.NewFromConfig(awsCfg, s3Opts...)
		store = storage.NewS3Store(cfg.S3Bucket, cfg.S3Prefix, s3Client)
		logger.Info("using S3 storage backend", "bucket", cfg.S3Bucket, "prefix", cfg.S3Prefix)
	default:
		storagePath := cfg.StoragePath
		if storagePath == "" {
			storagePath = "./data/uploads"
		}
		localStore, err := storage.NewLocalStore(storagePath)
		if err != nil {
			return nil, fmt.Errorf("initializing file storage: %w", err)
		}
		store = localStore
	}

	s := &Server{
		db:            db,
		router:        http.NewServeMux(),
		submissions:   repository.NewSubmissionRepo(db, cfg.EncryptionKey),
		files:         repository.NewSubmissionFileRepo(db),
		apiKeys:       repository.NewAPIKeyRepo(db),
		users:         repository.NewUserRepo(db),
		orgs:          repository.NewOrgRepo(db),
		refreshTokens: repository.NewRefreshTokenRepo(db),
		acks:          repository.NewAckRepo(db),
		workflowLog:   repository.NewWorkflowLogRepo(db),
		auditLog:      repository.NewAuditLogRepo(db),
		webhooks:      repository.NewWebhookRepo(db),
		deliveries:        repository.NewWebhookDeliveryRepo(db),
		uploadSessions:    repository.NewUploadSessionRepo(db),
		backupCodes:       repository.NewBackupCodeRepo(db),
		notificationPrefs: repository.NewNotificationPreferenceRepo(db),
		templates:         repository.NewSubmissionTemplateRepo(db),
		fda: fdaclient.New(fdaclient.Config{
			ExternalBaseURL: cfg.FDAExternalBaseURL,
			UploadBaseURL:   cfg.FDAUploadBaseURL,
			ClientID:        cfg.FDAClientID,
			ClientSecret:    cfg.FDAClientSecret,
			Environment:     fdaEnv,
		}),
		fdaUserEmail:   cfg.FDAUserEmail,
		fdaEnvironment: cfg.FDAEnvironment,
		storage:        store,
		staticFS:     cfg.StaticFS,
		jwtSecret:    cfg.JWTSecret,
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

	// Auth — public (no withAuth)
	s.router.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	s.router.HandleFunc("POST /api/v1/auth/refresh", s.handleRefresh)
	s.router.HandleFunc("POST /api/v1/auth/logout", s.handleLogout)
	s.router.HandleFunc("POST /api/v1/auth/verify-mfa", s.handleVerifyMFA)

	// MFA management — authenticated
	s.router.HandleFunc("POST /api/v1/auth/mfa/setup", s.withAuth(s.handleMFASetup))
	s.router.HandleFunc("POST /api/v1/auth/mfa/confirm", s.withAuth(s.handleMFAConfirm))
	s.router.HandleFunc("DELETE /api/v1/auth/mfa", s.withAuth(s.adminOnly(s.handleMFADisable)))

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
	s.router.HandleFunc("PATCH /api/v1/users/{id}/password", s.withAuth(s.adminOnly(s.handleSetPassword)))

	// API key management — admin only
	s.router.HandleFunc("POST /api/v1/api-keys", s.withAuth(s.adminOnly(s.handleCreateAPIKey)))
	s.router.HandleFunc("GET /api/v1/api-keys", s.withAuth(s.adminOnly(s.handleListAPIKeys)))
	s.router.HandleFunc("DELETE /api/v1/api-keys/{id}", s.withAuth(s.adminOnly(s.handleRevokeAPIKey)))

	// Chunked (resumable) uploads — write: admin + submitter, read: all authenticated
	s.router.HandleFunc("POST /api/v1/submissions/{id}/uploads", s.withAuth(s.canWrite(s.handleInitiateUpload)))
	s.router.HandleFunc("PUT /api/v1/submissions/{id}/uploads/{uploadId}/chunks/{index}", s.withAuth(s.canWrite(s.handleUploadChunk)))
	s.router.HandleFunc("GET /api/v1/submissions/{id}/uploads/{uploadId}", s.withAuth(s.handleGetUploadProgress))
	s.router.HandleFunc("POST /api/v1/submissions/{id}/uploads/{uploadId}/complete", s.withAuth(s.canWrite(s.handleCompleteUpload)))

	// Notification preferences — all authenticated users manage their own
	s.router.HandleFunc("POST /api/v1/notifications/preferences", s.withAuth(s.handleCreateNotificationPref))
	s.router.HandleFunc("GET /api/v1/notifications/preferences", s.withAuth(s.handleListNotificationPrefs))
	s.router.HandleFunc("GET /api/v1/notifications/preferences/{channel}", s.withAuth(s.handleGetNotificationPref))
	s.router.HandleFunc("PATCH /api/v1/notifications/preferences/{channel}", s.withAuth(s.handleUpdateNotificationPref))
	s.router.HandleFunc("DELETE /api/v1/notifications/preferences/{channel}", s.withAuth(s.handleDeleteNotificationPref))

	// Submission templates — write: admin + submitter, delete: admin only
	s.router.HandleFunc("POST /api/v1/submission-templates", s.withAuth(s.canWrite(s.handleCreateTemplate)))
	s.router.HandleFunc("GET /api/v1/submission-templates", s.withAuth(s.handleListTemplates))
	s.router.HandleFunc("GET /api/v1/submission-templates/{id}", s.withAuth(s.handleGetTemplate))
	s.router.HandleFunc("PATCH /api/v1/submission-templates/{id}", s.withAuth(s.canWrite(s.handleUpdateTemplate)))
	s.router.HandleFunc("DELETE /api/v1/submission-templates/{id}", s.withAuth(s.adminOnly(s.handleDeleteTemplate)))

	// Organization management — admin only
	s.router.HandleFunc("POST /api/v1/orgs", s.withAuth(s.adminOnly(s.handleCreateOrg)))
	s.router.HandleFunc("GET /api/v1/orgs", s.withAuth(s.adminOnly(s.handleListOrgs)))
	s.router.HandleFunc("GET /api/v1/orgs/{id}", s.withAuth(s.adminOnly(s.handleGetOrg)))
	s.router.HandleFunc("PATCH /api/v1/orgs/{id}", s.withAuth(s.adminOnly(s.handleUpdateOrg)))
	s.router.HandleFunc("DELETE /api/v1/orgs/{id}", s.withAuth(s.adminOnly(s.handleDeleteOrg)))

	// --- Web UI routes (HTML, cookie auth) ---

	// Static assets
	if s.staticFS != nil {
		s.router.Handle("GET /static/", staticFileServer(s.staticFS))
	}

	// Root redirect
	s.router.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	})

	// Auth pages (public — withCookieAuth allows redirect-if-already-logged-in)
	s.router.HandleFunc("GET /auth/login", s.withCookieAuth(s.handleLoginPage))
	s.router.HandleFunc("POST /auth/login", s.handleWebLogin)
	s.router.HandleFunc("POST /auth/verify-mfa", s.handleWebVerifyMFA)
	s.router.HandleFunc("POST /auth/logout", s.handleWebLogout)

	// Dashboard (requires auth)
	s.router.HandleFunc("GET /dashboard", s.requireWebAuth(s.handleDashboard))
	s.router.HandleFunc("GET /dashboard/submissions", s.requireWebAuth(s.handleSubmissionsList))
	s.router.HandleFunc("GET /dashboard/submissions/new", s.requireWebAuth(s.handleCreateSubmissionPage))
	s.router.HandleFunc("POST /dashboard/submissions", s.requireWebAuth(s.handleWebCreateSubmission))
	s.router.HandleFunc("GET /dashboard/submissions/{id}", s.requireWebAuth(s.handleSubmissionDetail))
	s.router.HandleFunc("GET /dashboard/submissions/{id}/status", s.requireWebAuth(s.handleSubmissionStatus))
	s.router.HandleFunc("POST /dashboard/submissions/{id}/retry", s.requireWebAuth(s.handleRetrySubmission))
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

	// Hash a default password for the web UI login
	passwordHash, err := auth.HashPassword("admin")
	if err != nil {
		return fmt.Errorf("hashing default password: %w", err)
	}

	err = s.db.QueryRowContext(ctx,
		`INSERT INTO users (org_id, email, role, password_hash) VALUES ($1, 'admin@localhost', 'admin', $2)
		 ON CONFLICT (org_id, email) DO UPDATE SET role = EXCLUDED.role, password_hash = EXCLUDED.password_hash
		 RETURNING id`, s.defaultOrgID, passwordHash).Scan(&s.defaultUserID)
	if err != nil {
		return fmt.Errorf("creating default user: %w", err)
	}

	s.authDisabled = true
	s.logger.Info("default web login: email=admin@localhost password=admin org_slug=default")
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

	// Fire notification event for workflow state changes
	if eventType := mapWorkflowToEvent(newWorkflow); eventType != "" {
		var orgID, subName string
		err := s.db.QueryRowContext(ctx, `SELECT org_id, submission_name FROM submissions WHERE id = $1`, subID).Scan(&orgID, &subName)
		if err == nil {
			s.notifyEvent(orgID, WebhookEvent{
				Type: eventType,
				Data: map[string]any{"submission_id": subID, "submission_name": subName, "status": newStatus},
			})
		}
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
