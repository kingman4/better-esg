package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"time"
)

type Config struct {
	Port        string
	DatabaseURL string

	// FDA ESG NextGen API
	FDAExternalBaseURL string // auth + metadata API
	FDAUploadBaseURL   string // file upload API
	FDAClientID        string
	FDAClientSecret    string
	FDAEnvironment     string // "prod" or "test"
	FDAUserEmail       string // email for GetCompanyInfo lookup (resolves user_id + company_id)

	// Encryption — 32-byte key for AES-256-GCM (hex-encoded in env var)
	EncryptionKey []byte

	// Status poller — how often to poll FDA for in-flight submission updates
	StatusPollInterval time.Duration

	// Logging
	LogLevel string // "debug", "info", "warn", "error" (default: "info")

	// File storage
	StorageBackend string // "local" (default) or "s3"
	StoragePath    string // base directory for uploaded files (default: "./data/uploads") — used when StorageBackend = "local"

	// S3 storage (used when StorageBackend = "s3")
	S3Bucket   string // required when StorageBackend = "s3"
	S3Prefix   string // optional key prefix (default: "uploads/")
	S3Region   string // AWS region (default: from AWS_REGION env)
	S3Endpoint string // custom endpoint for S3-compatible services (MinIO, etc.)

	// JWT authentication
	JWTSecret string // HS256 signing key (min 32 chars, required when AUTH_DISABLED=false)

	// When true, API key auth is skipped (local dev convenience)
	AuthDisabled bool
}

func Load() (*Config, error) {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		// Build from individual components if DATABASE_URL not set
		host := envOrDefault("DB_HOST", "localhost")
		portDB := envOrDefault("DB_PORT", "5432")
		user := envOrDefault("DB_USER", "esg")
		pass := envOrDefault("DB_PASSWORD", "esg")
		name := envOrDefault("DB_NAME", "esg")
		sslmode := envOrDefault("DB_SSLMODE", "disable")
		dbURL = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", user, pass, host, portDB, name, sslmode)
	}

	fdaEnv := envOrDefault("FDA_ENVIRONMENT", "test")
	if fdaEnv != "prod" && fdaEnv != "test" {
		return nil, fmt.Errorf("FDA_ENVIRONMENT must be 'prod' or 'test', got %q", fdaEnv)
	}

	encKeyHex := os.Getenv("ENCRYPTION_KEY")
	if encKeyHex == "" {
		return nil, fmt.Errorf("ENCRYPTION_KEY is required (64-char hex string for 32-byte AES-256 key)")
	}
	encKey, err := hex.DecodeString(encKeyHex)
	if err != nil {
		return nil, fmt.Errorf("ENCRYPTION_KEY must be valid hex: %w", err)
	}
	if len(encKey) != 32 {
		return nil, fmt.Errorf("ENCRYPTION_KEY must be 32 bytes (64 hex chars), got %d bytes", len(encKey))
	}

	pollInterval := 60 * time.Second
	if v := os.Getenv("STATUS_POLL_INTERVAL"); v != "" {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("STATUS_POLL_INTERVAL must be a valid Go duration (e.g. 60s, 5m): %w", err)
		}
		pollInterval = parsed
	}

	logLevel := envOrDefault("LOG_LEVEL", "info")
	authDisabled := os.Getenv("AUTH_DISABLED") == "true"

	jwtSecret := os.Getenv("JWT_SECRET")
	if !authDisabled && jwtSecret != "" && len(jwtSecret) < 32 {
		return nil, fmt.Errorf("JWT_SECRET must be at least 32 characters")
	}

	storageBackend := envOrDefault("STORAGE_BACKEND", "local")
	if storageBackend != "local" && storageBackend != "s3" {
		return nil, fmt.Errorf("STORAGE_BACKEND must be 'local' or 's3', got %q", storageBackend)
	}
	s3Bucket := os.Getenv("S3_BUCKET")
	if storageBackend == "s3" && s3Bucket == "" {
		return nil, fmt.Errorf("S3_BUCKET is required when STORAGE_BACKEND=s3")
	}

	return &Config{
		Port:               port,
		DatabaseURL:        dbURL,
		FDAExternalBaseURL: envOrDefault("FDA_EXTERNAL_BASE_URL", "https://external-api-esgng.fda.gov"),
		FDAUploadBaseURL:   envOrDefault("FDA_UPLOAD_BASE_URL", "https://upload-api-esgng.fda.gov"),
		FDAClientID:        os.Getenv("FDA_CLIENT_ID"),
		FDAClientSecret:    os.Getenv("FDA_CLIENT_SECRET"),
		FDAEnvironment:     fdaEnv,
		FDAUserEmail:       os.Getenv("FDA_USER_EMAIL"),
		EncryptionKey:      encKey,
		StatusPollInterval: pollInterval,
		LogLevel:           logLevel,
		StorageBackend:     storageBackend,
		StoragePath:        envOrDefault("STORAGE_PATH", "./data/uploads"),
		S3Bucket:           s3Bucket,
		S3Prefix:           envOrDefault("S3_PREFIX", "uploads/"),
		S3Region:           os.Getenv("S3_REGION"),
		S3Endpoint:         os.Getenv("S3_ENDPOINT"),
		JWTSecret:          jwtSecret,
		AuthDisabled:       authDisabled,
	}, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
