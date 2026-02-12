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

	// Encryption — 32-byte key for AES-256-GCM (hex-encoded in env var)
	EncryptionKey []byte

	// Status poller — how often to poll FDA for in-flight submission updates
	StatusPollInterval time.Duration
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

	return &Config{
		Port:               port,
		DatabaseURL:        dbURL,
		FDAExternalBaseURL: envOrDefault("FDA_EXTERNAL_BASE_URL", "https://external-api-esgng.fda.gov"),
		FDAUploadBaseURL:   envOrDefault("FDA_UPLOAD_BASE_URL", "https://upload-api-esgng.fda.gov"),
		FDAClientID:        os.Getenv("FDA_CLIENT_ID"),
		FDAClientSecret:    os.Getenv("FDA_CLIENT_SECRET"),
		FDAEnvironment:     fdaEnv,
		EncryptionKey:      encKey,
		StatusPollInterval: pollInterval,
	}, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
