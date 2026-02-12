package config

import (
	"fmt"
	"os"
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

	return &Config{
		Port:               port,
		DatabaseURL:        dbURL,
		FDAExternalBaseURL: envOrDefault("FDA_EXTERNAL_BASE_URL", "https://external-api-esgng.fda.gov"),
		FDAUploadBaseURL:   envOrDefault("FDA_UPLOAD_BASE_URL", "https://upload-api-esgng.fda.gov"),
		FDAClientID:        os.Getenv("FDA_CLIENT_ID"),
		FDAClientSecret:    os.Getenv("FDA_CLIENT_SECRET"),
		FDAEnvironment:     fdaEnv,
	}, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
