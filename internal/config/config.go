package config

import (
	"fmt"
	"os"
)

type Config struct {
	Port        string
	DatabaseURL string
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

	return &Config{
		Port:        port,
		DatabaseURL: dbURL,
	}, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
