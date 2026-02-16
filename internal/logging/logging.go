package logging

import (
	"log/slog"
	"os"
	"strings"
)

// New creates a structured JSON logger at the given level.
// Valid levels: "debug", "info", "warn", "error". Defaults to "info".
// Also sets slog.SetDefault so any remaining log.Printf calls route through slog.
func New(level string) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: parseLevel(level),
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, opts))
	slog.SetDefault(logger)
	return logger
}

// parseLevel converts a string level name to slog.Level.
func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
