package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestNew_DefaultLevel(t *testing.T) {
	logger := New("info")
	if logger == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"INFO", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"ERROR", slog.LevelError},
		{"", slog.LevelInfo},         // empty defaults to info
		{"invalid", slog.LevelInfo},  // unknown defaults to info
		{" debug ", slog.LevelDebug}, // whitespace trimmed
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseLevel(tt.input)
			if got != tt.want {
				t.Errorf("parseLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestNew_JSONOutput(t *testing.T) {
	var buf bytes.Buffer
	opts := &slog.HandlerOptions{Level: parseLevel("info")}
	logger := slog.New(slog.NewJSONHandler(&buf, opts))

	logger.Info("test message", "key", "value")

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, buf.String())
	}

	if entry["msg"] != "test message" {
		t.Errorf("msg = %v, want %q", entry["msg"], "test message")
	}
	if entry["key"] != "value" {
		t.Errorf("key = %v, want %q", entry["key"], "value")
	}
	if entry["level"] != "INFO" {
		t.Errorf("level = %v, want %q", entry["level"], "INFO")
	}
	if _, ok := entry["time"]; !ok {
		t.Error("expected 'time' field in JSON output")
	}
}

func TestNew_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	opts := &slog.HandlerOptions{Level: parseLevel("warn")}
	logger := slog.New(slog.NewJSONHandler(&buf, opts))

	logger.Info("should be filtered")
	if buf.Len() > 0 {
		t.Error("info message should be filtered at warn level")
	}

	logger.Warn("should appear")
	if buf.Len() == 0 {
		t.Error("warn message should appear at warn level")
	}
}
