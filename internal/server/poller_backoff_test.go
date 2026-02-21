package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPollBackoffInterval(t *testing.T) {
	tests := []struct {
		name        string
		sinceSubmit time.Duration
		wantMin     time.Duration
		wantMax     time.Duration
	}{
		{"just submitted (< 30m)", 10 * time.Minute, 0, time.Minute},
		{"recent (30m-2h)", 1 * time.Hour, 5 * time.Minute, 15 * time.Minute},
		{"moderate (2h-24h)", 6 * time.Hour, 15 * time.Minute, 45 * time.Minute},
		{"old (> 24h)", 48 * time.Hour, 30 * time.Minute, 2 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interval := pollBackoffInterval(tt.sinceSubmit)
			assert.GreaterOrEqual(t, interval, tt.wantMin, "interval too short")
			assert.LessOrEqual(t, interval, tt.wantMax, "interval too long")
		})
	}
}
