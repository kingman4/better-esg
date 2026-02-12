package fdaclient

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// retryConfig defines retry behavior for an FDA API call.
type retryConfig struct {
	maxAttempts int
	baseDelay   time.Duration
	maxDelay    time.Duration
	linear      bool // true = linear (5s, 10s, 15s), false = exponential (2s, 4s, 8s)
}

// Per-endpoint retry configs from TDD spec.
var (
	retryToken   = retryConfig{maxAttempts: 4, baseDelay: 1 * time.Second, maxDelay: 8 * time.Second}
	retryDefault = retryConfig{maxAttempts: 3, baseDelay: 2 * time.Second, maxDelay: 8 * time.Second}
	retryUpload  = retryConfig{maxAttempts: 5, baseDelay: 5 * time.Second, maxDelay: 25 * time.Second, linear: true}
)

// permanentError wraps an error that should not be retried.
type permanentError struct {
	err error
}

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// retryableError wraps an error that should be retried.
type retryableError struct {
	err error
}

func (e *retryableError) Error() string { return e.err.Error() }
func (e *retryableError) Unwrap() error { return e.err }

// SetFastRetryForTest overrides all retry configs with minimal delays for testing.
// Returns a cleanup function that restores the original configs.
// Intended for use in external test packages (e.g. server integration tests).
func SetFastRetryForTest() func() {
	origToken := retryToken
	origDefault := retryDefault
	origUpload := retryUpload

	fast := retryConfig{maxAttempts: 1, baseDelay: time.Millisecond, maxDelay: time.Millisecond}
	retryToken = fast
	retryDefault = fast
	retryUpload = fast

	return func() {
		retryToken = origToken
		retryDefault = origDefault
		retryUpload = origUpload
	}
}

// isRetryable returns true for HTTP status codes that indicate a transient failure.
func isRetryable(statusCode int) bool {
	return statusCode == 429 || statusCode >= 500
}

// backoffDelay calculates the delay for the given attempt (0-indexed).
func backoffDelay(cfg retryConfig, attempt int) time.Duration {
	var delay time.Duration
	if cfg.linear {
		delay = cfg.baseDelay * time.Duration(attempt+1)
	} else {
		delay = cfg.baseDelay * (1 << attempt) // baseDelay * 2^attempt
	}
	if delay > cfg.maxDelay {
		delay = cfg.maxDelay
	}
	return delay
}

// retryDo executes fn up to cfg.maxAttempts times with backoff between retries.
// It stops immediately on permanentError or context cancellation.
// Plain errors and retryableErrors are retried.
func retryDo(ctx context.Context, cfg retryConfig, fn func() error) error {
	var lastErr error

	for attempt := 0; attempt < cfg.maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		// Stop on permanent errors
		var pe *permanentError
		if errors.As(lastErr, &pe) {
			return pe.err // unwrap — callers shouldn't know about retry internals
		}

		// Last attempt — don't sleep
		if attempt == cfg.maxAttempts-1 {
			break
		}

		delay := backoffDelay(cfg, attempt)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}

	return fmt.Errorf("after %d attempts: %w", cfg.maxAttempts, lastErr)
}
