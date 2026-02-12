package server

import (
	"context"
)

// contextKey is an unexported type to prevent collisions with context keys from other packages.
type contextKey int

const (
	ctxOrgID  contextKey = iota
	ctxUserID
	ctxRole
)

// orgIDFromContext returns the authenticated org_id from the request context.
func orgIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxOrgID).(string)
	return v
}

// userIDFromContext returns the authenticated user_id from the request context.
func userIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxUserID).(string)
	return v
}

// roleFromContext returns the authenticated user's role from the request context.
func roleFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxRole).(string)
	return v
}

// withAuthContext creates a new context with auth values set.
func withAuthContext(ctx context.Context, orgID, userID, role string) context.Context {
	ctx = context.WithValue(ctx, ctxOrgID, orgID)
	ctx = context.WithValue(ctx, ctxUserID, userID)
	ctx = context.WithValue(ctx, ctxRole, role)
	return ctx
}
