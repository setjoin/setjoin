package handlers

import "context"

type contextKey int

const ctxKeyUser contextKey = iota

// ContextWithUser attaches token claims to a request context.
func ContextWithUser(ctx context.Context, claims interface{}) context.Context {
	return context.WithValue(ctx, ctxKeyUser, claims)
}
