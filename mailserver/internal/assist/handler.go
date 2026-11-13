// Package assist provides the HTTP handler for the AI assist endpoint.
//
// Routes:
//
//	POST /assist/complete  — full response (gated, rate-limited via middleware)
//	POST /assist/stream    — reserved; returns 501 until SSE is wired
//
// The handler is fully dependency-injected so tests run without a DB or live
// provider: a fake sharedassist.Provider, an assistGate, and a configReader
// are all interfaces that test doubles can implement.
package assist

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"setjoin.com/mailserver/internal/auth"
	sharedassist "setjoin.com/shared/assist"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

// featureChecker is the narrow interface for feature toggles consumed by
// ToggleAssistGate. *toggle.FeatureFlags satisfies this.
type featureChecker interface {
	IsEnabled(key string) bool
}

// ToggleAssistGate implements assistGate by reading the feature.assist toggle.
// The per-user assist token budget (§7 B4) is deferred; this gate only checks
// the global toggle. If the toggle is off, all users are blocked regardless of
// per-user entitlements (the toggle is the admin kill-switch).
type ToggleAssistGate struct {
	toggles featureChecker
}

// NewToggleAssistGate constructs a ToggleAssistGate backed by the given feature
// flag set. Pass the *toggle.FeatureFlags constructed in main.go.
func NewToggleAssistGate(toggles featureChecker) *ToggleAssistGate {
	return &ToggleAssistGate{toggles: toggles}
}

// Allowed returns true when feature.assist is enabled globally.
// userID is accepted to satisfy the interface and allow future per-user checks.
func (g *ToggleAssistGate) Allowed(_ context.Context, _ int64) bool {
	return g.toggles.IsEnabled(toggle.FeatureAssist)
}

// assistGate checks whether the AI assist feature is enabled for a user.
// The user ID comes from the JWT claims; the gate resolves the primary
// mailbox internally when it needs to call the DB reducer.
type assistGate interface {
	// Allowed returns true when feature.assist is on for the given user.
	Allowed(ctx context.Context, userID int64) bool
}

// Handler serves POST /assist/complete and POST /assist/stream.
type Handler struct {
	provider  sharedassist.Provider
	gate      assistGate
	cfgReader configReader
	logger    *slog.Logger
}

// NewHandler constructs a production Handler backed by the given provider
// factory (which calls LoadConfig to build a real OpenAI-compatible provider),
// an assistGate, and a configReader for on-call config reads.
func NewHandler(provider sharedassist.Provider, gate assistGate, cfgReader configReader, logger *slog.Logger) *Handler {
	return &Handler{
		provider:  provider,
		gate:      gate,
		cfgReader: cfgReader,
		logger:    logger,
	}
}

// Complete handles POST /assist/complete.
//
//   - 403 if feature.assist is disabled for the caller
//   - 422 if the request envelope fails Validate
//   - 503 if the AI provider is not configured
//   - 502 if the upstream provider returns an error
//   - 200 {"content": "..."} on success
func (h *Handler) Complete(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("Authentication required."))
		return
	}

	// Feature gate: check feature.assist for this user.
	if !h.gate.Allowed(r.Context(), claims.UserID) {
		httputil.WriteProblem(w, r, httputil.NewForbiddenProblem("AI assist is not enabled for your account."))
		return
	}

	// Decode request body (1 MiB cap via DecodeJSON).
	var req sharedassist.Request
	if err := httputil.DecodeJSON(w, r, &req); err != nil {
		httputil.WriteProblem(w, r, httputil.NewValidationProblem("Invalid JSON in request body.", nil))
		return
	}

	// Validate envelope (empty messages, oversized content, invalid roles).
	if err := sharedassist.Validate(req); err != nil {
		detail := "Request validation failed."
		switch {
		case errors.Is(err, sharedassist.ErrEmptyMessages):
			detail = "messages must not be empty and each message must have non-empty content."
		case errors.Is(err, sharedassist.ErrRequestTooLarge):
			detail = "Request content exceeds the maximum allowed size."
		case errors.Is(err, sharedassist.ErrInvalidRole):
			detail = "Message role must be one of: system, user, assistant."
		}
		httputil.WriteProblem(w, r, httputil.NewValidationProblem(detail, nil))
		return
	}

	// Load config — returns ErrNotConfigured when the admin has not yet set the keys.
	cfg, err := LoadConfig(r.Context(), h.cfgReader)
	if errors.Is(err, ErrNotConfigured) {
		httputil.WriteProblem(w, r, httputil.NewServiceUnavailableProblem(
			"AI assist is not configured. An administrator must set assist.provider_url and assist.model.",
		))
		return
	}
	if err != nil {
		h.logError(r, "assist: load config error", err)
		httputil.WriteProblem(w, r, httputil.NewServiceUnavailableProblem(
			"AI assist is temporarily unavailable.",
		))
		return
	}

	// Swap the provider's config if necessary (per-call config for live keys).
	provider := h.resolveProvider(cfg)

	// Call the upstream provider.
	resp, err := provider.Complete(r.Context(), req)
	if err != nil {
		h.logError(r, "assist: upstream error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{
			Type:   httputil.TypeInternalError,
			Title:  "Bad Gateway",
			Status: http.StatusBadGateway,
			Detail: "The AI assist provider returned an error. Please try again.",
		})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"content": resp.Content})
}

// Stream handles POST /assist/stream. SSE streaming is reserved for a later
// wave; this endpoint always returns 501 Not Implemented.
func (h *Handler) Stream(w http.ResponseWriter, r *http.Request) {
	httputil.WriteProblem(w, r, &httputil.Problem{
		Type:   "https://setjoin.com/errors/not-implemented",
		Title:  "Not Implemented",
		Status: http.StatusNotImplemented,
		Detail: "Streaming is not yet available. Use POST /assist/complete instead.",
	})
}

// resolveProvider returns a provider configured with the given cfg.
// When the injected h.provider is already an *sharedassist.OpenAICompatible
// (production path), we construct a new one per-call so it uses the current
// config (which may have changed since startup). When it's a test double we
// return it as-is.
func (h *Handler) resolveProvider(cfg sharedassist.Config) sharedassist.Provider {
	if _, ok := h.provider.(*sharedassist.OpenAICompatible); ok {
		return sharedassist.NewOpenAICompatible(cfg)
	}
	// Test double — return as-is.
	return h.provider
}

// logError logs an error at Warn level without leaking details to clients.
func (h *Handler) logError(r *http.Request, msg string, err error) {
	if h.logger != nil {
		h.logger.Warn(msg, "path", r.URL.Path, "error", err)
	}
}
