package threat

import (
	"context"
	"log/slog"
)

// RateLimiter owns the per-IP/protocol token counter. allowed = count <= RateLimitPerMin.
type RateLimiter struct {
	store  RateLimitStore
	cfg    ThreatConfig
	logger *slog.Logger
}

// NewRateLimiter builds a RateLimiter. logger may be nil (logging is skipped).
func NewRateLimiter(store RateLimitStore, cfg ThreatConfig, logger *slog.Logger) *RateLimiter {
	return &RateLimiter{store: store, cfg: cfg, logger: logger}
}

// Allow increments the counter for auth:PROTOCOL:IP and reports whether the
// request is under the per-minute threshold. On a store error it logs (parity
// with the old inline "threat check query failed" warning) and fails open.
func (r *RateLimiter) Allow(ctx context.Context, meta ConnectionMeta) bool {
	count, err := r.store.Incr(ctx, "auth:"+meta.Protocol+":"+meta.SourceIP)
	if err != nil {
		if r.logger != nil {
			r.logger.Warn("threat check query failed", "step", "rate_limit", "error", err)
		}
		return true // fail-open, matching original
	}
	return count <= r.cfg.RateLimitPerMin
}
