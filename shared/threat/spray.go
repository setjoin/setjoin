package threat

import (
	"context"
	"encoding/json"
	"log/slog"
)

// SprayDetector owns password-spray detection + its side effects.
// Post (detected): LockIP -> Audit -> Notify, in that order. Not detected: zero writes.
// The metadata JSON is marshalled verbatim from intercept() step 5 (pre-refactor).
type SprayDetector struct {
	store  SprayStore
	cfg    ThreatConfig
	logger *slog.Logger
}

// NewSprayDetector builds a SprayDetector from a store and the threat config.
// logger may be nil (logging is skipped).
func NewSprayDetector(store SprayStore, cfg ThreatConfig, logger *slog.Logger) *SprayDetector {
	return &SprayDetector{store: store, cfg: cfg, logger: logger}
}

// Detect runs spray detection and, when detected, applies the IP lockout, writes
// the audit row, and fires the alert notification — in that exact order. On a
// detect-store error it logs (parity with the old inline "threat check query
// failed" warning, step="spray_detect") and fails open (returns false), matching
// the original inline behaviour where a failed detect_spray query did not trigger
// the side effects.
func (d *SprayDetector) Detect(ctx context.Context, meta ConnectionMeta) bool {
	detected, err := d.store.Detect(ctx, meta.SourceIP, d.cfg.SprayWindowSecs, d.cfg.SprayMaxUsers)
	if err != nil {
		if d.logger != nil {
			d.logger.Warn("threat check query failed", "step", "spray_detect", "error", err)
		}
		return false
	}
	if !detected {
		return false
	}
	_ = d.store.LockIP(ctx, meta.SourceIP, d.cfg.SprayLockoutMins)
	metaJSON, _ := json.Marshal(map[string]int{
		"unique_usernames": d.cfg.SprayMaxUsers,
		"window":           d.cfg.SprayWindowSecs,
	})
	_ = d.store.Audit(ctx, meta.SourceIP, metaJSON)
	_ = d.store.Notify(ctx, meta.SourceIP)
	return true
}
