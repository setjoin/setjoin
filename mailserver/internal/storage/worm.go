package storage

import (
	"context"
	"fmt"
)

// WORM configuration constants.
const (
	// DefaultWORMRetentionDays is 2557 days = 7 years, covering the strictest
	// regulation (FINRA 4511(c)). SEC 17a-4(f) requires 6 years for broker-dealers;
	// CFTC Rule 1.31(c)-(d) requires 5 years. We default to 7 to cover all three.
	DefaultWORMRetentionDays = 2557

	// MinWORMRetentionDays is the absolute minimum retention period. Operators
	// may configure lower values for non-regulated deployments, but values below
	// this threshold trigger a warning at startup.
	MinWORMRetentionDays = 1
)

// validWORMModes is the set of allowed Object Lock modes.
var validWORMModes = map[string]bool{
	"compliance": true,
	"governance": true,
}

// ValidateWORMConfig checks that the WORM configuration is valid.
// It returns nil if the configuration is acceptable for startup.
//
// Validation rules:
//   - If mode is empty, WORM is disabled. Retention days must also be 0.
//   - If mode is set, retention days must be >= 1.
//   - Mode must be "compliance" or "governance".
//
// Does NOT enforce minimum retention (that is a warning at the caller's discretion).
func ValidateWORMConfig(mode string, retentionDays int) error {
	if mode == "" {
		if retentionDays > 0 {
			return fmt.Errorf("WORM_RETENTION_DAYS=%d but WORM_MODE is empty: set WORM_MODE to \"compliance\" or \"governance\", or unset WORM_RETENTION_DAYS", retentionDays)
		}
		return nil
	}

	if !validWORMModes[mode] {
		return fmt.Errorf("WORM_MODE=%q is invalid: must be \"compliance\" or \"governance\"", mode)
	}

	if retentionDays < 1 {
		return fmt.Errorf("WORM_MODE=%q requires WORM_RETENTION_DAYS >= 1 (got %d)", mode, retentionDays)
	}

	return nil
}

// IsWORMConfigured returns true if WORM immutability is active.
func IsWORMConfigured(mode string) bool {
	return mode != "" && validWORMModes[mode]
}

// StartupWORMCheck verifies that the bucket's Object Lock configuration matches
// the configured WORM mode. It is called during gateway startup.
//
// It takes the segregated Retention capability (obtain it from a Driver via
// RetentionOf): a backend that cannot report Object Lock configuration cannot
// satisfy a WORM mandate, so the capability gate is the type itself.
//
// Returns nil if the bucket has Object Lock enabled in the expected mode.
// Returns a fatal error (gateway must not start) if:
//   - The bucket does not have Object Lock enabled.
//   - The bucket's Object Lock mode does not match the configured mode.
//   - The bucket config lookup itself fails (network, permissions, etc.).
func StartupWORMCheck(ctx context.Context, retention Retention, expectedMode string) error {
	cfg, err := retention.GetBucketObjectLockConfig(ctx)
	if err != nil {
		return fmt.Errorf("WORM startup check: cannot read bucket Object Lock configuration: %w", err)
	}

	if cfg == nil || !cfg.Enabled {
		return fmt.Errorf("WORM startup check: bucket does not have Object Lock enabled. "+
			"Create the blob bucket with Object Lock enabled in %s mode, then restart the gateway.", expectedMode)
	}

	if cfg.Mode != expectedMode {
		return fmt.Errorf("WORM startup check: bucket Object Lock mode mismatch: configured=%s, bucket=%s. "+
			"Recreate the bucket with mode %s or update WORM_MODE to match.", expectedMode, cfg.Mode, expectedMode)
	}

	return nil
}

// RetentionDaysBelowMinimum returns true if the configured retention is below
// the regulatory minimum (7 years / 2557 days). The caller should log a warning
// but not block startup — SREs may intentionally use shorter retention for
// non-regulated deployments.
func RetentionDaysBelowMinimum(days int) bool {
	return days > 0 && days < DefaultWORMRetentionDays
}
