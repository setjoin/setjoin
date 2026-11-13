package threat

import (
	"context"
	"log/slog"
	"time"
)

// LockoutManager owns auth_lockouts decisions. Pre/post invariants are documented
// per method and enforced by lockout_test.go. Empty Username is always a no-op,
// matching the original inline guards in intercept()/recordOutcome().
type LockoutManager struct {
	store  LockoutStore
	logger *slog.Logger
}

// NewLockoutManager builds a LockoutManager. logger may be nil (logging is skipped).
func NewLockoutManager(store LockoutStore, logger *slog.Logger) *LockoutManager {
	return &LockoutManager{store: store, logger: logger}
}

// Check reports current lockout state. Pre: meta.Username != "" else (false,0).
// Post: no writes; remaining is the longest locked_until across the three keys.
// On a store error it logs (parity with the old inline "threat check query failed"
// warning). Error handling matches the original inline step 4 exactly:
//   - EXISTS query errored (locked=false): fail OPEN — treat as not locked
//     (step="lockout").
//   - lockout established but the remaining-duration query errored (locked=true):
//     fail CLOSED — stay locked with remaining=0 (step="lockout_remaining"). The
//     original logged and still returned ActionReject/"lockout"/0; admitting a
//     locked-out connection here would be a security regression.
func (m *LockoutManager) Check(ctx context.Context, meta ConnectionMeta) (bool, time.Duration) {
	if meta.Username == "" {
		return false, 0
	}
	locked, rem, err := m.store.IsLocked(ctx, lockoutKeys(meta.SourceIP, meta.Username))
	if err != nil {
		if locked {
			// Remaining-duration query failed after lockout was established:
			// stay locked (fail-closed), matching the original step 4.
			if m.logger != nil {
				m.logger.Warn("threat check query failed", "step", "lockout_remaining", "error", err)
			}
			return true, 0
		}
		// EXISTS query failed: fail open, matching the original step 4.
		if m.logger != nil {
			m.logger.Warn("threat check query failed", "step", "lockout", "error", err)
		}
		return false, 0
	}
	return locked, rem
}

// Escalate bumps all three keys on auth failure. Pre: meta.Username != "".
// Post: exactly three Escalate calls in order ip, user, ip_user.
func (m *LockoutManager) Escalate(ctx context.Context, meta ConnectionMeta) {
	if meta.Username == "" {
		return
	}
	for _, k := range lockoutKeys(meta.SourceIP, meta.Username) {
		_ = m.store.Escalate(ctx, k)
	}
}

// Reset clears all three keys on auth success. Pre: meta.Username != "".
// Post: one Clear of exactly the three keys.
func (m *LockoutManager) Reset(ctx context.Context, meta ConnectionMeta) {
	if meta.Username == "" {
		return
	}
	_ = m.store.Clear(ctx, lockoutKeys(meta.SourceIP, meta.Username))
}
