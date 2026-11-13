package threat

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Scope discriminators for RevocationRow — typed to prevent silent typo fall-through.
const (
	ScopeAll    = "all"    // revoke all tokens for a user issued before NotBefore
	ScopeJTI    = "jti"    // revoke a single token by JTI
	ScopeFamily = "family" // revoke all tokens in a refresh-token family
)

// RevocationRow is one session_revocations entry (the gateway-side mirror).
type RevocationRow struct {
	UserID    int64
	Scope     string // ScopeAll | ScopeJTI | ScopeFamily
	JTI       string
	FamilyID  string
	NotBefore time.Time
	ExpiresAt time.Time
}

// SessionDenylist is the gateway-owned in-memory mirror of session_revocations.
// Fed by the fixed "session_revoke" NOTIFY (Apply) + a periodic Refresh reconcile.
// FAIL-CLOSED: a known-revoked entry survives a failed Refresh — a stale-but-safe
// denylist must never resurrect a session an admin already killed (§14).
//
// Loaded() distinguishes "first Refresh not yet done" from "nothing revoked", mirroring
// PolicyEngine.cacheLoaded. Task-9 middleware must DENY when !Loaded() (cold-start safety).
type SessionDenylist struct {
	mu              sync.RWMutex
	refreshMu       sync.Mutex
	rows            []RevocationRow
	allBefore       map[int64]time.Time
	revokedJTI      map[int64]map[string]struct{}
	revokedFamily   map[int64]map[string]struct{}
	applyGeneration uint64
	loaded          bool // true only after the first SUCCESSFUL Refresh
	reconcileFn     func(context.Context) ([]RevocationRow, error)
	logger          *slog.Logger
}

func NewSessionDenylist(reconcileFn func(context.Context) ([]RevocationRow, error), logger *slog.Logger) *SessionDenylist {
	d := &SessionDenylist{
		reconcileFn:   reconcileFn,
		logger:        logger,
		allBefore:     make(map[int64]time.Time),
		revokedJTI:    make(map[int64]map[string]struct{}),
		revokedFamily: make(map[int64]map[string]struct{}),
	}
	if reconcileFn == nil {
		// ponytail: no persistence backend (test/stub) → no cold-start reconcile needed; treat as immediately loaded.
		d.loaded = true
	}
	return d
}

// Loaded reports whether at least one successful Refresh has completed.
// Middleware must treat !Loaded() as "deny" to close the cold-start window.
func (d *SessionDenylist) Loaded() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.loaded
}

// Apply adds a revocation from session_revoke. Rows are compacted by effective
// key so duplicate notifications and repeated all-scope events cannot make
// request-time work or memory grow without bound.
func (d *SessionDenylist) Apply(row RevocationRow) {
	d.mu.Lock()
	d.replaceRowsLocked(append(d.rows, row), time.Now())
	d.applyGeneration++
	d.mu.Unlock()
}

// IsRevoked reports whether (userID, jti, family, iat) is killed by any row.
func (d *SessionDenylist) IsRevoked(userID int64, jti, family string, iat time.Time) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if watermark := d.allBefore[userID]; !watermark.IsZero() && !iat.After(watermark) {
		return true
	}
	if jti != "" {
		if _, revoked := d.revokedJTI[userID][jti]; revoked {
			return true
		}
	}
	if family != "" {
		if _, revoked := d.revokedFamily[userID][family]; revoked {
			return true
		}
	}
	return false
}

// Refresh reconciles the full set from the DB authority. On error it KEEPS the
// existing rows (fail-closed) and returns the error for logging.
func (d *SessionDenylist) Refresh(ctx context.Context) error {
	if d.reconcileFn == nil {
		return nil
	}
	// Serialize refreshes so an older query cannot finish last and overwrite a
	// newer authoritative snapshot.
	d.refreshMu.Lock()
	defer d.refreshMu.Unlock()

	d.mu.RLock()
	startGeneration := d.applyGeneration
	d.mu.RUnlock()

	rows, err := d.reconcileFn(ctx)
	if err != nil {
		d.logger.Warn("session denylist reconcile failed — keeping existing entries (fail-closed)", "error", err)
		return err
	}
	d.mu.Lock()
	if d.applyGeneration == startGeneration {
		d.replaceRowsLocked(rows, time.Now())
	} else {
		// A NOTIFY landed after the database snapshot began. Preserve the
		// in-memory rows for this cycle instead of letting the stale snapshot
		// resurrect a just-revoked token. A later quiet refresh removes rows
		// that have actually expired from durable storage.
		d.replaceRowsLocked(mergeRevocationRows(rows, d.rows), time.Now())
	}
	d.loaded = true // ponytail: mirrors PolicyEngine.cacheLoaded; set only after a clean load
	d.mu.Unlock()
	return nil
}

func (d *SessionDenylist) replaceRowsLocked(rows []RevocationRow, now time.Time) {
	d.rows = compactRevocationRows(rows, now)
	d.allBefore = make(map[int64]time.Time)
	d.revokedJTI = make(map[int64]map[string]struct{})
	d.revokedFamily = make(map[int64]map[string]struct{})
	for _, row := range d.rows {
		switch row.Scope {
		case ScopeAll:
			d.allBefore[row.UserID] = row.NotBefore
		case ScopeJTI:
			if d.revokedJTI[row.UserID] == nil {
				d.revokedJTI[row.UserID] = make(map[string]struct{})
			}
			d.revokedJTI[row.UserID][row.JTI] = struct{}{}
		case ScopeFamily:
			if d.revokedFamily[row.UserID] == nil {
				d.revokedFamily[row.UserID] = make(map[string]struct{})
			}
			d.revokedFamily[row.UserID][row.FamilyID] = struct{}{}
		}
	}
}

func compactRevocationRows(rows []RevocationRow, now time.Time) []RevocationRow {
	byKey := make(map[string]RevocationRow, len(rows))
	for _, row := range rows {
		if row.UserID <= 0 || row.NotBefore.IsZero() ||
			(!row.ExpiresAt.IsZero() && !row.ExpiresAt.After(now)) {
			continue
		}
		var key string
		switch row.Scope {
		case ScopeAll:
			key = ScopeAll
		case ScopeJTI:
			if row.JTI == "" {
				continue
			}
			key = ScopeJTI + "\x00" + row.JTI
		case ScopeFamily:
			if row.FamilyID == "" {
				continue
			}
			key = ScopeFamily + "\x00" + row.FamilyID
		default:
			continue
		}
		key = fmt.Sprintf("%d\x00%s", row.UserID, key)
		existing, ok := byKey[key]
		if !ok || row.NotBefore.After(existing.NotBefore) {
			byKey[key] = row
		}
	}
	out := make([]RevocationRow, 0, len(byKey))
	for _, row := range byKey {
		out = append(out, row)
	}
	return out
}

func mergeRevocationRows(authoritative, live []RevocationRow) []RevocationRow {
	// replaceRowsLocked performs the keyed O(n) compaction immediately after
	// this merge. Appending here avoids a redundant quadratic duplicate scan
	// during a NOTIFY-vs-refresh race while preserving every live revocation.
	out := make([]RevocationRow, 0, len(authoritative)+len(live))
	out = append(out, authoritative...)
	out = append(out, live...)
	return out
}
