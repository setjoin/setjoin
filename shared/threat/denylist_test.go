package threat

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"
)

func TestDenylistScopeAll(t *testing.T) {
	dl := NewSessionDenylist(nil, slog.Default())
	t0 := time.Now()
	dl.Apply(RevocationRow{UserID: 7, Scope: ScopeAll, NotBefore: t0})
	// A token issued before not_before is dead; one issued after survives.
	if !dl.IsRevoked(7, "j1", "f1", t0.Add(-time.Minute)) {
		t.Fatal("token iat < not_before must be revoked")
	}
	if dl.IsRevoked(7, "j1", "f1", t0.Add(time.Minute)) {
		t.Fatal("token iat > not_before must survive scope=all")
	}
	if dl.IsRevoked(8, "j1", "f1", t0.Add(-time.Minute)) {
		t.Fatal("other user must be unaffected")
	}
}

func TestDenylistScopeJTIAndFamily(t *testing.T) {
	dl := NewSessionDenylist(nil, slog.Default())
	dl.Apply(RevocationRow{UserID: 7, Scope: ScopeJTI, JTI: "kill-me", NotBefore: time.Now()})
	dl.Apply(RevocationRow{UserID: 7, Scope: ScopeFamily, FamilyID: "fam9", NotBefore: time.Now()})
	if !dl.IsRevoked(7, "kill-me", "other", time.Now().Add(-time.Hour)) {
		t.Fatal("matching jti must be revoked")
	}
	if !dl.IsRevoked(7, "other", "fam9", time.Now().Add(-time.Hour)) {
		t.Fatal("matching family must be revoked")
	}
	if dl.IsRevoked(7, "survivor", "famX", time.Now().Add(-time.Hour)) {
		t.Fatal("non-matching jti/family must survive")
	}
}

func TestDenylistCompactsAndDropsExpiredEnforcementRows(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	dl := NewSessionDenylist(nil, slog.Default())
	dl.Apply(RevocationRow{
		UserID: 7, Scope: ScopeAll, NotBefore: now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
	})
	dl.Apply(RevocationRow{
		UserID: 7, Scope: ScopeAll, NotBefore: now,
		ExpiresAt: now.Add(time.Hour),
	})
	dl.Apply(RevocationRow{
		UserID: 7, Scope: ScopeJTI, JTI: "expired",
		NotBefore: now, ExpiresAt: now.Add(-time.Second),
	})
	dl.mu.RLock()
	rowCount := len(dl.rows)
	dl.mu.RUnlock()
	if rowCount != 1 {
		t.Fatalf("compacted rows = %d, want one greatest active watermark", rowCount)
	}
	if dl.IsRevoked(7, "expired", "", now.Add(time.Minute)) {
		t.Fatal("expired targeted revocation remained enforceable")
	}
	if !dl.IsRevoked(7, "fresh", "", now.Add(-time.Second)) {
		t.Fatal("greatest active all-scope watermark was not retained")
	}
}

func TestDenylistCompactionRejectsIncompleteAndUnknownScopes(t *testing.T) {
	now := time.Now()
	rows := compactRevocationRows([]RevocationRow{
		{UserID: 7, Scope: ScopeJTI, NotBefore: now, ExpiresAt: now.Add(time.Hour)},
		{UserID: 7, Scope: ScopeFamily, NotBefore: now, ExpiresAt: now.Add(time.Hour)},
		{UserID: 7, Scope: "unknown", NotBefore: now, ExpiresAt: now.Add(time.Hour)},
	}, now)
	if len(rows) != 0 {
		t.Fatalf("invalid enforcement rows survived compaction: %+v", rows)
	}
}

// TestDenylistScopeAllCompactionKeepsMultiUserDenyWindows pins the s09
// compaction invariant: all-scope rows collapse to one row per user (the
// compaction key is "<userID>\x00all", so users never merge) and the winner
// is the GREATEST NotBefore — and the collapse must never narrow the
// effective deny window: a revoked user stays denied post-compaction across
// the full window, including the stretch only the discarded older row
// covered.
//
// Soundness precondition (reducer-generated rows only): compaction keeps max
// NotBefore and discards the loser's expiry, which is only correct when a
// later NotBefore implies a later-or-equal expiry. That holds for
// mailserver/sql/reducers/revoke_user_sessions.sql, whose scope='all' branch
// stamps not_before = statement_timestamp() and
// expires_at = statement_timestamp() + 31 days on every event (and deletes
// the user's prior 'all' rows in the same transaction — the mirror-side
// compaction here is the safety net for the NOTIFY-vs-refresh merge, where
// two rows for one user can transiently coexist). A row source violating
// that shape (newer NotBefore, earlier ExpiresAt) could shrink the denied
// window once the winner expires; this test documents that precondition, not
// a property compaction itself enforces.
func TestDenylistScopeAllCompactionKeepsMultiUserDenyWindows(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	t0 := now
	t1 := now.Add(time.Hour)
	t2 := now.Add(2 * time.Hour)
	expires := now.Add(31 * 24 * time.Hour) // reducer shape: revoke time + 31d

	dl := NewSessionDenylist(nil, slog.Default())
	// Newer row first, older row second per user: the winner must be the
	// greatest NotBefore, never merely the row applied last.
	dl.Apply(RevocationRow{UserID: 7, Scope: ScopeAll, NotBefore: t1, ExpiresAt: expires})
	dl.Apply(RevocationRow{UserID: 7, Scope: ScopeAll, NotBefore: t0, ExpiresAt: expires})
	dl.Apply(RevocationRow{UserID: 8, Scope: ScopeAll, NotBefore: t2, ExpiresAt: expires})
	dl.Apply(RevocationRow{UserID: 8, Scope: ScopeAll, NotBefore: t0, ExpiresAt: expires})

	dl.mu.RLock()
	rowCount := len(dl.rows)
	dl.mu.RUnlock()
	if rowCount != 2 {
		t.Fatalf("compacted rows = %d, want one greatest-watermark row per user", rowCount)
	}

	// User 7 stays denied across the FULL window: before the oldest
	// NotBefore (the coverage only the discarded row contributed must
	// survive), between the two, and exactly at the winner.
	for _, iat := range []time.Time{t0.Add(-time.Minute), t0.Add(time.Minute), t1.Add(-time.Second), t1} {
		if !dl.IsRevoked(7, "j", "f", iat) {
			t.Fatalf("user 7 token iat %v must stay denied post-compaction", iat)
		}
	}
	if dl.IsRevoked(7, "j", "f", t1.Add(time.Second)) {
		t.Fatal("user 7 token issued after the watermark must survive scope=all")
	}
	// User 8 compacts independently over its own window.
	if !dl.IsRevoked(8, "j", "f", t0.Add(-time.Minute)) {
		t.Fatal("user 8 token before its oldest NotBefore must stay denied post-compaction")
	}
	if !dl.IsRevoked(8, "j", "f", t2) {
		t.Fatal("user 8 token at its watermark must be denied")
	}
	if dl.IsRevoked(8, "j", "f", t2.Add(time.Second)) {
		t.Fatal("user 8 token issued after the watermark must survive scope=all")
	}
	// No cross-user bleed in either direction.
	if dl.IsRevoked(9, "j", "f", t0.Add(-time.Minute)) {
		t.Fatal("user without revocation rows must be unaffected")
	}
}

// TestDenylistScopeAllNewerNotBeforeExtendsDeny pins the live-path half of
// the invariant: a later scope=all event moves the watermark forward,
// widening the deny over tokens issued between the two revocations, while
// the older window stays denied (no resurrection) and post-watermark tokens
// stay alive — under the same reducer-generated precondition documented on
// TestDenylistScopeAllCompactionKeepsMultiUserDenyWindows.
func TestDenylistScopeAllNewerNotBeforeExtendsDeny(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	t0 := now
	t1 := now.Add(time.Hour)
	expires := now.Add(31 * 24 * time.Hour)

	dl := NewSessionDenylist(nil, slog.Default())
	dl.Apply(RevocationRow{UserID: 7, Scope: ScopeAll, NotBefore: t0, ExpiresAt: expires})

	// A token minted between the two revocation events is alive under the
	// first watermark alone.
	gap := t0.Add(30 * time.Minute)
	if dl.IsRevoked(7, "j", "f", gap) {
		t.Fatal("token issued after the only watermark must survive scope=all")
	}

	// The later scope=all event advances NotBefore (reducer shape: expiry
	// extends with it) and must widen the deny over the gap token.
	dl.Apply(RevocationRow{UserID: 7, Scope: ScopeAll, NotBefore: t1, ExpiresAt: expires})
	if !dl.IsRevoked(7, "j", "f", gap) {
		t.Fatal("newer scope=all watermark must extend the deny over tokens issued between events")
	}
	if !dl.IsRevoked(7, "j", "f", t0.Add(-time.Minute)) {
		t.Fatal("older deny window must survive the newer watermark")
	}
	if dl.IsRevoked(7, "j", "f", t1.Add(time.Second)) {
		t.Fatal("token issued after the newest watermark must survive scope=all")
	}

	dl.mu.RLock()
	watermark, hasWatermark := dl.allBefore[7]
	rowCount := len(dl.rows)
	dl.mu.RUnlock()
	if !hasWatermark || !watermark.Equal(t1) {
		t.Fatalf("compacted watermark = %v (present=%v), want the greatest NotBefore %v", watermark, hasWatermark, t1)
	}
	if rowCount != 1 {
		t.Fatalf("compacted rows = %d, want the single greatest-watermark row", rowCount)
	}
}

func TestDenylistReconcileFailClosed(t *testing.T) {
	// A known-revoked entry must STAY denied even when Refresh errors.
	dl := NewSessionDenylist(func(context.Context) ([]RevocationRow, error) {
		return nil, errors.New("db down")
	}, slog.Default())
	dl.Apply(RevocationRow{UserID: 7, Scope: ScopeAll, NotBefore: time.Now()})
	_ = dl.Refresh(context.Background()) // errors, must not wipe the cache
	if !dl.IsRevoked(7, "j", "f", time.Now().Add(-time.Minute)) {
		t.Fatal("fail-closed: known revocation must survive a failed reconcile")
	}
}

func TestDenylistLoadedSentinel(t *testing.T) {
	// Before first successful Refresh, Loaded() must be false (cold-start gate).
	calls := 0
	dl := NewSessionDenylist(func(context.Context) ([]RevocationRow, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("db down") // first call errors
		}
		return []RevocationRow{{UserID: 7, Scope: ScopeAll, NotBefore: time.Now()}}, nil
	}, slog.Default())

	if dl.Loaded() {
		t.Fatal("must not be loaded before first Refresh")
	}
	_ = dl.Refresh(context.Background()) // errors — still not loaded
	if dl.Loaded() {
		t.Fatal("must not be loaded after a failed Refresh")
	}
	if err := dl.Refresh(context.Background()); err != nil { // success
		t.Fatalf("second refresh must succeed: %v", err)
	}
	if !dl.Loaded() {
		t.Fatal("must be loaded after a successful Refresh")
	}
}

func TestDenylistRefreshCannotOverwriteConcurrentApply(t *testing.T) {
	t.Parallel()
	queryStarted := make(chan struct{})
	releaseQuery := make(chan struct{})
	dl := NewSessionDenylist(func(context.Context) ([]RevocationRow, error) {
		close(queryStarted)
		<-releaseQuery
		return nil, nil // stale snapshot taken before the concurrent NOTIFY
	}, slog.Default())

	refreshDone := make(chan error, 1)
	go func() {
		refreshDone <- dl.Refresh(context.Background())
	}()
	<-queryStarted

	now := time.Now().UTC()
	dl.Apply(RevocationRow{
		UserID: 91, Scope: ScopeAll, NotBefore: now,
	})
	close(releaseQuery)
	if err := <-refreshDone; err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !dl.IsRevoked(91, "jti", "family", now.Add(-time.Second)) {
		t.Fatal("stale refresh snapshot resurrected a concurrently revoked token")
	}
	if !dl.Loaded() {
		t.Fatal("successful refresh must still mark the denylist loaded")
	}
}

func TestDenylistQuietRefreshRemovesExpiredRows(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	dl := NewSessionDenylist(func(context.Context) ([]RevocationRow, error) {
		return nil, nil
	}, slog.Default())
	dl.Apply(RevocationRow{
		UserID: 92, Scope: ScopeAll, NotBefore: now,
	})
	if err := dl.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if dl.IsRevoked(92, "jti", "family", now.Add(-time.Second)) {
		t.Fatal("quiet authoritative refresh retained a row absent from durable storage")
	}
}
