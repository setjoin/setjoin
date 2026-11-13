package threat

import (
	"sync/atomic"
	"testing"
	"time"
)

type countedCloser struct {
	closes atomic.Int32
}

func (c *countedCloser) Close() error {
	c.closes.Add(1)
	return nil
}

func TestProtocolSessionRegistryAppliesOnlyMatchingAllScope(t *testing.T) {
	t.Parallel()
	registry := NewProtocolSessionRegistry()
	now := time.Now().UTC()
	oldMatch := &countedCloser{}
	newMatch := &countedCloser{}
	otherUser := &countedCloser{}

	releaseOld := registry.Register(7, now.Add(-time.Minute), oldMatch)
	releaseNew := registry.Register(7, now.Add(time.Minute), newMatch)
	releaseOther := registry.Register(8, now.Add(-time.Minute), otherUser)

	registry.Apply(RevocationRow{
		UserID: 7, Scope: ScopeJTI, JTI: "token-only", NotBefore: now,
	})
	if oldMatch.closes.Load() != 0 || newMatch.closes.Load() != 0 {
		t.Fatal("token-specific revocation closed a password protocol connection")
	}

	registry.Apply(RevocationRow{UserID: 7, Scope: ScopeAll, NotBefore: now})
	if oldMatch.closes.Load() != 1 {
		t.Fatalf("pre-revocation connection closes = %d, want 1", oldMatch.closes.Load())
	}
	if newMatch.closes.Load() != 0 {
		t.Fatal("post-revocation connection was closed")
	}
	if otherUser.closes.Load() != 0 {
		t.Fatal("another user's connection was closed")
	}

	// Releases remain safe after Apply removed the matching entry.
	releaseOld()
	releaseOld()
	releaseNew()
	releaseOther()
}

func TestProtocolSessionRegistryReconcileRepairsMissedNotification(t *testing.T) {
	t.Parallel()
	registry := NewProtocolSessionRegistry()
	now := time.Now().UTC()
	conn := &countedCloser{}
	registry.Register(19, now.Add(-time.Second), conn)

	registry.Reconcile([]RevocationRow{
		{UserID: 19, Scope: ScopeAll, NotBefore: now},
	})
	if conn.closes.Load() != 1 {
		t.Fatalf("reconciled connection closes = %d, want 1", conn.closes.Load())
	}

	// Reapplying the durable row is idempotent for the removed connection.
	registry.Reconcile([]RevocationRow{
		{UserID: 19, Scope: ScopeAll, NotBefore: now},
	})
	if conn.closes.Load() != 1 {
		t.Fatalf("replayed reconcile closes = %d, want 1", conn.closes.Load())
	}
}

func TestProtocolSessionRegistryRejectsLateRegistrationFromRevokedAuthentication(t *testing.T) {
	t.Parallel()
	registry := NewProtocolSessionRegistry()
	now := time.Now().UTC()
	registry.Apply(RevocationRow{UserID: 23, Scope: ScopeAll, NotBefore: now})

	stale := &countedCloser{}
	registry.Register(23, now.Add(-time.Second), stale)
	if stale.closes.Load() != 1 {
		t.Fatalf("late stale registration closes = %d, want 1", stale.closes.Load())
	}

	fresh := &countedCloser{}
	release := registry.Register(23, now.Add(time.Second), fresh)
	if fresh.closes.Load() != 0 {
		t.Fatal("authentication accepted after the revocation watermark was closed")
	}
	release()
}

func TestProtocolSessionRegistryRetainsGreatestRevocationWatermark(t *testing.T) {
	t.Parallel()
	registry := NewProtocolSessionRegistry()
	now := time.Now().UTC()
	registry.Apply(RevocationRow{UserID: 31, Scope: ScopeAll, NotBefore: now})
	registry.Apply(RevocationRow{UserID: 31, Scope: ScopeAll, NotBefore: now.Add(-time.Hour)})

	conn := &countedCloser{}
	registry.Register(31, now.Add(-time.Minute), conn)
	if conn.closes.Load() != 1 {
		t.Fatalf("registration below greatest watermark closes = %d, want 1", conn.closes.Load())
	}
}

func TestProtocolSessionRegistryAppliesOnlyMatchingTokenScope(t *testing.T) {
	t.Parallel()
	registry := NewProtocolSessionRegistry()
	now := time.Now().UTC()
	jtiMatch := &countedCloser{}
	familyMatch := &countedCloser{}
	sameUserOtherToken := &countedCloser{}
	otherUser := &countedCloser{}

	releaseJTI := registry.RegisterTokenSession(41, now, "jti-a", "family-a", jtiMatch)
	releaseFamily := registry.RegisterTokenSession(41, now, "jti-b", "family-b", familyMatch)
	releaseOther := registry.RegisterTokenSession(41, now, "jti-c", "family-c", sameUserOtherToken)
	releaseOtherUser := registry.RegisterTokenSession(42, now, "jti-a", "family-b", otherUser)

	registry.Apply(RevocationRow{
		UserID: 41, Scope: ScopeJTI, JTI: "jti-a", NotBefore: now.Add(time.Minute),
	})
	if jtiMatch.closes.Load() != 1 {
		t.Fatalf("matching JTI connection closes = %d, want 1", jtiMatch.closes.Load())
	}
	if familyMatch.closes.Load() != 0 || sameUserOtherToken.closes.Load() != 0 || otherUser.closes.Load() != 0 {
		t.Fatal("JTI revocation closed a non-matching token session")
	}

	registry.Apply(RevocationRow{
		UserID: 41, Scope: ScopeFamily, FamilyID: "family-b", NotBefore: now.Add(time.Minute),
	})
	if familyMatch.closes.Load() != 1 {
		t.Fatalf("matching family connection closes = %d, want 1", familyMatch.closes.Load())
	}
	if sameUserOtherToken.closes.Load() != 0 || otherUser.closes.Load() != 0 {
		t.Fatal("family revocation closed a non-matching token session")
	}

	// Releases remain idempotent after targeted Apply removed registrations.
	releaseJTI()
	releaseJTI()
	releaseFamily()
	releaseOther()
	releaseOtherUser()
}

func TestProtocolSessionRegistryRejectsLateTargetedRegistration(t *testing.T) {
	t.Parallel()
	registry := NewProtocolSessionRegistry()
	now := time.Now().UTC()
	registry.Apply(RevocationRow{
		UserID: 51, Scope: ScopeJTI, JTI: "revoked-jti", NotBefore: now,
	})
	registry.Apply(RevocationRow{
		UserID: 51, Scope: ScopeFamily, FamilyID: "revoked-family", NotBefore: now,
	})

	staleJTI := &countedCloser{}
	registry.RegisterTokenSession(51, now, "revoked-jti", "fresh-family", staleJTI)
	if staleJTI.closes.Load() != 1 {
		t.Fatalf("late JTI registration closes = %d, want 1", staleJTI.closes.Load())
	}

	staleFamily := &countedCloser{}
	registry.RegisterTokenSession(51, now, "fresh-jti", "revoked-family", staleFamily)
	if staleFamily.closes.Load() != 1 {
		t.Fatalf("late family registration closes = %d, want 1", staleFamily.closes.Load())
	}

	fresh := &countedCloser{}
	releaseFresh := registry.RegisterTokenSession(51, now, "fresh-jti", "fresh-family", fresh)
	if fresh.closes.Load() != 0 {
		t.Fatal("unrelated token session was rejected")
	}
	releaseFresh()
}

func TestProtocolSessionRegistryPrunesExpiredTargetedKeys(t *testing.T) {
	t.Parallel()
	registry := NewProtocolSessionRegistry()
	now := time.Now().UTC()
	registry.Apply(RevocationRow{
		UserID: 61, Scope: ScopeJTI, JTI: "expired-jti",
		NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Second),
	})
	registry.Apply(RevocationRow{
		UserID: 61, Scope: ScopeFamily, FamilyID: "live-family",
		NotBefore: now, ExpiresAt: now.Add(time.Hour),
	})
	registry.Reconcile(nil)

	if len(registry.revokedJTI[61]) != 0 {
		t.Fatal("expired JTI key survived registry reconciliation")
	}
	if _, ok := registry.revokedFamily[61]["live-family"]; !ok {
		t.Fatal("active family key was pruned")
	}
}

func TestProtocolSessionRegistryRejectsMalformedRowsAndPrunesEveryExpiryClass(t *testing.T) {
	t.Parallel()
	var nilRegistry *ProtocolSessionRegistry
	nilRegistry.Apply(RevocationRow{})
	nilRegistry.Reconcile(nil)
	nilRegistry.Register(1, time.Now(), &countedCloser{})()

	registry := NewProtocolSessionRegistry()
	now := time.Now().UTC()
	invalidRegistrations := []struct {
		userID int64
		at     time.Time
		conn   *countedCloser
	}{
		{0, now, &countedCloser{}},
		{1, time.Time{}, &countedCloser{}},
		{1, now, nil},
	}
	for _, item := range invalidRegistrations {
		registry.Register(item.userID, item.at, item.conn)()
	}
	if len(registry.sessions) != 0 {
		t.Fatal("invalid registration entered the registry")
	}

	for _, row := range []RevocationRow{
		{},
		{UserID: 1, Scope: ScopeAll},
		{UserID: 1, Scope: ScopeAll, NotBefore: now, ExpiresAt: now.Add(-time.Second)},
		{UserID: 1, Scope: ScopeJTI, NotBefore: now},
		{UserID: 1, Scope: ScopeFamily, NotBefore: now},
		{UserID: 1, Scope: "unknown", NotBefore: now},
	} {
		registry.Apply(row)
	}
	if len(registry.allBefore) != 0 || len(registry.revokedJTI) != 0 ||
		len(registry.revokedFamily) != 0 {
		t.Fatal("malformed or expired revocation changed registry state")
	}

	registry.Apply(RevocationRow{
		UserID: 1, Scope: ScopeAll, NotBefore: now,
		ExpiresAt: now.Add(time.Minute),
	})
	registry.Apply(RevocationRow{
		UserID: 2, Scope: ScopeJTI, JTI: "expired",
		NotBefore: now, ExpiresAt: now.Add(time.Minute),
	})
	registry.Apply(RevocationRow{
		UserID: 3, Scope: ScopeFamily, FamilyID: "expired",
		NotBefore: now, ExpiresAt: now.Add(time.Minute),
	})
	registry.allBefore[1] = expiringWatermark{notBefore: now, expiresAt: now.Add(-time.Second)}
	registry.revokedJTI[2]["expired"] = now.Add(-time.Second)
	registry.revokedFamily[3]["expired"] = now.Add(-time.Second)
	registry.Reconcile(nil)
	if len(registry.allBefore) != 0 || len(registry.revokedJTI) != 0 ||
		len(registry.revokedFamily) != 0 {
		t.Fatal("expired watermark, JTI, or family state survived pruning")
	}
}
