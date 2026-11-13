package threat

import (
	"context"
	"testing"
)

// newTestInterceptorWithSignInPool builds a minimal ThreatInterceptor that uses
// the given SignInPool for login_events writes. pool is nil so auth_attempts
// writes are skipped (nil-guarded in recordOutcome). lockout is nil (also guarded).
func newTestInterceptorWithSignInPool(sp SignInPool) *ThreatInterceptor {
	return &ThreatInterceptor{
		pool:   nil, // nil-guarded in recordOutcome and upsertDevice
		siPool: sp,
	}
}

// recordOutcome must invoke a login_events write for IMAP/SMTP outcomes.
func TestRecordOutcome_AlsoWritesLoginEvents(t *testing.T) {
	fp := &fakePool{} // fakePool satisfies SignInPool; defined in signin_test.go
	ti := newTestInterceptorWithSignInPool(fp)
	ti.recordOutcome(context.Background(),
		ConnectionMeta{SourceIP: "203.0.113.9", Protocol: ProtocolIMAP}, true, 42)
	// fakePool.tx is set when Begin is called (known-user path, userID=42).
	if fp.tx == nil {
		t.Fatal("recordOutcome did not write a login_events row (Begin not called)")
	}
	if !fp.tx.committed {
		t.Error("login_events transaction must be committed")
	}
}
