package ws

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/threat"
)

// shouldPushSessionRevoked decides whether a session_revoke payload targets this
// connection's user+session. Extracted as a pure helper so it is unit-testable.
func TestShouldPushSessionRevoked(t *testing.T) {
	issuedAt := time.Now().UTC()
	claims := &jwtutil.Claims{UserID: 7, JTI: "tok-abc", FamilyID: "fam-a"}
	claims.IssuedAt = jwtutil.NewNumericDate(issuedAt)
	before := issuedAt.Add(time.Second).Format(time.RFC3339Nano)
	after := issuedAt.Add(-time.Second).Format(time.RFC3339Nano)

	if !shouldPushSessionRevoked([]byte(`{"user_id":7,"scope":"all","not_before":"`+before+`"}`), claims) {
		t.Fatal("scope=all matching pre-watermark session must push")
	}
	if shouldPushSessionRevoked([]byte(`{"user_id":7,"scope":"all","not_before":"`+after+`"}`), claims) {
		t.Fatal("scope=all must not close a session issued after the watermark")
	}
	if shouldPushSessionRevoked([]byte(`{"user_id":8,"scope":"all","not_before":"`+before+`"}`), claims) {
		t.Fatal("non-matching user_id must NOT push")
	}
	if shouldPushSessionRevoked([]byte(`not json`), claims) {
		t.Fatal("garbage payload must NOT push")
	}
	if !shouldPushSessionRevoked([]byte(`{"user_id":7,"scope":"jti","jti":"tok-abc"}`), claims) {
		t.Fatal("scope=jti with matching JTI must push")
	}
	if shouldPushSessionRevoked([]byte(`{"user_id":7,"scope":"jti","jti":"tok-xyz"}`), claims) {
		t.Fatal("scope=jti with non-matching JTI must NOT push")
	}
	if !shouldPushSessionRevoked([]byte(`{"user_id":7,"scope":"family","family_id":"fam-a"}`), claims) {
		t.Fatal("scope=family with matching family must push")
	}
	if shouldPushSessionRevoked([]byte(`{"user_id":7,"scope":"family","family_id":"fam-b"}`), claims) {
		t.Fatal("scope=family must not close a sibling family")
	}
}

// TestDenylistDecisionUnloaded verifies that a non-nil denylist that has never successfully
// loaded (Loaded()==false) returns deny+shouldClose (fail-CLOSED). Prevents the WS gate from
// being asymmetric with RequireRuntimeAccess (Fix 4).
func TestDenylistDecisionUnloaded(t *testing.T) {
	// reconcileFn always errors → Refresh never sets loaded=true → Loaded()==false.
	dl := threat.NewSessionDenylist(func(context.Context) ([]threat.RevocationRow, error) {
		return nil, errors.New("db unavailable")
	}, slog.Default())
	claims := &jwtutil.Claims{UserID: 1, JTI: "tok"}
	claims.IssuedAt = jwtutil.NewNumericDate(time.Now())
	deny, shouldClose := denylistDecision(dl, claims)
	if !deny || !shouldClose {
		t.Fatalf("unloaded denylist must deny+close: deny=%v shouldClose=%v", deny, shouldClose)
	}
}

// TestDenylistDecisionNil verifies nil denylist passes through (not wired = no check).
func TestDenylistDecisionNil(t *testing.T) {
	claims := &jwtutil.Claims{UserID: 1}
	deny, shouldClose := denylistDecision(nil, claims)
	if deny || shouldClose {
		t.Fatalf("nil denylist must pass: deny=%v shouldClose=%v", deny, shouldClose)
	}
}

// TestDeviceRevocationDecision verifies the WS device-revocation gate (offline #2b):
// a revoked device's handleMessage call must be denied; clean/legacy devices pass.
func TestDeviceRevocationDecision(t *testing.T) {
	ctx := context.Background()

	t.Run("nil fn passes (not wired)", func(t *testing.T) {
		claims := &jwtutil.Claims{Device: &jwtutil.DeviceClaim{ID: "fp-1"}}
		if deviceRevocationDecision(ctx, nil, claims) {
			t.Fatal("nil fn must pass")
		}
	})

	t.Run("legacy device (no Device claim) passes", func(t *testing.T) {
		fn := func(context.Context, string) bool { return true }
		claims := &jwtutil.Claims{} // no Device
		if deviceRevocationDecision(ctx, fn, claims) {
			t.Fatal("no-device claim must pass")
		}
	})

	t.Run("revoked device denied", func(t *testing.T) {
		fn := func(_ context.Context, fp string) bool { return fp == "bad-fp" }
		claims := &jwtutil.Claims{Device: &jwtutil.DeviceClaim{ID: "bad-fp"}}
		if !deviceRevocationDecision(ctx, fn, claims) {
			t.Fatal("revoked device must be denied")
		}
	})

	t.Run("clean device passes", func(t *testing.T) {
		fn := func(_ context.Context, fp string) bool { return fp == "bad-fp" }
		claims := &jwtutil.Claims{Device: &jwtutil.DeviceClaim{ID: "good-fp"}}
		if deviceRevocationDecision(ctx, fn, claims) {
			t.Fatal("clean device must pass")
		}
	})

	t.Run("fail-CLOSED: fn returns true when denylist unloaded", func(t *testing.T) {
		// Simulates DeviceRevocationChecker.IsRevoked returning true when cache is nil.
		fn := func(context.Context, string) bool { return true } // unloaded → deny
		claims := &jwtutil.Claims{Device: &jwtutil.DeviceClaim{ID: "any-fp"}}
		if !deviceRevocationDecision(ctx, fn, claims) {
			t.Fatal("unloaded denylist must deny (fail-CLOSED)")
		}
	})
}
