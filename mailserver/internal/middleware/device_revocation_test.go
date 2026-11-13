package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/toggle"
)

type fakeRevSet struct {
	hashes map[string]bool // sha256(fingerprint) hex
	err    error
}

func (f *fakeRevSet) load(_ context.Context) (map[string]bool, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.hashes, nil
}

func reqWithDevice(fp string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/jmap", nil)
	claims := &jwtutil.Claims{Device: &jwtutil.DeviceClaim{ID: fp}}
	return r.WithContext(auth.ContextWithUser(r.Context(), claims))
}

func hashFP(fp string) string {
	sum := sha256.Sum256([]byte(fp))
	return hex.EncodeToString(sum[:])
}

func TestDeviceRevocationGate(t *testing.T) {
	on := staticToggle{toggle.FeatureDeviceTrustEnforcement: true}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })

	t.Run("listed device 403 with valid JWT", func(t *testing.T) {
		set := &fakeRevSet{hashes: map[string]bool{hashFP("bad-fp"): true}}
		gate, _ := newDeviceRevocationGate(set.load, on, gateLogger())
		rr := httptest.NewRecorder()
		gate(next).ServeHTTP(rr, reqWithDevice("bad-fp"))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("code = %d, want 403", rr.Code)
		}
	})

	t.Run("clean device passes", func(t *testing.T) {
		set := &fakeRevSet{hashes: map[string]bool{}}
		gate, _ := newDeviceRevocationGate(set.load, on, gateLogger())
		rr := httptest.NewRecorder()
		gate(next).ServeHTTP(rr, reqWithDevice("good-fp"))
		if rr.Code != 200 {
			t.Fatalf("code = %d, want 200", rr.Code)
		}
	})

	t.Run("first-load DB error fails CLOSED (403, denylist never loaded)", func(t *testing.T) {
		// When the denylist has never loaded (cached==nil) and the DB is down,
		// the gate must DENY — a device with wipe_requested=true must not pass.
		set := &fakeRevSet{err: errors.New("db down")}
		gate, _ := newDeviceRevocationGate(set.load, on, gateLogger())
		rr := httptest.NewRecorder()
		gate(next).ServeHTTP(rr, reqWithDevice("any-fp"))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("first-load fail-CLOSED: code = %d, want 403", rr.Code)
		}
	})

	t.Run("stale cache used on refresh failure (no fail-open bypass)", func(t *testing.T) {
		// Prime the cache with "bad-fp" revoked, then make every reload fail.
		// With TTL=0 every request forces a reload; without stale-fallback fix the
		// device bypasses revocation on the second request.
		calls := 0
		loader := func(_ context.Context) (map[string]bool, error) {
			calls++
			if calls == 1 {
				return map[string]bool{hashFP("bad-fp"): true}, nil
			}
			return nil, errors.New("db down")
		}
		orig := revocationCacheTTL
		revocationCacheTTL = 0 // force TTL expiry on every request
		defer func() { revocationCacheTTL = orig }()

		gate, _ := newDeviceRevocationGate(loader, on, gateLogger())
		// First request: primes cache → blocked.
		rr1 := httptest.NewRecorder()
		gate(next).ServeHTTP(rr1, reqWithDevice("bad-fp"))
		if rr1.Code != http.StatusForbidden {
			t.Fatalf("initial block: code = %d, want 403", rr1.Code)
		}
		// Second request: TTL expired, reload fails → stale cache must still block.
		rr2 := httptest.NewRecorder()
		gate(next).ServeHTTP(rr2, reqWithDevice("bad-fp"))
		if rr2.Code != http.StatusForbidden {
			t.Fatalf("stale-fallback: code = %d, want 403 (revoked device bypassed gate)", rr2.Code)
		}
	})

	t.Run("toggle off is pure pass-through", func(t *testing.T) {
		off := staticToggle{toggle.FeatureDeviceTrustEnforcement: false}
		set := &fakeRevSet{hashes: map[string]bool{hashFP("bad-fp"): true}}
		gate, _ := newDeviceRevocationGate(set.load, off, gateLogger())
		rr := httptest.NewRecorder()
		gate(next).ServeHTTP(rr, reqWithDevice("bad-fp"))
		if rr.Code != 200 {
			t.Fatalf("toggle-off code = %d, want 200", rr.Code)
		}
	})

	t.Run("nil device claim passes (legacy/unenrolled)", func(t *testing.T) {
		set := &fakeRevSet{hashes: map[string]bool{hashFP("bad-fp"): true}}
		gate, _ := newDeviceRevocationGate(set.load, on, gateLogger())
		rr := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/jmap", nil)
		r = r.WithContext(auth.ContextWithUser(r.Context(), &jwtutil.Claims{}))
		gate(next).ServeHTTP(rr, r)
		if rr.Code != 200 {
			t.Fatalf("nil-device code = %d, want 200", rr.Code)
		}
	})
}
