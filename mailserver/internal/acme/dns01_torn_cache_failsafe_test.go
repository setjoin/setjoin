package acme

// Torn/partial cache-blob failsafe pin (ACME-001/002 serving-only contract):
// a cache blob that is garbage or truncated — e.g. left by a non-atomic
// writer or corrupted externally — must never be served, must never trigger
// issuance or account registration from the handshake path (no full issuance
// flow per affected handshake), and must mark the domain stale so ONLY the
// managed loop reissues. Atomic Put (writeFileAtomic) prevents torn blobs in
// the first place; this pins the defense-in-depth arm in GetCertificate.

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestGetCertificate_TornCacheBlob_FailsSafe_NoIssuance(t *testing.T) {
	fresh := genTestCert(t, []string{testDomain}, time.Now().Add(90*24*time.Hour))
	ctrl := newIssueController(fresh) // counted: handshake-path calls fail the assertions below
	reg := newRegCounter()
	mgr := newTestManager(t, t.TempDir(), "")
	mgr.issueFn = ctrl.issue
	mgr.registerFn = reg.observe(mgr)

	// Simulate torn blobs by writing corrupt bytes directly over the
	// normalized cache path, bypassing Put (which is atomic and would never
	// produce them): garbage, and the first half of a valid key+chain blob
	// (the truncation a crash mid-write would leave behind).
	good := blobOf(genTestCert(t, []string{testDomain}, time.Now().Add(90*24*time.Hour)))
	torn := []struct {
		label string
		blob  []byte
	}{
		{"garbage", []byte("torn mid-write: not a PEM payload at all")},
		{"truncated half-blob", good[:len(good)/2]},
	}
	for _, tc := range torn {
		if err := os.WriteFile(mgr.cache.certPath(testDomain), tc.blob, 0o600); err != nil {
			t.Fatalf("seed torn blob (%s): %v", tc.label, err)
		}

		// Failsafe serving: (nil, nil) so the tls.Config fallback chain
		// proceeds — never the torn bytes, never an error to the handshake.
		cert, err := mgr.GetCertificate(helloFor(testDomain))
		if cert != nil || err != nil {
			t.Fatalf("torn blob (%s): expected (nil, nil) fallback, got (%v, %v)", tc.label, cert, err)
		}
		// No issuance flow per affected handshake: zero obtain, zero register.
		if got := ctrl.count(); got != 0 {
			t.Fatalf("torn blob (%s): handshake lookup issued %d times; must be 0", tc.label, got)
		}
		if got := reg.count(); got != 0 {
			t.Fatalf("torn blob (%s): handshake lookup registered %d times; must be 0", tc.label, got)
		}
		// Fail-safe ≠ fail-silent forever: the corrupt blob marks the domain
		// stale so the managed loop reissues.
		if !mgr.needsRenewal(testDomain) {
			t.Fatalf("torn blob (%s): domain not marked stale; managed loop would never reissue", tc.label)
		}
	}

	// Recovery is managed-loop-only: one round replaces the torn blob with a
	// servable certificate.
	mgr.renewIfNeeded(context.Background())
	if got := ctrl.count(); got != 1 {
		t.Fatalf("managed recovery issued %d times; want exactly 1", got)
	}
	cert, err := mgr.GetCertificate(helloFor(testDomain))
	if err != nil || cert == nil || cert.Leaf == nil {
		t.Fatalf("post-recovery serve failed: (%v, %v)", cert, err)
	}
}
