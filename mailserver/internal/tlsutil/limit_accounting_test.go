package tlsutil

// Per-user connection-slot accounting pins (D-MAILSERVER-INTERNAL-IMAP-F-001
// fan-out). The IMAP identity-rebind bug orphaned a ConnTracker slot by
// overwriting the release callback without running it: the ORIGINAL user's
// count stayed consumed beyond the connection's disconnect and only explicit
// tracker reconciliation or tracker restart could restore it. These tests pin
// the tracker contract the fixed IMAP flow relies on: a plain disconnect
// release restores the exact count, release-then-acquire rebinds without
// leaking, per-user accounting is independent, and repeated acquire/release
// cycles converge to zero held slots (post-drain accounting restoration).

import (
	"errors"
	"testing"
)

func TestConnTrackerReleaseRestoresPerUserCountForReuse(t *testing.T) {
	var ct ConnTracker
	ct.SetMaxConns(1)

	release, err := ct.TryAcquire(101)
	if err != nil {
		t.Fatalf("first TryAcquire(101): %v", err)
	}
	if _, err := ct.TryAcquire(101); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("second TryAcquire(101) = %v, want ErrLimitExceeded", err)
	}

	// Disconnect-style release must restore the slot. The leak-beyond-disconnect
	// bug class is "the release callback never ran", which surfaces exactly here:
	// post-fix, this acquire succeeds; pre-fix (orphaned release), it could not.
	release()
	again, err := ct.TryAcquire(101)
	if err != nil {
		t.Fatalf("TryAcquire(101) after release = %v, want success (slot leaked)", err)
	}
	again()
}

func TestConnTrackerReleaseThenAcquireRebindsWithoutLeak(t *testing.T) {
	var ct ConnTracker
	ct.SetMaxConns(1)

	// Acquire-before-release at the limit: while the original slot is still
	// held, the rebind is refused. An implementation that then dropped the old
	// release callback would strand user 9's slot beyond disconnect — the
	// observable signature of the identity-rebind leak.
	held, err := ct.TryAcquire(9)
	if err != nil {
		t.Fatalf("TryAcquire(9): %v", err)
	}
	if _, err := ct.TryAcquire(9); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("TryAcquire(9) while original slot still held = %v, want ErrLimitExceeded", err)
	}
	held()

	// Release-then-acquire — the ordering the fixed IMAP auth flow uses —
	// rebinds the connection to another identity even at the per-user limit.
	first, err := ct.TryAcquire(9)
	if err != nil {
		t.Fatalf("TryAcquire(9) after release: %v", err)
	}
	first()
	second, err := ct.TryAcquire(10)
	if err != nil {
		t.Fatalf("TryAcquire(10) after release = %v, want success", err)
	}
	second()
}

func TestConnTrackerUsersAreIndependentAndConvergeToZero(t *testing.T) {
	var ct ConnTracker
	ct.SetMaxConns(1)

	holdA, err := ct.TryAcquire(1)
	if err != nil {
		t.Fatalf("TryAcquire(1): %v", err)
	}
	defer holdA()

	// One user's held slot must not disturb another user's accounting.
	relB, err := ct.TryAcquire(2)
	if err != nil {
		t.Fatalf("TryAcquire(2) while user 1 holds: %v", err)
	}
	relB()
	relB2, err := ct.TryAcquire(2)
	if err != nil {
		t.Fatalf("TryAcquire(2) after own release = %v, want success (cross-user drift)", err)
	}
	relB2()

	// Repeated acquire/release cycles converge to exactly zero held slots for
	// the user (the post-drain reconciliation the work package requires).
	for i := 0; i < 5; i++ {
		r, err := ct.TryAcquire(2)
		if err != nil {
			t.Fatalf("cycle %d TryAcquire(2): %v", i, err)
		}
		r()
	}
	if val, ok := ct.users.Load(int64(2)); ok {
		if got := *val.(*int32); got != 0 {
			t.Fatalf("user 2 count after cycles = %d, want 0", got)
		}
	}

	// Unlimited mode returns a usable no-op release.
	var unlimited ConnTracker
	rel, err := unlimited.TryAcquire(3)
	if err != nil {
		t.Fatalf("unlimited TryAcquire(3): %v", err)
	}
	rel()
}
