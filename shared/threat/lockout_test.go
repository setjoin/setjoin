package threat

import (
	"context"
	"testing"
	"time"
)

type fakeLockoutStore struct {
	lockedKeys map[string]time.Duration // key -> remaining; presence = locked
	escalated  []string
	cleared    [][]string
	isLockErr  error // models the EXISTS-query error path: (false, 0, err)
	// remErr models the remaining-duration-query error sub-case: lockout was
	// established (locked=true) but the remaining query failed, so IsLocked
	// returns (true, 0, remErr) — exactly what pgxLockoutStore.IsLocked does.
	remErr error
}

func (f *fakeLockoutStore) IsLocked(_ context.Context, keys []string) (bool, time.Duration, error) {
	if f.isLockErr != nil {
		return false, 0, f.isLockErr
	}
	if f.remErr != nil {
		return true, 0, f.remErr
	}
	var maxRem time.Duration
	locked := false
	for _, k := range keys {
		if d, ok := f.lockedKeys[k]; ok {
			locked = true
			if d > maxRem {
				maxRem = d
			}
		}
	}
	return locked, maxRem, nil
}

func (f *fakeLockoutStore) Escalate(_ context.Context, key string) error {
	f.escalated = append(f.escalated, key)
	return nil
}

func (f *fakeLockoutStore) Clear(_ context.Context, keys []string) error {
	f.cleared = append(f.cleared, keys)
	return nil
}

func TestLockoutManager_Check_NoUsernameIsNoop(t *testing.T) {
	f := &fakeLockoutStore{}
	lm := NewLockoutManager(f, nil)
	locked, rem := lm.Check(context.Background(), ConnectionMeta{SourceIP: "1.2.3.4"}) // no Username
	if locked || rem != 0 {
		t.Fatalf("invariant: empty username must be no-op, got locked=%v rem=%v", locked, rem)
	}
}

func TestLockoutManager_Check_ReturnsMaxRemaining(t *testing.T) {
	f := &fakeLockoutStore{lockedKeys: map[string]time.Duration{
		"user:bob@x": 30 * time.Second,
		"ip:1.2.3.4": 90 * time.Second,
	}}
	lm := NewLockoutManager(f, nil)
	locked, rem := lm.Check(context.Background(), ConnectionMeta{SourceIP: "1.2.3.4", Username: "bob@x"})
	if !locked || rem != 90*time.Second {
		t.Fatalf("invariant: locked w/ max remaining, got locked=%v rem=%v", locked, rem)
	}
}

func TestLockoutManager_Check_RemainingQueryError_FailsClosed(t *testing.T) {
	// Security-critical: the EXISTS query reported locked=true, but the
	// remaining-duration query then errored. The original interceptor step 4
	// logged and STILL returned ActionReject/"lockout"/0 (fail-CLOSED — the
	// connection stays locked). Check must do the same: return (true, 0), never
	// admit a locked-out connection. This BITES a fail-open Check that collapses
	// any err -> (false, 0).
	f := &fakeLockoutStore{remErr: context.DeadlineExceeded}
	lm := NewLockoutManager(f, nil)
	locked, rem := lm.Check(context.Background(), ConnectionMeta{SourceIP: "1.2.3.4", Username: "bob@x"})
	if !locked || rem != 0 {
		t.Fatalf("invariant: locked-but-remaining-errored must fail CLOSED (true,0); got locked=%v rem=%v", locked, rem)
	}
}

func TestLockoutManager_Check_ExistsQueryError_FailsOpen(t *testing.T) {
	// The EXISTS query itself errored (lockout never established): fail OPEN —
	// admit the connection (false, 0), matching the original step 4.
	f := &fakeLockoutStore{isLockErr: context.DeadlineExceeded}
	lm := NewLockoutManager(f, nil)
	locked, rem := lm.Check(context.Background(), ConnectionMeta{SourceIP: "1.2.3.4", Username: "bob@x"})
	if locked || rem != 0 {
		t.Fatalf("invariant: EXISTS-query error must fail OPEN (false,0); got locked=%v rem=%v", locked, rem)
	}
}

func TestLockoutManager_Escalate_ThreeKeysInOrder(t *testing.T) {
	f := &fakeLockoutStore{}
	lm := NewLockoutManager(f, nil)
	lm.Escalate(context.Background(), ConnectionMeta{SourceIP: "1.2.3.4", Username: "bob@x"})
	want := []string{"ip:1.2.3.4", "user:bob@x", "ip_user:1.2.3.4:bob@x"}
	if len(f.escalated) != 3 || f.escalated[0] != want[0] || f.escalated[1] != want[1] || f.escalated[2] != want[2] {
		t.Fatalf("invariant: escalate ip,user,ip_user in order; got %v", f.escalated)
	}
}

func TestLockoutManager_Escalate_NoUsernameIsNoop(t *testing.T) {
	f := &fakeLockoutStore{}
	lm := NewLockoutManager(f, nil)
	lm.Escalate(context.Background(), ConnectionMeta{SourceIP: "1.2.3.4"})
	if len(f.escalated) != 0 {
		t.Fatalf("invariant: no username -> no escalation; got %v", f.escalated)
	}
}

func TestLockoutManager_Reset_ClearsThreeKeys(t *testing.T) {
	f := &fakeLockoutStore{}
	lm := NewLockoutManager(f, nil)
	lm.Reset(context.Background(), ConnectionMeta{SourceIP: "1.2.3.4", Username: "bob@x"})
	if len(f.cleared) != 1 || len(f.cleared[0]) != 3 {
		t.Fatalf("invariant: reset clears exactly the three keys once; got %v", f.cleared)
	}
}

func TestLockoutManager_Reset_NoUsernameIsNoop(t *testing.T) {
	f := &fakeLockoutStore{}
	lm := NewLockoutManager(f, nil)
	lm.Reset(context.Background(), ConnectionMeta{SourceIP: "1.2.3.4"})
	if len(f.cleared) != 0 {
		t.Fatalf("invariant: no username -> no reset; got %v", f.cleared)
	}
}
