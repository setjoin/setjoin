package drive

// Pure unit tests for applyWormLocks (spec §3.4, G1) — no DB, no real
// storage: a fake storage.Retention (records calls, programmable per-key
// failure) and a fake dbExecer (records the mark-applied UPDATE calls).
// DB-backed coverage (the gxp put-version response override, the worker
// retry tick, the audit-verify route) lives in worm_live_test.go.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"setjoin.com/mailserver/internal/storage"
)

// fakeRetention implements storage.Retention: PutObjectRetention records the
// key and fails for any key in failKeys. Every other method is an unused
// stub — applyWormLocks only calls PutObjectRetention.
type fakeRetention struct {
	calls    []string
	failKeys map[string]bool
}

func (f *fakeRetention) PutObjectRetention(_ context.Context, key, _ string, _ time.Time) error {
	f.calls = append(f.calls, key)
	if f.failKeys[key] {
		return errors.New("fake: put retention failed")
	}
	return nil
}
func (f *fakeRetention) GetObjectRetention(context.Context, string) (*storage.RetentionStatus, error) {
	return nil, errors.New("fakeRetention: not implemented")
}
func (f *fakeRetention) PutObjectLegalHold(context.Context, string, string) error {
	return errors.New("fakeRetention: not implemented")
}
func (f *fakeRetention) GetObjectLegalHold(context.Context, string) (string, error) {
	return "", errors.New("fakeRetention: not implemented")
}
func (f *fakeRetention) EnsureBucketObjectLock(context.Context, string, int) error {
	return errors.New("fakeRetention: not implemented")
}
func (f *fakeRetention) GetBucketObjectLockConfig(context.Context) (*storage.BucketLockConfig, error) {
	return nil, errors.New("fakeRetention: not implemented")
}

// fakeExecer implements dbExecer: records every Exec call (sql + args).
type fakeExecer struct {
	calls   int
	lastSQL string
	failAll bool
}

func (f *fakeExecer) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	f.calls++
	f.lastSQL = sql
	if f.failAll {
		return pgconn.CommandTag{}, errors.New("fake: exec failed")
	}
	return pgconn.CommandTag{}, nil
}

func TestApplyWormLocksAllSucceed(t *testing.T) {
	ret := &fakeRetention{failKeys: map[string]bool{}}
	exec := &fakeExecer{}
	until := time.Now().Add(30 * 24 * time.Hour)

	pending := applyWormLocks(context.Background(), ret, exec, discardLogger(), "s1", "governance", until, []string{"aaa", "bbb"})

	if pending {
		t.Error("every chunk succeeded: want pending=false, got true")
	}
	wantKeys := []string{"drive/s1/aaa", "drive/s1/bbb"}
	if len(ret.calls) != len(wantKeys) {
		t.Fatalf("PutObjectRetention calls = %d, want %d", len(ret.calls), len(wantKeys))
	}
	for i, k := range wantKeys {
		if ret.calls[i] != k {
			t.Errorf("call %d key = %q, want %q", i, ret.calls[i], k)
		}
	}
	if exec.calls != 2 {
		t.Fatalf("mark-applied Exec calls = %d, want 2 (one per chunk)", exec.calls)
	}
}

// TestApplyWormLocksPartialFailure pins the per-chunk (not all-or-nothing)
// accounting: one failing chunk marks the batch pending, but the OTHER
// chunks that succeeded still get their mark-applied Exec — a retry must not
// re-attempt work that already landed.
func TestApplyWormLocksPartialFailure(t *testing.T) {
	ret := &fakeRetention{failKeys: map[string]bool{"drive/s1/bbb": true}}
	exec := &fakeExecer{}
	until := time.Now().Add(30 * 24 * time.Hour)

	pending := applyWormLocks(context.Background(), ret, exec, discardLogger(), "s1", "governance", until, []string{"aaa", "bbb", "ccc"})

	if !pending {
		t.Error("one chunk failed: want pending=true")
	}
	if len(ret.calls) != 3 {
		t.Fatalf("PutObjectRetention attempted on %d chunks, want 3 (every chunk attempted)", len(ret.calls))
	}
	if exec.calls != 2 {
		t.Fatalf("mark-applied Exec calls = %d, want 2 (aaa + ccc, NOT bbb)", exec.calls)
	}
}

// TestApplyWormLocksNilRetention pins the spec §12-22 fallback: no Retention
// capability configured on this deployment means every gxp chunk stays
// worm-pending — correct fail-closed, never silently "applied".
func TestApplyWormLocksNilRetention(t *testing.T) {
	pending := applyWormLocks(context.Background(), nil, &fakeExecer{}, discardLogger(), "s1", "governance", time.Now(), []string{"aaa"})
	if !pending {
		t.Error("nil Retention capability: want pending=true")
	}
}

// TestApplyWormLocksEmptyManifest: no chunks means nothing to lock — never
// pending (an empty version, or a lookup with no manifest, must not spuriously
// flag worm-pending).
func TestApplyWormLocksEmptyManifest(t *testing.T) {
	if applyWormLocks(context.Background(), nil, &fakeExecer{}, discardLogger(), "s1", "governance", time.Now(), nil) {
		t.Error("empty manifest: want pending=false")
	}
}

// TestApplyWormLocksMarkAppliedFailureStaysPending: PutObjectRetention
// succeeds but the bookkeeping Exec fails — the lock IS applied in storage,
// but since the DB can't confirm it, the chunk must stay pending so a future
// tick retries the (idempotent, lengthen-only) apply rather than silently
// losing track of it.
func TestApplyWormLocksMarkAppliedFailureStaysPending(t *testing.T) {
	ret := &fakeRetention{failKeys: map[string]bool{}}
	exec := &fakeExecer{failAll: true}
	pending := applyWormLocks(context.Background(), ret, exec, discardLogger(), "s1", "governance", time.Now(), []string{"aaa"})
	if !pending {
		t.Error("mark-applied Exec failed: want pending=true")
	}
}
