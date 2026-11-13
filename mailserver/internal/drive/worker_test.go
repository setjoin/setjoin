package drive

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestGCDecide(t *testing.T) {
	now := time.Now()
	future := now.Add(24 * time.Hour)
	for _, tc := range []struct {
		refCount    int64
		retainUntil *time.Time
		want        gcAction
	}{
		{0, nil, gcDelete},   // zero-ref, unlocked → delete object + row
		{2, nil, gcDequeue},  // re-referenced after queueing → drop the queue row only
		{0, &future, gcSkip}, // WORM-retained → benign skip, retry later (§3.5)
	} {
		if got := gcDecide(tc.refCount, tc.retainUntil, now); got != tc.want {
			t.Errorf("gcDecide(%d,%v): want %v got %v", tc.refCount, tc.retainUntil, tc.want, got)
		}
	}
}

func TestTmpIsStale(t *testing.T) {
	now := time.Now()
	if tmpIsStale(time.Time{}, now) {
		t.Error("unknown tmp object age must fail safe")
	}
	if tmpIsStale(now.Add(-23*time.Hour), now) {
		t.Error("23h-old tmp object must survive (G8 window is 24h)")
	}
	if !tmpIsStale(now.Add(-25*time.Hour), now) {
		t.Error("25h-old tmp object must be reaped")
	}
}

func TestCanonicalOrphanIsStale(t *testing.T) {
	now := time.Now()
	if canonicalOrphanIsStale(time.Time{}, now) {
		t.Error("unknown canonical object age must fail safe")
	}
	if canonicalOrphanIsStale(now.Add(-canonicalOrphanReapWindow), now) {
		t.Error("an object exactly at the grace boundary must survive")
	}
	if !canonicalOrphanIsStale(now.Add(-canonicalOrphanReapWindow-time.Second), now) {
		t.Error("an object older than the grace boundary must be eligible")
	}
}

func TestParseCanonicalChunkKey(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		key        string
		wantScope  string
		wantSHA    string
		wantAccept bool
	}{
		{"drive/g/" + sha, "g", sha, true},
		{"drive/s42/" + sha, "s42", sha, true},
		{"tmp/upload/" + sha, "", "", false},
		{"drive/s0/" + sha, "", "", false},
		{"drive/s042/" + sha, "", "", false},
		{"drive/s-1/" + sha, "", "", false},
		{"drive/x42/" + sha, "", "", false},
		{"drive/g/" + strings.ToUpper(sha), "", "", false},
		{"drive/g/short", "", "", false},
		{"drive/g/" + sha + "/extra", "", "", false},
	} {
		scope, gotSHA, ok := parseCanonicalChunkKey(tc.key)
		if ok != tc.wantAccept || scope != tc.wantScope || gotSHA != tc.wantSHA {
			t.Errorf("parseCanonicalChunkKey(%q) = (%q,%q,%v), want (%q,%q,%v)",
				tc.key, scope, gotSHA, ok, tc.wantScope, tc.wantSHA, tc.wantAccept)
		}
	}
}

func TestCanonicalInventoryCursorBoundsAndRotates(t *testing.T) {
	empty := &Worker{
		store:              newFakeStore(),
		bucket:             "b",
		logger:             discardLogger(),
		canonicalScanAfter: "drive/g/" + strings.Repeat("f", 64),
	}
	if err := empty.reapCanonicalOrphans(context.Background()); err != nil {
		t.Fatalf("empty inventory: %v", err)
	}
	if empty.canonicalScanAfter != "" {
		t.Fatalf("an empty terminal page must reset the cursor, got %q", empty.canonicalScanAfter)
	}

	fake := newFakeStore()
	for i := 1; i <= canonicalInventoryBatchSize+5; i++ {
		key := "drive/g/" + fmt.Sprintf("%064x", i)
		fake.objects[key] = []byte("fresh")
		fake.putTimes[key] = time.Now()
	}
	w := &Worker{store: fake, bucket: "b", logger: discardLogger()}
	if err := w.reapCanonicalOrphans(context.Background()); err != nil {
		t.Fatalf("first inventory page: %v", err)
	}
	if w.canonicalScanAfter == "" {
		t.Fatal("a full inventory page must retain a continuation cursor")
	}
	if err := w.reapCanonicalOrphans(context.Background()); err != nil {
		t.Fatalf("second inventory page: %v", err)
	}
	if w.canonicalScanAfter != "" {
		t.Fatalf("short final page must reset the scan cursor, got %q", w.canonicalScanAfter)
	}
	if len(fake.removeKeys) != 0 {
		t.Fatalf("fresh objects must never be removed, got %v", fake.removeKeys)
	}
}

// TestGCDecideRefCountAndRetainUntilBothSet: a re-referenced chunk (ref_count
// > 0) dequeues even if it also happens to carry a future retain_until — the
// ref-count check comes first (a live reference always wins over the WORM
// skip branch, which only matters once ref_count is genuinely back to zero).
func TestGCDecideRefCountAndRetainUntilBothSet(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	if got := gcDecide(1, &future, now); got != gcDequeue {
		t.Errorf("gcDecide(1, future): want gcDequeue, got %v", got)
	}
}

// TestGCDecideExpiredRetention: retain_until in the PAST behaves like no
// retention at all — delete, not skip.
func TestGCDecideExpiredRetention(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	if got := gcDecide(0, &past, now); got != gcDelete {
		t.Errorf("gcDecide(0, past): want gcDelete, got %v", got)
	}
}

// TestReapTmpDeletesOnlyStaleObjects pins the G8 window pool-less: a fresh
// tmp object survives a tick, a 25h-old one is removed, and a non-tmp/upload/
// key is never touched regardless of age (prefix scoping).
func TestReapTmpDeletesOnlyStaleObjects(t *testing.T) {
	fake := newFakeStore()
	fake.objects["tmp/upload/fresh"] = []byte("x")
	fake.putTimes["tmp/upload/fresh"] = time.Now()
	fake.objects["tmp/upload/stale"] = []byte("y")
	fake.putTimes["tmp/upload/stale"] = time.Now().Add(-25 * time.Hour)
	fake.objects["drive/g/deadbeef"] = []byte("z") // a real canonical chunk, also 25h old
	fake.putTimes["drive/g/deadbeef"] = time.Now().Add(-25 * time.Hour)

	w := &Worker{store: fake, bucket: "b", logger: discardLogger()}
	if err := w.reapTmp(context.Background()); err != nil {
		t.Fatalf("reapTmp: %v", err)
	}

	if _, ok := fake.objects["tmp/upload/fresh"]; !ok {
		t.Error("fresh tmp object must survive")
	}
	if _, ok := fake.objects["tmp/upload/stale"]; ok {
		t.Error("stale tmp object must be reaped")
	}
	if _, ok := fake.objects["drive/g/deadbeef"]; !ok {
		t.Error("a canonical (non-tmp/upload/) key must never be reaped regardless of age")
	}
}
