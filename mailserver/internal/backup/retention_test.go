package backup

import (
	"testing"
	"time"
)

func TestRetention_ParseGFS(t *testing.T) {
	daily, weekly, monthly := parseGFS("7d4w12m")
	if daily != 7 {
		t.Errorf("daily = %d, want 7", daily)
	}
	if weekly != 4 {
		t.Errorf("weekly = %d, want 4", weekly)
	}
	if monthly != 12 {
		t.Errorf("monthly = %d, want 12", monthly)
	}
}

func TestRetention_ParseGFS_Empty(t *testing.T) {
	daily, weekly, monthly := parseGFS("")
	if daily != 7 || weekly != 4 || monthly != 12 {
		t.Errorf("empty scheme should default to 7d4w12m, got %dd%dw%dm",
			daily, weekly, monthly)
	}
}

// TestRetention_TieredNotFlatSum: one run per day for 30 consecutive days, policy
// 7d4w12m. The OLD flat-sum logic kept the newest 23 runs OUTRIGHT (deleting days
// 24-30). Real GFS keeps the 7 most-recent days PLUS one run per the 4 most-recent
// distinct ISO-weeks PLUS one per the 12 most-recent distinct months — so the 30
// daily runs (spanning ~4-5 weeks, 1-2 months) collapse to far fewer survivors than
// a flat 23, and the count of pruned runs is NOT simply 30-23=7.
func TestRetention_TieredNotFlatSum(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	var runs []retentionRun
	for d := 0; d < 30; d++ {
		runs = append(runs, retentionRun{ID: int64(1000 - d), Timestamp: gfsTS(now.AddDate(0, 0, -d))})
	}
	prune := runsToPrune(runs, RetentionPolicy{GFSScheme: "7d4w12m"})
	// The 7 newest days fill the daily tier; older runs only survive if they are the
	// newest in a still-open week or month bucket. 30 consecutive days span ~5 ISO-
	// weeks and 1-2 months, so most days 8-30 prune. A flat-sum keep-23 would prune
	// exactly 7 — assert we prune MORE than that (tiered collapse), proving the
	// newest-N-total logic is gone.
	if len(prune) <= 7 {
		t.Errorf("tiered GFS over 30 daily runs should prune more than the flat-sum 7, pruned %d", len(prune))
	}
	// The single newest run is always retained.
	pruned := idset(prune)
	if pruned[1000] {
		t.Errorf("newest run (ID 1000) was pruned — it fills the daily tier")
	}
}

// TestRetention_TieredKeepsAllWhenSparse: when runs are already one-per-distinct
// bucket and within the tier depths, nothing is pruned.
func TestRetention_TieredKeepsAllWhenSparse(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	runs := []retentionRun{
		{ID: 3, Timestamp: gfsTS(now)},
		{ID: 2, Timestamp: gfsTS(now.AddDate(0, 0, -1))},
		{ID: 1, Timestamp: gfsTS(now.AddDate(0, 0, -2))},
	}
	if got := runsToPrune(runs, RetentionPolicy{GFSScheme: "7d4w12m"}); len(got) != 0 {
		t.Errorf("three distinct recent days within the daily tier should prune nothing, got %d", len(got))
	}
}

// TestRetention_ParseGFS_ConcatenatedNonDefault: the canonical scheme is
// concatenated with no spaces ("3d2w1m"). The old space-split parser silently fell
// back to the 7,4,12 default for ANY concatenated scheme — the existing "7d4w12m"
// test only passed because the default happened to equal the expected.
func TestRetention_ParseGFS_ConcatenatedNonDefault(t *testing.T) {
	daily, weekly, monthly := parseGFS("3d2w1m")
	if daily != 3 || weekly != 2 || monthly != 1 {
		t.Errorf("parseGFS(3d2w1m) = %dd%dw%dm, want 3d2w1m", daily, weekly, monthly)
	}
}

// TestRetention_ParseGFS_Partial: an unspecified unit keeps its default.
func TestRetention_ParseGFS_Partial(t *testing.T) {
	daily, weekly, monthly := parseGFS("5d")
	if daily != 5 || weekly != 4 || monthly != 12 {
		t.Errorf("parseGFS(5d) = %dd%dw%dm, want 5d4w12m (defaults for w,m)", daily, weekly, monthly)
	}
}

// gfsTS formats a time into the canonical manifest-timestamp layout used by the
// backup engine (engine.go: time.Now().UTC().Format("20060102T150405Z")).
func gfsTS(tm time.Time) string { return tm.UTC().Format("20060102T150405Z") }

// idset collapses a slice of runs to a set of IDs for order-independent assertions.
func idset(runs []retentionRun) map[int64]bool {
	m := make(map[int64]bool, len(runs))
	for _, r := range runs {
		m[r.ID] = true
	}
	return m
}

// TestRunsToPrune_KeepsNewestPrunesOlder: five runs on five consecutive distinct
// calendar-days. "1d0w0m" keeps ONLY the newest day; the four older days prune.
func TestRunsToPrune_KeepsNewestPrunesOlder(t *testing.T) {
	base := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	runs := []retentionRun{
		{ID: 5, Timestamp: gfsTS(base)},                   // day 0 (newest)
		{ID: 4, Timestamp: gfsTS(base.AddDate(0, 0, -1))}, // day -1
		{ID: 3, Timestamp: gfsTS(base.AddDate(0, 0, -2))}, // day -2
		{ID: 2, Timestamp: gfsTS(base.AddDate(0, 0, -3))}, // day -3
		{ID: 1, Timestamp: gfsTS(base.AddDate(0, 0, -4))}, // day -4
	}
	prune := runsToPrune(runs, RetentionPolicy{GFSScheme: "1d0w0m"})
	got := idset(prune)
	if len(got) != 4 || got[5] || !got[4] || !got[3] || !got[2] || !got[1] {
		t.Errorf("prune = %+v, want the 4 oldest days (IDs 4,3,2,1)", prune)
	}
}

// TestRunsToPrune_UnderLimitNoPrune: fewer runs than the GFS keep-count prunes none.
func TestRunsToPrune_UnderLimitNoPrune(t *testing.T) {
	base := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	runs := []retentionRun{
		{ID: 2, Timestamp: gfsTS(base)},
		{ID: 1, Timestamp: gfsTS(base.AddDate(0, 0, -1))},
	}
	if got := runsToPrune(runs, RetentionPolicy{GFSScheme: "7d4w12m"}); len(got) != 0 {
		t.Errorf("under the keep-limit should prune nothing, got %d", len(got))
	}
}

// TestRunsToPrune_RealGFSTiers is the load-bearing test: it proves retention does
// REAL grandfather-father-son tiered bucketing, NOT newest-N-total.
//
// Fixture spans many days/weeks/months. With daily=7 weekly=4 monthly=12, the flat
// sum is 23, so a naive runs[23:] would keep the newest 23 runs OUTRIGHT and delete
// everything older — silently dropping the old monthly DR snapshots an operator who
// configured "12 monthly" expects to survive. Real GFS instead retains one run per
// distinct recent day/week/month, so an 8-month-old monthly snapshot survives while
// a same-day redundant run (older of two on one calendar day) is pruned.
func TestRunsToPrune_RealGFSTiers(t *testing.T) {
	// Anchor "now" deterministically. All offsets are relative to this.
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	day := func(d int) time.Time { return now.AddDate(0, 0, -d) }

	var runs []retentionRun
	add := func(id int64, tm time.Time) { runs = append(runs, retentionRun{ID: id, Timestamp: gfsTS(tm)}) }

	// Two runs on TODAY (day 0): a 12:00 and an earlier 09:00. The newest fills the
	// daily bucket; the redundant same-day 09:00 run must be PRUNED.
	add(100, now)                   // newest of the day → kept (daily)
	add(101, now.Add(-3*time.Hour)) // same calendar day, redundant → PRUNED

	// Recent distinct days 1..6 → fill the rest of the 7 daily buckets.
	add(106, day(1))
	add(105, day(2))
	add(104, day(3))
	add(103, day(4))
	add(102, day(5))
	add(99, day(6))

	// Older runs at weekly cadence (distinct ISO-weeks beyond the daily window) →
	// fill the 4 weekly buckets.
	add(90, day(10))
	add(89, day(17))
	add(88, day(24))
	add(87, day(31))

	// An 8-month-old monthly DR snapshot. Under a flat newest-23 sum this is FAR
	// past the cutoff and would be deleted. Real GFS keeps the newest run of each of
	// the most-recent 12 distinct months, so this MUST survive.
	oldMonthly := now.AddDate(0, -8, 0)
	add(50, oldMonthly)

	// A second run in that SAME old month, a day earlier → redundant monthly, PRUNED
	// (only the newest run within a month bucket is retained).
	add(49, oldMonthly.AddDate(0, 0, -1))

	policy := RetentionPolicy{GFSScheme: "7d4w12m"}
	prune := runsToPrune(runs, policy)
	pruned := idset(prune)

	// The old monthly snapshot survives (the whole point).
	if pruned[50] {
		t.Errorf("8-month-old monthly snapshot (ID 50) was pruned — real GFS must retain one run per recent month")
	}
	// The redundant same-day run is pruned.
	if !pruned[101] {
		t.Errorf("redundant same-day run (ID 101) was NOT pruned — only the newest run per day is retained")
	}
	// The redundant same-month run is pruned.
	if !pruned[49] {
		t.Errorf("redundant same-month run (ID 49) was NOT pruned — only the newest run per month is retained")
	}
	// The newest-of-day run is kept.
	if pruned[100] {
		t.Errorf("newest run of today (ID 100) was pruned — it fills the daily bucket")
	}

	// Sanity: a naive flat-sum keep-23 would retain ALL 17 runs here (17 ≤ 23) and
	// prune NOTHING — so any pruning at all proves tiered semantics are in effect.
	if len(prune) == 0 {
		t.Fatalf("nothing pruned — flat-sum newest-N logic still in effect (real GFS must prune redundant same-day/same-month runs)")
	}
}

// TestRunsToPrune_OneRunPerDistinctWeekAndMonth asserts that exactly one run per
// distinct recent week and month is retained (NOT newest-N-total): many redundant
// runs clustered in a few weeks/months collapse to one-per-bucket.
func TestRunsToPrune_OneRunPerDistinctWeekAndMonth(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

	var runs []retentionRun
	id := int64(0)
	add := func(tm time.Time) int64 {
		id++
		runs = append(runs, retentionRun{ID: id, Timestamp: gfsTS(tm)})
		return id
	}

	// daily=0 weekly=2 monthly=2: only week and month tiers are active.
	policy := RetentionPolicy{GFSScheme: "0d2w2m"}

	// Cluster A: three runs in the SAME ISO-week (this week). Newest kept, 2 pruned.
	weekNewest := add(now)
	weekRedundant1 := add(now.Add(-2 * time.Hour))
	weekRedundant2 := add(now.Add(-5 * time.Hour))

	// Cluster B: two runs last week → newest kept, 1 pruned.
	lastWeekNewest := add(now.AddDate(0, 0, -7))
	lastWeekRedundant := add(now.AddDate(0, 0, -8))

	// Cluster C: two runs ~2 months ago (a distinct month) → newest kept, 1 pruned.
	monthNewest := add(now.AddDate(0, -2, 0))
	monthRedundant := add(now.AddDate(0, -2, -1))

	prune := runsToPrune(runs, policy)
	pruned := idset(prune)

	kept := []struct {
		id   int64
		name string
	}{{weekNewest, "this-week newest"}, {lastWeekNewest, "last-week newest"}, {monthNewest, "2-months-ago newest"}}
	for _, k := range kept {
		if pruned[k.id] {
			t.Errorf("%s (ID %d) was pruned — it is the sole survivor of its bucket", k.name, k.id)
		}
	}
	for _, rid := range []int64{weekRedundant1, weekRedundant2, lastWeekRedundant, monthRedundant} {
		if !pruned[rid] {
			t.Errorf("redundant run (ID %d) was NOT pruned — only one run per distinct week/month is retained", rid)
		}
	}
}
