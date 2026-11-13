package backup

import (
	"regexp"
	"strconv"
	"time"
)

// gfsRe matches one number+unit pair in a GFS scheme ("7d", "4w", "12m"),
// concatenated or space-separated.
var gfsRe = regexp.MustCompile(`(\d+)([dwm])`)

// gfsTSLayout is the canonical manifest-timestamp layout the backup engine writes
// (engine.go: time.Now().UTC().Format("20060102T150405Z")). retentionRun.Timestamp
// is this string; GFS bucketing parses it back into a time to classify the run.
const gfsTSLayout = "20060102T150405Z"

// RetentionPolicy controls how many backup runs are retained, as a
// grandfather-father-son (GFS) tiered scheme. Each backup-manifest-<ts>.json is a
// SELF-CONTAINED restore point (BuildBlobManifest lists every live blob, not a
// delta), so retention prunes whole runs' index objects — never blobs.
//
// The counts are TIER DEPTHS, not a flat total: `daily` distinct most-recent
// calendar-days, `weekly` distinct most-recent ISO-weeks, `monthly` distinct
// most-recent calendar-months. A run is retained if it is the newest run within ANY
// retained day/week/month bucket; it is pruned only if it falls into none. So "keep
// 12 monthly" really retains 12 distinct months — an old monthly DR snapshot
// survives even when many newer runs exist (the flat-sum `runs[N:]` predecessor
// silently deleted it).
type RetentionPolicy struct {
	GFSScheme string // "7d4w12m" = 7 daily + 4 weekly + 12 monthly tier depths
}

// retentionRun is a completed backup run eligible for GFS pruning — its id (to
// delete the backup_runs row) and the manifest timestamp (to build the per-run
// index object keys AND to classify it into day/week/month buckets).
type retentionRun struct {
	ID        int64
	Timestamp string
}

// runsToPrune returns the runs to delete under REAL GFS tiered bucketing. runs MUST
// be newest-first. A run is RETAINED if it is:
//   - the newest run within any of the most-recent `daily` distinct calendar-days, OR
//   - the newest run within any of the most-recent `weekly` distinct ISO-weeks, OR
//   - the newest run within any of the most-recent `monthly` distinct calendar-months.
//
// A run is pruned only when it falls into NONE of those retained buckets. A run
// whose timestamp cannot be parsed is conservatively RETAINED (never prune what we
// cannot classify — this is a DR feature). Pure — testable without a DB or store.
func runsToPrune(runs []retentionRun, policy RetentionPolicy) []retentionRun {
	daily, weekly, monthly := parseGFS(policy.GFSScheme)

	// Track which tier-buckets are already filled and, within a bucket, whether the
	// newest run has been claimed. Because `runs` is newest-first, the FIRST run we
	// see for a bucket key is that bucket's newest → retained; later runs in the
	// same bucket are redundant for that tier.
	type bucketState struct {
		seen  map[string]bool // bucket key → newest already retained
		count int             // distinct buckets retained so far
		depth int             // tier depth (how many distinct buckets to keep)
	}
	day := bucketState{seen: map[string]bool{}, depth: daily}
	week := bucketState{seen: map[string]bool{}, depth: weekly}
	month := bucketState{seen: map[string]bool{}, depth: monthly}

	// retain reports whether this run is the newest in a not-yet-full bucket of the
	// given tier (and, as a side effect, records the bucket as filled).
	retain := func(bs *bucketState, key string) bool {
		if bs.depth <= 0 {
			return false
		}
		if bs.seen[key] {
			return false // an earlier (newer) run already claimed this bucket
		}
		if bs.count >= bs.depth {
			return false // this tier's quota of distinct buckets is exhausted
		}
		bs.seen[key] = true
		bs.count++
		return true
	}

	var prune []retentionRun
	for _, r := range runs {
		tm, err := time.Parse(gfsTSLayout, r.Timestamp)
		if err != nil {
			// Unclassifiable timestamp → retain conservatively (data-loss-safe).
			continue
		}
		tm = tm.UTC()

		dayKey := tm.Format("2006-01-02")
		isoYear, isoWeek := tm.ISOWeek()
		weekKey := strconv.Itoa(isoYear) + "-W" + strconv.Itoa(isoWeek)
		monthKey := tm.Format("2006-01")

		// Evaluate all three tiers; OR semantics — retained if ANY tier keeps it.
		// Evaluate each (not short-circuit) so a run retained by the daily tier ALSO
		// claims its week/month bucket, preventing a later run from filling that
		// bucket when this newer one already covers it.
		keepDay := retain(&day, dayKey)
		keepWeek := retain(&week, weekKey)
		keepMonth := retain(&month, monthKey)

		if !keepDay && !keepWeek && !keepMonth {
			prune = append(prune, r)
		}
	}
	return prune
}

// parseGFS parses a GFS scheme like "7d4w12m" — concatenated number+unit pairs
// (spaces tolerated). Returns daily, weekly, monthly tier depths; an unspecified
// unit keeps its default (7, 4, 12). The earlier space-split parser silently fell
// back to all-defaults for the canonical concatenated form.
func parseGFS(scheme string) (daily, weekly, monthly int) {
	daily, weekly, monthly = 7, 4, 12
	for _, m := range gfsRe.FindAllStringSubmatch(scheme, -1) {
		val, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		switch m[2] {
		case "d":
			daily = val
		case "w":
			weekly = val
		case "m":
			monthly = val
		}
	}
	return
}
