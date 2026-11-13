package storage

import "time"

// retentionModeRank orders WORM modes by strictness: compliance can never be
// relaxed to governance (S3 Object Lock semantics; mirrors the BZ142 no-downgrade
// posture in the drive schema).
func retentionModeRank(mode string) int {
	switch mode {
	case "compliance":
		return 2
	case "governance":
		return 1
	default:
		return 0 // no lock
	}
}

// resolveRetentionUpgrade merges an existing object lock with a requested one
// under WORM rules: retain-until may only LENGTHEN, mode may only HARDEN
// (governance→compliance), and the result is the pairwise maximum of both
// axes. apply == false means the existing lock already covers the request —
// the caller must not touch the object (no immutable-flag round-trip).
func resolveRetentionUpgrade(curMode string, curUntil time.Time, reqMode string, reqUntil time.Time) (mode string, until time.Time, apply bool) {
	mode = curMode
	if retentionModeRank(reqMode) > retentionModeRank(curMode) {
		mode = reqMode
	}
	until = curUntil
	if reqUntil.After(curUntil) {
		until = reqUntil
	}
	apply = mode != curMode || !until.Equal(curUntil)
	return mode, until, apply
}
