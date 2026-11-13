package storage

import (
	"testing"
	"time"
)

func TestResolveRetentionUpgrade(t *testing.T) {
	t0 := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	later := t0.Add(48 * time.Hour)
	cases := []struct {
		name      string
		curMode   string
		curUntil  time.Time
		reqMode   string
		reqUntil  time.Time
		wantApply bool
		wantMode  string
		wantUntil time.Time
	}{
		{"fresh object (no existing lock)", "", time.Time{}, "governance", t0, true, "governance", t0},
		{"lengthen", "governance", t0, "governance", later, true, "governance", later},
		{"shorten is a no-op, never weakens", "governance", later, "governance", t0, false, "governance", later},
		{"equal is a no-op", "governance", t0, "governance", t0, false, "governance", t0},
		{"mode may harden governance→compliance", "governance", t0, "compliance", t0, true, "compliance", t0},
		{"compliance is sticky — governance request keeps compliance", "compliance", later, "governance", later, false, "compliance", later},
		{"harden mode AND lengthen", "governance", t0, "compliance", later, true, "compliance", later},
		{"shorten but harden: keep longer date, apply harder mode", "governance", later, "compliance", t0, true, "compliance", later},
	}
	for _, c := range cases {
		mode, until, apply := resolveRetentionUpgrade(c.curMode, c.curUntil, c.reqMode, c.reqUntil)
		if apply != c.wantApply || mode != c.wantMode || !until.Equal(c.wantUntil) {
			t.Errorf("%s: got (%q,%v,%v) want (%q,%v,%v)", c.name, mode, until, apply, c.wantMode, c.wantUntil, c.wantApply)
		}
	}
}
