package cron

import (
	"testing"
	"time"
)

func TestTaskDue_EveryInterval(t *testing.T) {
	now := time.Date(2026, 6, 1, 3, 30, 0, 0, time.UTC)
	task := &Task{
		Name:     "test-every",
		Schedule: "@every 1m",
		SQL:      "SELECT 1",
	}
	if err := task.prepare(); err != nil {
		t.Fatal(err)
	}
	task.lastRun = now.Add(-61 * time.Second)
	if !task.Due(now) {
		t.Error("task should be due 61s after last run with @every 1m")
	}

	task.lastRun = now.Add(-30 * time.Second)
	if task.Due(now) {
		t.Error("task should NOT be due 30s after last run with @every 1m")
	}
}

func TestTaskDue_CronExpression(t *testing.T) {
	// "30 3 * * *" — should match 03:30, not 03:31
	task := &Task{
		Name:     "test-cron",
		Schedule: "30 3 * * *",
		SQL:      "SELECT 1",
	}
	if err := task.prepare(); err != nil {
		t.Fatal(err)
	}

	// At exactly 03:30, should be due (within this minute)
	ref := time.Date(2026, 6, 1, 3, 30, 0, 0, time.UTC)
	if !task.matchesCron(ref) {
		t.Error("30 3 * * * should match 03:30")
	}
	if task.matchesCron(ref.Add(1 * time.Minute)) {
		t.Error("30 3 * * * should NOT match 03:31")
	}
}

// TestTaskDue_CronNotFiredTwiceInSameMinute pins the fix for the 60x-per-minute
// bug: Due() for a cron task must return false if lastRun is already within the
// current matching minute (i.e. we already fired this minute).
func TestTaskDue_CronNotFiredTwiceInSameMinute(t *testing.T) {
	task := &Task{
		Name:     "test-cron-once",
		Schedule: "30 3 * * *",
		SQL:      "SELECT 1",
	}
	if err := task.prepare(); err != nil {
		t.Fatal(err)
	}

	// Simulate: it's 03:30:45 and we already ran at 03:30:00 this minute.
	now := time.Date(2026, 6, 1, 3, 30, 45, 0, time.UTC)
	task.lastRun = time.Date(2026, 6, 1, 3, 30, 0, 0, time.UTC)

	// matchesCron returns true for this minute, but Due() must return false
	// because lastRun.Truncate(minute) == now.Truncate(minute).
	if task.Due(now) {
		t.Error("same-minute check logic error: should not be due when already ran this minute")
	}

	// Previous minute: lastRun was in the minute before — should be due.
	task.lastRun = time.Date(2026, 6, 1, 3, 29, 0, 0, time.UTC)
	if !task.Due(now) {
		t.Error("should be due when lastRun was in a previous minute and cron matches")
	}
}

func TestParseSchedule(t *testing.T) {
	tests := []struct {
		schedule string
		wantErr  bool
		interval time.Duration
		cron     string
	}{
		{"@every 5m", false, 5 * time.Minute, ""},
		{"@every 2s", false, 2 * time.Second, ""},
		{"@every 1h", false, 1 * time.Hour, ""},
		{"30 3 * * *", false, 0, "30 3 * * *"},
		{"*/5 * * * *", false, 0, "*/5 * * * *"},
		{"60 * * * *", true, 0, ""},
		{"*/0 * * * *", true, 0, ""},
		{"@every 0s", true, 0, ""},
		{"bad", true, 0, ""},
	}

	for _, tt := range tests {
		interval, cronExpr, err := parseSchedule(tt.schedule)
		if tt.wantErr && err == nil {
			t.Errorf("parseSchedule(%q) expected error", tt.schedule)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("parseSchedule(%q) unexpected error: %v", tt.schedule, err)
		}
		if interval != tt.interval {
			t.Errorf("parseSchedule(%q) interval = %v, want %v", tt.schedule, interval, tt.interval)
		}
		if cronExpr != tt.cron {
			t.Errorf("parseSchedule(%q) cronExpr = %q, want %q", tt.schedule, cronExpr, tt.cron)
		}
	}
}

// TestCronCatchUp_MissedSlotFiresOnRecovery pins the catch-up semantics
// (D-MAILSERVER-INTERNAL-CRON-003): a stall spanning the ENTIRE matching
// minute (wall-clock 02:40 slot missed, recovery at 02:41+) must still fire —
// the old wall-clock-only check silently skipped the window.
func TestCronCatchUp_MissedSlotFiresOnRecovery(t *testing.T) {
	tk := &Task{Name: "t", Schedule: "40 2 * * *", Timeout: time.Second, cronExpr: "40 2 * * *"}
	// Last fire at 02:35; the 02:40 slot was missed entirely; recovery at 02:41.
	tk.lastRun = time.Date(2026, 9, 12, 2, 35, 0, 0, time.Local)
	now := time.Date(2026, 9, 12, 2, 41, 30, 0, time.Local)

	if !tk.Due(now) {
		t.Error("a missed matching minute inside the stall must make the task due on recovery")
	}
}

// TestCronCatchUp_NoRefireAfterNormalRun is the companion control: after a
// normal in-slot fire the task must NOT become due again while scanning the
// already-fired slot, and a non-matching minute right after a fresh fire stays
// not-due.
func TestCronCatchUp_NoRefireAfterNormalRun(t *testing.T) {
	tk := &Task{Name: "t", Schedule: "40 2 * * *", Timeout: time.Second, cronExpr: "40 2 * * *"}
	fired := time.Date(2026, 9, 12, 2, 40, 0, 500_000, time.Local)
	tk.lastRun = fired

	if tk.Due(fired.Add(500 * time.Millisecond)) {
		t.Error("the fired slot must not re-arm within the same minute")
	}
	if tk.Due(time.Date(2026, 9, 12, 2, 41, 0, 0, time.Local)) {
		t.Error("the minute after a normal fire must not be due (slot already consumed)")
	}
}

// TestCronCatchUp_NeverRunWaitsForSlot: a task that has never fired must wait
// for its first matching minute (the catch-up scan must not fire it outright
// off the zero-time lastRun).
func TestCronCatchUp_NeverRunWaitsForSlot(t *testing.T) {
	tk := &Task{Name: "t", Schedule: "40 2 * * *", Timeout: time.Second, cronExpr: "40 2 * * *"}
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.Local)
	if tk.Due(now) {
		t.Error("never-run task with a non-matching current minute must stay not-due")
	}
	if !tk.Due(time.Date(2026, 9, 12, 2, 40, 30, 0, time.Local)) {
		t.Error("never-run task must fire on its first matching minute")
	}
}
