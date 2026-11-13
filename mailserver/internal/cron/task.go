package cron

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Task represents one reducer-backed scheduled operation. Scheduling state is
// guarded by mu; Worker is the only production caller of reserve/complete.
type Task struct {
	Name     string
	Schedule string
	SQL      string
	Timeout  time.Duration
	enabled  bool

	interval time.Duration
	cronExpr string
	lastRun  time.Time
	lastErr  string
	lastOK   time.Time
	running  bool
	mu       sync.RWMutex
}

func (t *Task) prepare() error {
	if t.Name == "" {
		return fmt.Errorf("cron task name is required")
	}
	if t.SQL == "" {
		return fmt.Errorf("cron task %q SQL is required", t.Name)
	}
	interval, cronExpr, err := parseSchedule(t.Schedule)
	if err != nil {
		return fmt.Errorf("cron task %q: %w", t.Name, err)
	}
	if t.Timeout <= 0 {
		t.Timeout = 30 * time.Second
	}
	t.interval = interval
	t.cronExpr = cronExpr
	return nil
}

// Due reports schedule eligibility at now. It does not reserve the task;
// Worker.reserve performs that state transition atomically with single-flight.
func (t *Task) Due(now time.Time) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.dueLocked(now)
}

// maxCatchupScanMinutes bounds the missed-slot scan in dueLocked. One day of
// minutes covers every schedule that fires at least daily without a full
// cron-next-time calculator; gaps longer than the cap fall through to the
// always-due branch (a stalled schedule certainly came due within a day+).
const maxCatchupScanMinutes = 1440

func (t *Task) dueLocked(now time.Time) bool {
	if t.interval > 0 {
		return now.Sub(t.lastRun) >= t.interval
	}
	if t.cronExpr != "" {
		// Fast path: the current minute matches and has not fired yet.
		if t.matchesCron(now) && t.lastRun.Truncate(time.Minute).Before(now.Truncate(time.Minute)) {
			return true
		}
		// Catch-up (D-MAILSERVER-INTERNAL-CRON-003): the old wall-clock-only
		// check silently skipped the slot whenever a stall (>60s admission
		// gap, downtime, DST shift) spanned the ENTIRE matching minute. Scan
		// the missed minutes between the last fire and now — if any of them
		// matched the expression, the task is due NOW instead of skipped.
		return t.matchedMinuteSince(now)
	}
	return false
}

// matchedMinuteSince reports whether any minute-slot S with
// lastRun < S <= now (minute-truncated) matches the cron expression, scanning
// at most maxCatchupScanMinutes slots back from now. A gap longer than the cap
// is treated as overdue (always true): every schedule that fires at least once
// per day is provably missed by then, and the reducers behind these tasks are
// idempotent — over-firing after a long stall is safe, silently skipping a
// retention/purge/anchor window is not.
func (t *Task) matchedMinuteSince(now time.Time) bool {
	first := t.lastRun.Truncate(time.Minute)
	if t.lastRun.IsZero() {
		// Never fired: no missed slots exist — wait for the first matching
		// minute via the fast path instead of scanning from the zero time.
		return false
	}
	slot := now.Truncate(time.Minute)
	scanned := 0
	for slot.After(first) {
		if scanned >= maxCatchupScanMinutes {
			return true // stall beyond the scan horizon: treat as overdue
		}
		if t.matchesCron(slot) {
			return true
		}
		scanned++
		slot = slot.Add(-time.Minute)
	}
	return false
}

func (t *Task) reserve(now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.enabled || t.running || !t.dueLocked(now) {
		return false
	}
	t.running = true
	t.lastRun = now
	return true
}

func (t *Task) complete(now time.Time, errText string, success bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.running = false
	t.lastErr = errText
	if success {
		t.lastOK = now
	}
}

func (t *Task) matchesCron(now time.Time) bool {
	fields := strings.Fields(t.cronExpr)
	if len(fields) != 5 {
		return false
	}
	return matchField(fields[0], now.Minute(), 0, 59) &&
		matchField(fields[1], now.Hour(), 0, 23) &&
		matchField(fields[2], now.Day(), 1, 31) &&
		matchField(fields[3], int(now.Month()), 1, 12) &&
		matchField(fields[4], int(now.Weekday()), 0, 6)
}

func matchField(expr string, value, _, _ int) bool {
	if expr == "*" {
		return true
	}
	if strings.HasPrefix(expr, "*/") {
		step, _ := strconv.Atoi(expr[2:])
		return step > 0 && value%step == 0
	}
	n, err := strconv.Atoi(expr)
	return err == nil && n == value
}

func validateCronField(expr string, min, max int) error {
	if expr == "*" {
		return nil
	}
	if strings.HasPrefix(expr, "*/") {
		step, err := strconv.Atoi(expr[2:])
		if err == nil && step > 0 && step <= max-min+1 {
			return nil
		}
		return fmt.Errorf("invalid cron step %q", expr)
	}
	value, err := strconv.Atoi(expr)
	if err != nil || value < min || value > max {
		return fmt.Errorf("invalid cron field %q (want %d..%d)", expr, min, max)
	}
	return nil
}

func parseSchedule(s string) (time.Duration, string, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "@every ") {
		d, err := time.ParseDuration(s[7:])
		if err != nil || d <= 0 {
			return 0, "", fmt.Errorf("invalid @every duration %q", s[7:])
		}
		return d, "", nil
	}
	fields := strings.Fields(s)
	if len(fields) != 5 {
		return 0, "", fmt.Errorf("invalid schedule: %q (want @every X or 5-field cron)", s)
	}
	bounds := [][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 6}}
	for i, field := range fields {
		if err := validateCronField(field, bounds[i][0], bounds[i][1]); err != nil {
			return 0, "", fmt.Errorf("invalid schedule %q: %w", s, err)
		}
	}
	return 0, s, nil
}
