//! Process-wide summary of refusal rows that `refusal_budget` suppressed (CWE-779).
//! Suppressed rows are counted per outcome, not logged per event. At most one stderr
//! line per `EMIT_INTERVAL` per process carries the counts. The line has no source IP,
//! username or user agent.
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The outcomes `refusal_budget` accepts, in counter-index order.
const OUTCOMES: [&str; 6] = [
    "captcha_needed",
    "rate_limited",
    "lockout",
    "spray_detected",
    "geo_blocked",
    "threat_blocked",
];
const EMIT_INTERVAL: Duration = Duration::from_secs(60);

/// Per-outcome suppressed-row counters plus the monotonic instant of the last report.
/// `None` means nothing was reported yet, so the first suppression is reported at once.
pub struct SuppressedRefusals {
    counts: [AtomicU64; OUTCOMES.len()],
    last_report: Mutex<Option<Instant>>,
}

impl SuppressedRefusals {
    pub const fn new() -> Self {
        Self {
            counts: [const { AtomicU64::new(0) }; OUTCOMES.len()],
            last_report: Mutex::new(None),
        }
    }

    /// Counts one suppressed row. Outcomes outside `OUTCOMES` are ignored.
    pub fn count(&self, outcome: &str) {
        if let Some(slot) = index(outcome) {
            self.counts[slot].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Reports the pending counts when `EMIT_INTERVAL` has passed since the last report. `now`
    /// decides whether a report is due. `done` is read after the write and stamps the last
    /// report, so the interval runs from completion. The line is written to `out` while the lock
    /// is held; the lock is released only after the write. A busy or poisoned lock is skipped
    /// (never waited on, never a panic) and the counts stay for a later call. Returns the
    /// non-zero counts that were reported.
    pub fn report_at<W: Write>(
        &self,
        now: Instant,
        out: &mut W,
        done: impl FnOnce() -> Instant,
    ) -> Option<Vec<(&'static str, u64)>> {
        let Ok(mut last) = self.last_report.try_lock() else {
            return None;
        };
        let due = match *last {
            None => true,
            Some(previous) => now.duration_since(previous) >= EMIT_INTERVAL,
        };
        if !due {
            return None;
        }
        let counts: Vec<(&'static str, u64)> = OUTCOMES
            .iter()
            .zip(self.counts.iter())
            .filter_map(|(name, count)| {
                let n = count.swap(0, Ordering::AcqRel);
                (n > 0).then_some((*name, n))
            })
            .collect();
        if counts.is_empty() {
            return None;
        }
        let summary = counts
            .iter()
            .map(|(name, n)| format!("{name}={n}"))
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(
            out,
            "threat refusal rows suppressed by budget (since last report): {summary}"
        );
        *last = Some(done());
        Some(counts)
    }
}

impl Default for SuppressedRefusals {
    fn default() -> Self {
        Self::new()
    }
}

/// Counter index for an outcome `refusal_budget` accepts; `None` for any other string.
fn index(outcome: &str) -> Option<usize> {
    OUTCOMES.iter().position(|known| *known == outcome)
}

static SUPPRESSED: SuppressedRefusals = SuppressedRefusals::new();

/// Records one refusal row that the budget suppressed (its INSERT wrote 0 rows) and reports a
/// summary when one is due. Call it only for budgeted outcomes and not on database errors. The
/// first suppression after start is reported at once, then at most one stderr line per 60 s.
pub fn note_suppressed_refusal(outcome: &str) {
    SUPPRESSED.count(outcome);
    let _ = SUPPRESSED.report_at(Instant::now(), &mut std::io::stderr(), Instant::now);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;
    use std::sync::Barrier;
    use std::thread;

    /// Outcome strings the auth_attempts CHECK names, plus the Rust-only ones the gate uses.
    const KNOWN: [&str; 11] = [
        "captcha_needed",
        "rate_limited",
        "lockout",
        "spray_detected",
        "geo_blocked",
        "threat_blocked",
        "success",
        "failure",
        "tarpit_applied",
        "ip_blocked",
        "conditional_access_blocked",
    ];

    fn fresh() -> SuppressedRefusals {
        SuppressedRefusals::new()
    }

    fn reported_at(t: Instant) -> SuppressedRefusals {
        let s = SuppressedRefusals::new();
        *s.last_report.lock().unwrap() = Some(t);
        s
    }

    fn report(s: &SuppressedRefusals, now: Instant) -> Option<Vec<(&'static str, u64)>> {
        s.report_at(now, &mut Vec::<u8>::new(), || now)
    }

    fn counter(s: &SuppressedRefusals, outcome: &str) -> u64 {
        s.counts[index(outcome).unwrap()].load(Ordering::Relaxed)
    }

    #[test]
    fn counts_accumulate_and_nothing_reports_before_sixty_seconds() {
        let t0 = Instant::now();
        let s = reported_at(t0);
        s.count("captcha_needed");
        s.count("captcha_needed");
        s.count("rate_limited");
        assert_eq!(report(&s, t0 + Duration::from_secs(59)), None);
        assert_eq!(counter(&s, "captcha_needed"), 2);
        assert_eq!(counter(&s, "rate_limited"), 1);
    }

    #[test]
    fn one_report_at_sixty_seconds_carries_nonzero_counts_and_resets() {
        let t0 = Instant::now();
        let s = reported_at(t0);
        s.count("captcha_needed");
        s.count("captcha_needed");
        s.count("rate_limited");
        s.count("lockout");
        let mut sink = Vec::<u8>::new();
        let reported = s.report_at(t0 + Duration::from_secs(60), &mut sink, || {
            t0 + Duration::from_secs(60)
        });
        assert_eq!(
            reported,
            Some(vec![
                ("captcha_needed", 2),
                ("rate_limited", 1),
                ("lockout", 1)
            ])
        );
        assert_eq!(
            String::from_utf8(sink).unwrap(),
            "threat refusal rows suppressed by budget (since last report): captcha_needed=2 rate_limited=1 lockout=1\n"
        );
        assert!(s.counts.iter().all(|c| c.load(Ordering::Relaxed) == 0));
        // The next report waits its own 60 s from the last one.
        s.count("lockout");
        assert_eq!(report(&s, t0 + Duration::from_secs(61)), None);
        assert_eq!(
            report(&s, t0 + Duration::from_secs(120)),
            Some(vec![("lockout", 1)])
        );
    }

    #[test]
    fn the_interval_runs_from_completion_not_from_the_due_check() {
        let base = Instant::now();
        let s = fresh();
        s.count("lockout");
        let done_at = base + Duration::from_secs(90);
        let reported = s.report_at(base, &mut Vec::<u8>::new(), || done_at);
        assert_eq!(reported, Some(vec![("lockout", 1)]));
        s.count("lockout");
        // Ten seconds after completion: not due, even though 100 s passed since the due check.
        assert_eq!(report(&s, base + Duration::from_secs(100)), None);
        // Sixty seconds after completion: due.
        assert_eq!(
            report(&s, base + Duration::from_secs(150)),
            Some(vec![("lockout", 1)])
        );
    }

    #[test]
    fn first_suppression_is_reported_at_once() {
        let t0 = Instant::now();
        let s = fresh();
        s.count("captcha_needed");
        assert_eq!(report(&s, t0), Some(vec![("captcha_needed", 1)]));
    }

    #[test]
    fn an_empty_window_never_reports() {
        let t0 = Instant::now();
        let s = fresh();
        assert_eq!(report(&s, t0 + Duration::from_secs(600)), None);
        assert_eq!(*s.last_report.lock().unwrap(), None);
    }

    #[test]
    fn a_busy_lock_skips_and_keeps_the_counts() {
        let t0 = Instant::now();
        let s = fresh();
        s.count("lockout");
        let held = s.last_report.lock().unwrap();
        assert_eq!(report(&s, t0), None);
        assert_eq!(counter(&s, "lockout"), 1);
        drop(held);
        assert_eq!(report(&s, t0), Some(vec![("lockout", 1)]));
    }

    #[test]
    fn a_poisoned_lock_is_skipped_without_panicking() {
        let t0 = Instant::now();
        let s = fresh();
        s.count("lockout");
        thread::scope(|scope| {
            let poisoner = scope.spawn(|| {
                let _guard = s.last_report.lock().unwrap();
                panic!("poisoning the report lock for this test");
            });
            assert!(poisoner.join().is_err());
        });
        assert_eq!(report(&s, t0), None);
        assert_eq!(counter(&s, "lockout"), 1);
    }

    #[test]
    fn concurrent_decisions_have_one_winner_and_lose_no_count() {
        const THREADS: usize = 8;
        const PER_THREAD: u64 = 50;
        let t0 = Instant::now();
        let s = fresh();
        let barrier = Barrier::new(THREADS);
        let outcomes: Vec<Option<Vec<(&'static str, u64)>>> = thread::scope(|scope| {
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    scope.spawn(|| {
                        for _ in 0..PER_THREAD {
                            s.count("captcha_needed");
                        }
                        barrier.wait();
                        report(&s, t0)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(outcomes.iter().filter(|o| o.is_some()).count(), 1);
        let mut total: u64 = outcomes
            .iter()
            .flatten()
            .flat_map(|counts| counts.iter())
            .map(|(_, n)| *n)
            .sum();
        let tail = report(&s, t0 + EMIT_INTERVAL).unwrap_or_default();
        total += tail.iter().map(|(_, n)| *n).sum::<u64>();
        assert_eq!(total, THREADS as u64 * PER_THREAD);
    }

    #[test]
    fn unknown_outcomes_are_not_counted() {
        let s = fresh();
        s.count("ip_blocked");
        assert!(s.counts.iter().all(|c| c.load(Ordering::Relaxed) == 0));
    }

    #[test]
    fn counted_outcomes_are_exactly_the_budgeted_ones() {
        let config = Config::default();
        for outcome in KNOWN {
            let budgeted = crate::refusal_budget(outcome, &config).is_some();
            assert_eq!(OUTCOMES.contains(&outcome), budgeted, "{outcome}");
        }
        for outcome in OUTCOMES {
            assert!(
                crate::refusal_budget(outcome, &config).is_some(),
                "{outcome}"
            );
        }
    }
}
