//! Process-wide summary of refusal rows that `refusal_budget` suppressed (CWE-779).
//! Suppressed rows are counted per outcome, not logged per event. At most one
//! `warn` per `EMIT_INTERVAL_SECS` per process carries the counts. The event has no
//! source IP, username or user agent.
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// The outcomes `refusal_budget` accepts, in counter-index order.
const OUTCOMES: [&str; 6] = [
    "captcha_needed",
    "rate_limited",
    "lockout",
    "spray_detected",
    "geo_blocked",
    "threat_blocked",
];
const EMIT_INTERVAL_SECS: i64 = 60;

/// Per-outcome suppressed-row counters plus the unix second of the last emit.
pub struct SuppressedRefusals {
    counts: [AtomicU64; OUTCOMES.len()],
    last_emit: AtomicI64,
}

impl SuppressedRefusals {
    pub const fn new() -> Self {
        Self {
            counts: [const { AtomicU64::new(0) }; OUTCOMES.len()],
            last_emit: AtomicI64::new(0),
        }
    }

    /// Counts one suppressed row, then returns the summary if this call is the one that
    /// emits it. `now` is unix seconds, injected so the decision is testable.
    pub fn note_at(&self, outcome: &str, now: i64) -> Option<Vec<(&'static str, u64)>> {
        if let Some(index) = index(outcome) {
            self.counts[index].fetch_add(1, Ordering::Relaxed);
        }
        self.take_due(now)
    }

    /// Returns the non-zero counts and resets them when at least `EMIT_INTERVAL_SECS` have
    /// passed since the last emit and this call wins the compare-exchange on the last-emit
    /// time. Losers and empty windows return `None` and leave the counters alone.
    fn take_due(&self, now: i64) -> Option<Vec<(&'static str, u64)>> {
        let last = self.last_emit.load(Ordering::Acquire);
        if now.saturating_sub(last) < EMIT_INTERVAL_SECS {
            return None;
        }
        let pending: u64 = self.counts.iter().map(|c| c.load(Ordering::Relaxed)).sum();
        if pending == 0 {
            return None;
        }
        self.last_emit
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        Some(
            OUTCOMES
                .iter()
                .zip(self.counts.iter())
                .filter_map(|(name, count)| {
                    let n = count.swap(0, Ordering::AcqRel);
                    (n > 0).then_some((*name, n))
                })
                .collect(),
        )
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

/// Records one refusal row that the budget suppressed (its INSERT wrote 0 rows). Call it only
/// for outcomes with a budget and not on database errors. Emits at most one summary `warn`
/// per process per 60 s.
pub fn note_suppressed_refusal(outcome: &str) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        });
    if let Some(counts) = SUPPRESSED.note_at(outcome, now) {
        let summary = counts
            .iter()
            .map(|(name, n)| format!("{name}={n}"))
            .collect::<Vec<_>>()
            .join(" ");
        tracing::warn!(counts = %summary, "threat refusal rows suppressed by budget");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    fn started_at(t: i64) -> SuppressedRefusals {
        let s = SuppressedRefusals::new();
        s.last_emit.store(t, Ordering::Release);
        s
    }

    #[test]
    fn counts_accumulate_and_nothing_emits_before_sixty_seconds() {
        let s = started_at(1_000);
        assert_eq!(s.note_at("captcha_needed", 1_000), None);
        assert_eq!(s.note_at("captcha_needed", 1_030), None);
        assert_eq!(s.note_at("rate_limited", 1_059), None);
        assert_eq!(
            s.counts[index("captcha_needed").unwrap()].load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            s.counts[index("rate_limited").unwrap()].load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn one_emit_at_sixty_seconds_carries_nonzero_counts_and_resets() {
        let s = started_at(1_000);
        s.note_at("captcha_needed", 1_000);
        s.note_at("captcha_needed", 1_010);
        s.note_at("rate_limited", 1_020);
        let emitted = s.note_at("lockout", 1_060);
        assert_eq!(
            emitted,
            Some(vec![
                ("captcha_needed", 2),
                ("rate_limited", 1),
                ("lockout", 1)
            ])
        );
        assert!(s.counts.iter().all(|c| c.load(Ordering::Relaxed) == 0));
        // The next window starts from zero and waits its own 60 s.
        assert_eq!(s.note_at("lockout", 1_061), None);
        assert_eq!(s.take_due(1_120), Some(vec![("lockout", 1)]));
    }

    #[test]
    fn concurrent_first_emits_have_exactly_one_winner() {
        let s = started_at(1_000);
        s.note_at("captcha_needed", 1_000);
        let first = s.take_due(1_060);
        let second = s.take_due(1_060);
        assert!(first.is_some());
        assert_eq!([first, second].iter().filter(|r| r.is_some()).count(), 1);
    }

    #[test]
    fn an_empty_window_never_emits() {
        let s = started_at(1_000);
        assert_eq!(s.take_due(1_600), None);
        assert_eq!(s.last_emit.load(Ordering::Acquire), 1_000);
    }

    #[test]
    fn unknown_outcomes_are_not_counted() {
        let s = started_at(1_000);
        assert_eq!(s.note_at("ip_blocked", 1_000), None);
        assert!(s.counts.iter().all(|c| c.load(Ordering::Relaxed) == 0));
    }

    #[test]
    fn every_counted_outcome_has_a_budget() {
        let config = Config::default();
        for outcome in OUTCOMES {
            assert!(
                crate::refusal_budget(outcome, &config).is_some(),
                "{outcome}"
            );
        }
    }
}
