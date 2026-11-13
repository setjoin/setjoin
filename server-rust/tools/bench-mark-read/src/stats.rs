//! Latency summaries. Percentiles are nearest-rank (the smallest sample with
//! at least p% of samples at or below it): no interpolation, so every
//! reported value is a latency that was actually observed.

#[derive(Clone, Debug, PartialEq)]
pub struct Summary {
    pub n: usize,
    pub min: u64,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
    pub max: u64,
    pub mean: f64,
}

impl Summary {
    /// `None` for an empty set: a missing measurement has no summary.
    pub fn of(samples: &[u64]) -> Option<Summary> {
        if samples.is_empty() {
            return None;
        }
        let mut v = samples.to_vec();
        v.sort_unstable();
        let n = v.len();
        let rank = |p: usize| v[(p * n).div_ceil(100).max(1) - 1];
        Some(Summary {
            n,
            min: v[0],
            p50: rank(50),
            p95: rank(95),
            p99: rank(99),
            max: v[n - 1],
            mean: v.iter().map(|&x| x as f64).sum::<f64>() / n as f64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank_percentiles_of_one_to_hundred() {
        let v: Vec<u64> = (1..=100).rev().collect();
        let s = Summary::of(&v).unwrap();
        assert_eq!(
            (s.n, s.min, s.p50, s.p95, s.p99, s.max),
            (100, 1, 50, 95, 99, 100)
        );
        assert_eq!(s.mean, 50.5);
    }

    #[test]
    fn small_sets_report_observed_values_only() {
        // 3 samples: p50 = 2nd, p95 = p99 = 3rd (ceil(0.95*3) = 3).
        let s = Summary::of(&[30, 10, 20]).unwrap();
        assert_eq!((s.p50, s.p95, s.p99), (20, 30, 30));
        let one = Summary::of(&[7]).unwrap();
        assert_eq!((one.min, one.p50, one.p99, one.max), (7, 7, 7, 7));
    }

    #[test]
    fn empty_set_has_no_summary() {
        assert_eq!(Summary::of(&[]), None);
    }
}
