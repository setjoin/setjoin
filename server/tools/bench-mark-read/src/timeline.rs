//! Per-request records and what an interruption looked like to the client.

use crate::outcome::Outcome;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Sample {
    /// Request start, µs since the run started.
    pub start_us: u64,
    pub latency_us: u64,
    pub outcome: Outcome,
}

impl Sample {
    pub fn csv(&self) -> String {
        format!(
            "{},{},{}",
            self.start_us,
            self.latency_us,
            self.outcome.label()
        )
    }

    pub fn parse_csv(line: &str) -> Option<Sample> {
        let mut f = line.split(',');
        Some(Sample {
            start_us: f.next()?.parse().ok()?,
            latency_us: f.next()?.parse().ok()?,
            outcome: Outcome::parse(f.next()?)?,
        })
    }
}

/// The failure window of a run: from the first non-success to the first
/// success after the last non-success.
#[derive(Debug, PartialEq)]
pub struct Outage {
    pub first_failure_us: u64,
    pub last_failure_us: u64,
    /// `None` if no request succeeded after the last failure.
    pub recovered_at_us: Option<u64>,
    /// Count per outcome label among the failures, sorted by label.
    pub failures: Vec<(String, usize)>,
}

pub fn outage(samples: &[Sample]) -> Option<Outage> {
    let mut v: Vec<&Sample> = samples.iter().collect();
    v.sort_by_key(|s| s.start_us);
    let fails: Vec<&&Sample> = v.iter().filter(|s| !s.outcome.is_success()).collect();
    let (first, last) = (fails.first()?, fails.last()?);
    let recovered_at_us = v
        .iter()
        .find(|s| s.start_us > last.start_us && s.outcome.is_success())
        .map(|s| s.start_us + s.latency_us);
    let mut failures: Vec<(String, usize)> = Vec::new();
    for s in &fails {
        let l = s.outcome.label();
        match failures.iter_mut().find(|(k, _)| *k == l) {
            Some((_, n)) => *n += 1,
            None => failures.push((l, 1)),
        }
    }
    failures.sort();
    Some(Outage {
        first_failure_us: first.start_us,
        last_failure_us: last.start_us,
        recovered_at_us,
        failures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(start_us: u64, outcome: Outcome) -> Sample {
        Sample {
            start_us,
            latency_us: 10,
            outcome,
        }
    }

    #[test]
    fn a_clean_run_has_no_outage() {
        assert_eq!(
            outage(&[s(0, Outcome::Updated), s(5, Outcome::Updated)]),
            None
        );
    }

    #[test]
    fn outage_spans_first_failure_to_first_later_success() {
        let run = [
            s(0, Outcome::Updated),
            s(100, Outcome::Transport),
            s(200, Outcome::Http(502)),
            s(250, Outcome::Updated), // a success inside the window does not end it
            s(300, Outcome::Transport),
            s(400, Outcome::Updated),
            s(500, Outcome::Updated),
        ];
        assert_eq!(
            outage(&run),
            Some(Outage {
                first_failure_us: 100,
                last_failure_us: 300,
                recovered_at_us: Some(410),
                failures: vec![("http_502".into(), 1), ("transport".into(), 2)],
            })
        );
    }

    #[test]
    fn unrecovered_outage_says_so() {
        let o = outage(&[s(0, Outcome::Updated), s(9, Outcome::Unknown)]).unwrap();
        assert_eq!(o.recovered_at_us, None);
        assert_eq!(o.failures, vec![("unknown".to_string(), 1)]);
    }

    #[test]
    fn csv_round_trip() {
        let x = Sample {
            start_us: 12,
            latency_us: 3400,
            outcome: Outcome::Http(503),
        };
        assert_eq!(x.csv(), "12,3400,http_503");
        assert_eq!(Sample::parse_csv(&x.csv()), Some(x));
    }
}
