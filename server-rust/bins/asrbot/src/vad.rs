//! Energy-based voice-activity detection and the F10 slot manager (Go `internal/vad`).
//! ponytail: energy VAD, upgrade to a real VAD model if zh WER on real audio demands it.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Mean absolute amplitude of one frame of 16-bit PCM.
pub fn energy(pcm: &[i16]) -> f64 {
    if pcm.is_empty() {
        return 0.0;
    }
    let sum: f64 = pcm.iter().map(|s| (f64::from(*s)).abs()).sum();
    sum / pcm.len() as f64
}

/// Attack/hangover state machine for one track.
#[derive(Debug, Clone)]
pub struct Detector {
    threshold: f64,
    hangover: i64,
    active: bool,
    silent_since: i64,
}

impl Detector {
    pub fn new(threshold: f64, hangover: i64) -> Self {
        Self {
            threshold,
            hangover,
            active: false,
            silent_since: 0,
        }
    }

    pub fn update(&mut self, energy: f64) -> bool {
        if energy >= self.threshold {
            self.active = true;
            self.silent_since = 0;
            return true;
        }
        if !self.active {
            return false;
        }
        self.silent_since += 1;
        if self.silent_since > self.hangover {
            self.active = false;
            return false;
        }
        true
    }

    pub fn active(&self) -> bool {
        self.active
    }
}

/// The arbiter seam `TrackWorker` depends on.
pub trait TrackArbiter: Send + Sync {
    fn update(&self, id: &str, frame_energy: f64) -> bool;
    fn remove(&self, id: &str);
}

#[derive(Default)]
struct State {
    detectors: HashMap<String, Detector>,
    energy: HashMap<String, f64>,
    holding: HashSet<String>,
}

/// One detector per track; at most `cap` tracks hold an ASR slot (the lowest
/// energy active track yields past the cap; ties break by track id).
pub struct Manager {
    cap: i64,
    threshold: f64,
    hangover: i64,
    state: Mutex<State>,
}

impl Manager {
    pub fn new(cap: i64, threshold: f64, hangover: i64) -> Self {
        Self {
            cap,
            threshold,
            hangover,
            state: Mutex::new(State::default()),
        }
    }
}

impl TrackArbiter for Manager {
    fn update(&self, id: &str, frame_energy: f64) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let (threshold, hangover) = (self.threshold, self.hangover);
        let detector = state
            .detectors
            .entry(id.to_owned())
            .or_insert_with(|| Detector::new(threshold, hangover));
        if !detector.update(frame_energy) {
            state.energy.remove(id);
            state.holding.remove(id);
            return false;
        }
        state.energy.insert(id.to_owned(), frame_energy);
        let mut ids: Vec<&String> = state.energy.keys().collect();
        ids.sort_by(|a, b| {
            let (ea, eb) = (state.energy[*a], state.energy[*b]);
            if ea != eb {
                return eb.partial_cmp(&ea).unwrap_or(std::cmp::Ordering::Equal);
            }
            a.cmp(b)
        });
        let cap = self.cap;
        let holders: Vec<(String, bool)> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| ((*id).clone(), (i as i64) < cap))
            .collect();
        for (id, holds) in holders {
            if holds {
                state.holding.insert(id);
            } else {
                state.holding.remove(&id);
            }
        }
        state.holding.contains(id)
    }

    fn remove(&self, id: &str) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.detectors.remove(id);
        state.energy.remove(id);
        state.holding.remove(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const THRESHOLD: f64 = 500.0;

    #[test]
    fn detector_silence_never_active() {
        let mut d = Detector::new(THRESHOLD, 3);
        for _ in 0..10 {
            assert!(!d.update(10.0));
        }
        assert!(!d.active());
    }

    #[test]
    fn detector_speech_acquires_immediately() {
        let mut d = Detector::new(THRESHOLD, 3);
        assert!(d.update(900.0));
        assert!(d.active());
    }

    #[test]
    fn detector_hangover_releases_after_n_silent_frames() {
        let mut d = Detector::new(THRESHOLD, 3);
        assert!(d.update(900.0));
        for _ in 0..3 {
            assert!(d.update(0.0), "within hangover stays active");
        }
        assert!(!d.update(0.0), "past hangover releases");
        assert!(!d.active());
    }

    #[test]
    fn detector_hangover_resets_on_speech() {
        let mut d = Detector::new(THRESHOLD, 2);
        d.update(900.0);
        d.update(0.0);
        d.update(0.0);
        assert!(d.update(900.0));
        assert!(d.update(0.0));
        assert!(d.update(0.0));
        assert!(!d.update(0.0));
    }

    #[test]
    fn energy_is_mean_absolute_amplitude() {
        assert_eq!(energy(&[]), 0.0);
        assert_eq!(energy(&[100, -100, 300, -300]), 200.0);
        assert_eq!(energy(&[i16::MIN]), 32768.0);
    }

    #[test]
    fn manager_silence_never_holds_a_slot() {
        let m = Manager::new(1, THRESHOLD, 3);
        assert!(!m.update("a", 0.0));
    }

    #[test]
    fn manager_speech_acquires_and_hangover_releases() {
        let m = Manager::new(1, THRESHOLD, 2);
        assert!(m.update("a", 900.0));
        assert!(m.update("a", 0.0));
        assert!(m.update("a", 0.0));
        assert!(!m.update("a", 0.0));
    }

    #[test]
    fn manager_cap_lowest_energy_yields() {
        let m = Manager::new(2, THRESHOLD, 3);
        assert!(m.update("a", 600.0));
        assert!(m.update("b", 700.0));
        // A louder third track takes a slot; the quietest holder yields.
        assert!(m.update("c", 900.0));
        assert!(!m.update("a", 600.0), "a is now the lowest active track");
        assert!(m.update("b", 700.0));
        assert!(m.update("c", 900.0));
    }

    #[test]
    fn manager_tie_breaks_by_track_id() {
        let m = Manager::new(1, THRESHOLD, 3);
        assert!(m.update("b", 800.0));
        assert!(m.update("a", 800.0), "equal energy: the lower id wins");
        assert!(!m.update("b", 800.0));
    }

    #[test]
    fn manager_remove_clears_slot() {
        let m = Manager::new(1, THRESHOLD, 3);
        assert!(m.update("a", 900.0));
        m.remove("a");
        assert!(m.update("b", 600.0));
        assert!(!m.update("c", 0.0));
    }
}
