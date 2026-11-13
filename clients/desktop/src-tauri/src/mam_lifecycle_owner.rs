//! Exactly-one MAM start/resume composition owner for the Tauri mobile shell.
//!
//! It owns the sole periodic timer and coalesces lifecycle opportunities. The
//! production root constructs it in `Off` mode; Connectivity E4 may later feed
//! trusted narrowed policy into this same off/observe/execute seam.

use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MamRolloutMode {
    Off,
    Observe,
    Execute,
}

pub const DEFAULT_MAM_ROLLOUT_MODE: MamRolloutMode = MamRolloutMode::Off;
pub const MAM_PERIODIC_INTERVAL: Duration = Duration::from_secs(15 * 60);

fn rollout_modes() -> [MamRolloutMode; 3] {
    [
        MamRolloutMode::Off,
        MamRolloutMode::Observe,
        MamRolloutMode::Execute,
    ]
}

type Completion = Box<dyn FnOnce() + Send>;
type CheckinLauncher = Arc<dyn Fn(Completion) + Send + Sync>;

#[derive(Default)]
struct OwnerState {
    started: bool,
    foreground: bool,
    in_flight: bool,
    pending_opportunity: bool,
    stop_tx: Option<mpsc::Sender<()>>,
    timer_thread: Option<thread::JoinHandle<()>>,
}

pub struct MamLifecycleOwner {
    mode: MamRolloutMode,
    interval: Duration,
    launcher: CheckinLauncher,
    state: Arc<Mutex<OwnerState>>,
}

impl MamLifecycleOwner {
    pub fn new(mode: MamRolloutMode, launcher: CheckinLauncher) -> Self {
        debug_assert!(rollout_modes().contains(&mode));
        Self::with_interval(mode, MAM_PERIODIC_INTERVAL, launcher)
    }

    fn with_interval(mode: MamRolloutMode, interval: Duration, launcher: CheckinLauncher) -> Self {
        Self {
            mode,
            interval,
            launcher,
            state: Arc::new(Mutex::new(OwnerState::default())),
        }
    }

    pub fn start(&self) {
        {
            let mut state = self.state.lock().expect("MAM lifecycle owner lock");
            if state.started {
                return;
            }
            state.started = true;
            state.foreground = true;
            if self.mode != MamRolloutMode::Execute {
                return;
            }

            let (stop_tx, stop_rx) = mpsc::channel();
            state.stop_tx = Some(stop_tx);
            let owner_state = Arc::clone(&self.state);
            let launcher = Arc::clone(&self.launcher);
            let interval = self.interval;
            state.timer_thread = Some(thread::spawn(move || {
                while let Err(mpsc::RecvTimeoutError::Timeout) = stop_rx.recv_timeout(interval) {
                    request_opportunity(&owner_state, &launcher, MamRolloutMode::Execute);
                }
            }));
        }
        request_opportunity(&self.state, &self.launcher, self.mode);
    }

    pub fn pause(&self) {
        let mut state = self.state.lock().expect("MAM lifecycle owner lock");
        if state.started {
            state.foreground = false;
        }
    }

    pub fn resume(&self) {
        let should_run = {
            let mut state = self.state.lock().expect("MAM lifecycle owner lock");
            if !state.started || state.foreground {
                false
            } else {
                state.foreground = true;
                true
            }
        };
        if should_run {
            request_opportunity(&self.state, &self.launcher, self.mode);
        }
    }

    pub fn stop(&self) {
        let timer_thread = {
            let mut state = self.state.lock().expect("MAM lifecycle owner lock");
            if !state.started {
                return;
            }
            state.started = false;
            state.foreground = false;
            state.pending_opportunity = false;
            if let Some(stop_tx) = state.stop_tx.take() {
                let _ = stop_tx.send(());
            }
            state.timer_thread.take()
        };
        if let Some(timer_thread) = timer_thread {
            let _ = timer_thread.join();
        }
    }

    #[cfg(test)]
    fn periodic_opportunity_for_test(&self) {
        request_opportunity(&self.state, &self.launcher, self.mode);
    }
}

impl Drop for MamLifecycleOwner {
    fn drop(&mut self) {
        self.stop();
    }
}

fn request_opportunity(
    state: &Arc<Mutex<OwnerState>>,
    launcher: &CheckinLauncher,
    mode: MamRolloutMode,
) {
    {
        let mut guard = state.lock().expect("MAM lifecycle owner lock");
        if !guard.started || !guard.foreground || mode != MamRolloutMode::Execute {
            return;
        }
        if guard.in_flight {
            guard.pending_opportunity = true;
            return;
        }
        guard.in_flight = true;
    }

    let completion_state = Arc::clone(state);
    let completion_launcher = Arc::clone(launcher);
    launcher(Box::new(move || {
        let rerun = {
            let mut guard = completion_state
                .lock()
                .expect("MAM lifecycle owner completion lock");
            guard.in_flight = false;
            let rerun = guard.pending_opportunity && guard.started && guard.foreground;
            guard.pending_opportunity = false;
            rerun
        };
        if rerun {
            request_opportunity(
                &completion_state,
                &completion_launcher,
                MamRolloutMode::Execute,
            );
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_resume_reentry_and_stop_are_exactly_once() {
        let launches = Arc::new(Mutex::new(Vec::<Completion>::new()));
        let captured = Arc::clone(&launches);
        let launcher: CheckinLauncher = Arc::new(move |done| {
            captured.lock().unwrap().push(done);
        });
        let owner = MamLifecycleOwner::with_interval(
            MamRolloutMode::Execute,
            Duration::from_secs(60),
            launcher,
        );

        owner.start();
        owner.start();
        assert_eq!(launches.lock().unwrap().len(), 1);

        owner.periodic_opportunity_for_test();
        owner.periodic_opportunity_for_test();
        assert_eq!(launches.lock().unwrap().len(), 1);
        let done = launches.lock().unwrap().remove(0);
        done();
        assert_eq!(launches.lock().unwrap().len(), 1);
        launches.lock().unwrap().remove(0)();

        owner.pause();
        owner.resume();
        owner.resume();
        assert_eq!(launches.lock().unwrap().len(), 1);
        launches.lock().unwrap().remove(0)();

        owner.stop();
        owner.stop();
        owner.periodic_opportunity_for_test();
        assert!(launches.lock().unwrap().is_empty());
    }

    #[test]
    fn off_and_observe_modes_never_launch_or_own_a_timer() {
        for mode in [MamRolloutMode::Off, MamRolloutMode::Observe] {
            let count = Arc::new(Mutex::new(0));
            let captured = Arc::clone(&count);
            let owner =
                MamLifecycleOwner::new(mode, Arc::new(move |_done| *captured.lock().unwrap() += 1));
            owner.start();
            owner.pause();
            owner.resume();
            assert_eq!(*count.lock().unwrap(), 0);
            assert!(owner.state.lock().unwrap().stop_tx.is_none());
            owner.stop();
        }
    }

    #[test]
    fn default_mode_and_interval_match_the_v1_corpus() {
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../../../mam/conformance/v1/lifecycle.json"))
                .unwrap();
        assert_eq!(
            corpus["rollout_modes"],
            serde_json::json!(["off", "observe", "execute"])
        );
        assert_eq!(corpus["default_rollout_mode"], "off");
        assert_eq!(corpus["rollout_modes"].as_array().unwrap().len(), 3);
        assert_eq!(DEFAULT_MAM_ROLLOUT_MODE, MamRolloutMode::Off);
        assert_eq!(
            corpus["periodic_interval_ms"].as_u64().unwrap(),
            MAM_PERIODIC_INTERVAL.as_millis() as u64
        );
    }
}
