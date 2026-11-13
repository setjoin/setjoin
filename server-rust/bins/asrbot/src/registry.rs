//! `RoomRegistry`: the single process-local authority for room admission,
//! capacity, cancellation, identity-safe release and status (Go `bot.RoomRegistry`).

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

/// The LiveKit adapter behind the registry. `run` blocks until the room
/// disconnects or `cancel` fires. Capacity, identity and cancellation stay
/// registry decisions; the runner only owns the media lifecycle.
#[async_trait]
pub trait RoomRunner: Send + Sync + 'static {
    async fn run(&self, cancel: CancellationToken, room: String, token: String);
}

struct RoomSession {
    room: String,
    cancel: CancellationToken,
    stopping: bool,
}

type Sessions = HashMap<String, Arc<Mutex<RoomSession>>>;

pub struct RoomRegistry {
    max: i64,
    runner: Arc<dyn RoomRunner>,
    sessions: Arc<Mutex<Sessions>>,
}

/// An admitted identity. Compared by pointer: release removes only this exact one.
#[derive(Clone)]
pub struct Admitted(Arc<Mutex<RoomSession>>);

impl Admitted {
    /// Identity comparison: two admissions of the same room are different identities.
    pub fn same(&self, other: &Admitted) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl RoomRegistry {
    pub fn new(max: i64, runner: Arc<dyn RoomRunner>) -> Self {
        Self {
            max,
            runner,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Reserve `room` and start its runner asynchronously. True for a new
    /// admission and for an idempotent active repeat; false when capacity is
    /// full or the same identity is stopping.
    pub fn start(&self, room: &str, token: &str) -> bool {
        let (session, admitted, ok) = self.admit(room);
        if !ok || !admitted {
            return ok;
        }
        let session = session.expect("admitted session");
        let (runner, sessions) = (self.runner.clone(), self.sessions.clone());
        let token = token.to_owned();
        tokio::spawn(execute(runner, sessions, session.0, token));
        true
    }

    /// Split from `start` only so the admission-to-runner race is testable.
    pub fn admit(&self, room: &str) -> (Option<Admitted>, bool, bool) {
        let mut sessions = lock(&self.sessions);
        if let Some(existing) = sessions.get(room) {
            let stopping = lock(existing).stopping;
            if stopping {
                return (None, false, false);
            }
            return (Some(Admitted(existing.clone())), false, true);
        }
        if sessions.len() as i64 >= self.max {
            return (None, false, false);
        }
        let session = Arc::new(Mutex::new(RoomSession {
            room: room.to_owned(),
            cancel: CancellationToken::new(),
            stopping: false,
        }));
        sessions.insert(room.to_owned(), session.clone());
        (Some(Admitted(session)), true, true)
    }

    /// Run an admitted identity (the body `start` spawns).
    pub async fn execute(&self, admitted: Admitted, token: String) {
        execute(
            self.runner.clone(),
            self.sessions.clone(),
            admitted.0,
            token,
        )
        .await;
    }

    /// Cancel the current identity for `room` (idempotent). It stays admitted
    /// until its runner returns and compare-releases it.
    pub fn stop(&self, room: &str) {
        let sessions = lock(&self.sessions);
        if let Some(session) = sessions.get(room) {
            let mut session = lock(session);
            session.stopping = true;
            session.cancel.cancel();
        }
    }

    /// Release only the exact identity whose runner ended.
    pub fn release(&self, admitted: &Admitted) -> bool {
        release(&self.sessions, &admitted.0)
    }

    /// Admitted room ids in stable order (GET /status).
    pub fn rooms(&self) -> Vec<String> {
        let mut rooms: Vec<String> = lock(&self.sessions).keys().cloned().collect();
        rooms.sort();
        rooms
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn release(sessions: &Mutex<Sessions>, session: &Arc<Mutex<RoomSession>>) -> bool {
    let (room, cancel) = {
        let guard = lock(session);
        (guard.room.clone(), guard.cancel.clone())
    };
    let mut map = lock(sessions);
    let same = map
        .get(&room)
        .is_some_and(|current| Arc::ptr_eq(current, session));
    if same {
        map.remove(&room);
    }
    drop(map);
    if same {
        cancel.cancel();
    }
    same
}

async fn execute(
    runner: Arc<dyn RoomRunner>,
    sessions: Arc<Mutex<Sessions>>,
    session: Arc<Mutex<RoomSession>>,
    token: String,
) {
    let (room, cancel) = {
        let guard = lock(&session);
        (guard.room.clone(), guard.cancel.clone())
    };
    // Stop may win after admission but before this task is scheduled; a
    // cancelled identity must never be handed to the LiveKit adapter.
    if !cancel.is_cancelled() {
        runner.run(cancel, room, token).await;
    }
    release(&sessions, &session);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::time::Duration;

    /// Counts starts/active runs; optionally holds until cancelled or released.
    struct CountingRunner {
        started: AtomicI64,
        active: AtomicI64,
        hold: Option<tokio::sync::Notify>,
    }

    impl CountingRunner {
        fn new(hold: bool) -> Arc<Self> {
            Arc::new(Self {
                started: AtomicI64::new(0),
                active: AtomicI64::new(0),
                hold: hold.then(tokio::sync::Notify::new),
            })
        }
    }

    #[async_trait::async_trait]
    impl RoomRunner for CountingRunner {
        async fn run(&self, cancel: CancellationToken, _room: String, _token: String) {
            self.started.fetch_add(1, Ordering::SeqCst);
            self.active.fetch_add(1, Ordering::SeqCst);
            if let Some(hold) = &self.hold {
                tokio::select! {
                    _ = cancel.cancelled() => {}
                    _ = hold.notified() => {}
                }
            }
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    async fn until(what: &str, mut ready: impl FnMut() -> bool) {
        for _ in 0..400 {
            if ready() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("timed out waiting for {what}");
    }

    #[tokio::test]
    async fn stop_between_admission_and_runner_start_does_not_strand_the_session() {
        let runner = CountingRunner::new(true);
        let rooms = RoomRegistry::new(1, runner.clone());
        let (session, admitted, ok) = rooms.admit("room-a");
        assert!(ok && admitted);
        rooms.stop("room-a");
        // A cancelled identity must never reach the LiveKit adapter, and must free its slot.
        rooms.execute(session.expect("session"), "tok".into()).await;
        assert_eq!(runner.started.load(Ordering::SeqCst), 0);
        assert!(rooms.rooms().is_empty());
        assert!(rooms.start("room-b", "tok"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_start_honors_capacity_and_identity() {
        const CAPACITY: i64 = 8;
        let runner = CountingRunner::new(true);
        let rooms = Arc::new(RoomRegistry::new(CAPACITY, runner.clone()));
        let mut tasks = Vec::new();
        for i in 0..200 {
            let rooms = rooms.clone();
            tasks.push(tokio::spawn(async move {
                rooms.start(&format!("room-{:03}", i % 50), "tok");
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        let got = rooms.rooms();
        assert_eq!(got.len() as i64, CAPACITY, "{got:?}");
        assert!(got.windows(2).all(|w| w[0] < w[1]), "sorted: {got:?}");
        until("runners", || {
            runner.active.load(Ordering::SeqCst) == CAPACITY
        })
        .await;
        assert_eq!(
            runner.started.load(Ordering::SeqCst),
            CAPACITY,
            "one start per admitted identity"
        );
    }

    #[tokio::test]
    async fn connect_failure_and_natural_disconnect_release_capacity() {
        let failing = CountingRunner::new(false); // returns at once, like a failed connect
        let rooms = RoomRegistry::new(1, failing.clone());
        assert!(rooms.start("room-a", "tok"));
        until("release after failure", || rooms.rooms().is_empty()).await;
        assert!(
            rooms.start("room-b", "tok"),
            "connect failure frees capacity"
        );

        let live = CountingRunner::new(true);
        let rooms = RoomRegistry::new(1, live.clone());
        assert!(rooms.start("room-a", "tok"));
        until("active", || live.active.load(Ordering::SeqCst) == 1).await;
        assert_eq!(rooms.rooms(), vec!["room-a".to_owned()]);
        live.hold.as_ref().unwrap().notify_one(); // the room ends on its own
        until("release after disconnect", || rooms.rooms().is_empty()).await;
        assert!(rooms.start("room-b", "tok"));
    }

    #[tokio::test]
    async fn stop_cancels_the_active_runner() {
        let runner = CountingRunner::new(true);
        let rooms = RoomRegistry::new(1, runner.clone());
        assert!(rooms.start("room-a", "tok"));
        until("active", || runner.active.load(Ordering::SeqCst) == 1).await;
        rooms.stop("room-a");
        until("runner stopped", || {
            runner.active.load(Ordering::SeqCst) == 0
        })
        .await;
        until("released", || rooms.rooms().is_empty()).await;
    }

    #[tokio::test]
    async fn stopping_session_retains_capacity_until_the_runner_drains() {
        struct Draining {
            canceled: tokio::sync::Notify,
            drain: tokio::sync::Notify,
        }
        #[async_trait::async_trait]
        impl RoomRunner for Draining {
            async fn run(&self, cancel: CancellationToken, _room: String, _token: String) {
                cancel.cancelled().await;
                self.canceled.notify_one();
                self.drain.notified().await;
            }
        }
        let runner = Arc::new(Draining {
            canceled: tokio::sync::Notify::new(),
            drain: tokio::sync::Notify::new(),
        });
        let rooms = RoomRegistry::new(1, runner.clone());
        assert!(rooms.start("room-a", "tok"));
        tokio::time::sleep(Duration::from_millis(20)).await;
        rooms.stop("room-a");
        runner.canceled.notified().await;
        assert!(
            !rooms.start("room-b", "tok"),
            "replacement exceeded capacity while the old runner drains"
        );
        assert!(
            !rooms.start("room-a", "tok"),
            "a start racing a stopping identity must not be acknowledged"
        );
        assert_eq!(rooms.rooms(), vec!["room-a".to_owned()]);
        runner.drain.notify_one();
        until("drained", || rooms.rooms().is_empty()).await;
    }

    #[tokio::test]
    async fn stale_release_cannot_delete_a_replacement() {
        let rooms = RoomRegistry::new(1, CountingRunner::new(false));
        let (old, admitted, ok) = rooms.admit("room-a");
        let old = old.expect("old");
        assert!(ok && admitted);
        rooms.stop("room-a");
        assert!(rooms.release(&old), "matching old release");
        let (newer, admitted, ok) = rooms.admit("room-a");
        let newer = newer.expect("newer");
        assert!(ok && admitted && !newer.same(&old));
        assert!(!rooms.release(&old), "stale release reports no change");
        assert_eq!(rooms.rooms(), vec!["room-a".to_owned()]);
        assert!(rooms.release(&newer));
    }

    #[tokio::test]
    async fn zero_capacity_refuses_everything_and_a_repeat_is_idempotent() {
        let rooms = RoomRegistry::new(0, CountingRunner::new(true));
        assert!(!rooms.start("a", "t"));
        let runner = CountingRunner::new(true);
        let rooms = RoomRegistry::new(2, runner.clone());
        assert!(rooms.start("a", "t") && rooms.start("a", "other-token"));
        until("run", || runner.started.load(Ordering::SeqCst) >= 1).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            runner.started.load(Ordering::SeqCst),
            1,
            "a repeat start never spawns a second runner"
        );
    }
}
