//! Worker scheduling shared by the route families.
use chrono::{DateTime, Datelike, Local, Timelike, Utc};
use setjoin_pg::workers::{DirectListener, SessionRevocation, SingletonLease, WorkerDatabase};
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

pub type WorkerError = Box<dyn std::error::Error + Send + Sync>;
pub type Action =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<(), WorkerError>> + Send>> + Send + Sync>;

struct Task {
    name: String,
    schedule: Schedule,
    timeout: Duration,
    last_run: Option<DateTime<Local>>,
    running: Option<tokio::task::JoinHandle<()>>,
    action: Action,
    /// Per-task lock (#365); only tasks transferred out of Go carry one.
    lease: Option<SingletonLease>,
}

enum Schedule {
    Every(Duration),
    Cron([Option<u32>; 5]),
}

impl Schedule {
    fn due(&self, now: DateTime<Local>, last: Option<DateTime<Local>>) -> bool {
        match self {
            Self::Every(interval) => last.is_none_or(|last| {
                now.signed_duration_since(last)
                    .to_std()
                    .is_ok_and(|elapsed| elapsed >= *interval)
            }),
            Self::Cron(fields) => {
                let minute = |time: DateTime<Local>| {
                    time.with_second(0).unwrap().with_nanosecond(0).unwrap()
                };
                let current = minute(now);
                let matches = |time: DateTime<Local>| {
                    let values = [
                        time.minute(),
                        time.hour(),
                        time.day(),
                        time.month(),
                        time.weekday().num_days_from_sunday(),
                    ];
                    fields
                        .iter()
                        .zip(values)
                        .all(|(field, value)| field.is_none_or(|n| n == value))
                };
                if last.is_none_or(|last| minute(last) < current) && matches(current) {
                    return true;
                }
                let Some(last) = last else {
                    return false;
                };
                let last = minute(last);
                let mut slot = current;
                let mut scanned = 0;
                while slot > last {
                    if scanned >= 1440 || matches(slot) {
                        return true;
                    }
                    scanned += 1;
                    slot -= chrono::Duration::minutes(1);
                }
                false
            }
        }
    }
}

/// Go's frozen schedule and timeout (seconds) for a cron task name.
fn task_spec(name: &str) -> Option<(Schedule, u64)> {
    let every = |seconds| Schedule::Every(Duration::from_secs(seconds));
    let cron =
        |minute, hour, day, weekday| Schedule::Cron([Some(minute), hour, day, None, weekday]);
    let (schedule, seconds) = match name {
        "drain-outbound-hot" => (every(2), 10),
        "dispatch-scheduled-actions"
        | "scan-due-reminders"
        | "retry-outbound-queue"
        | "drain-journal-queue"
        | "retry-journal-queue" => (every(60), 30),
        "prune-ws-subscriptions" => (every(60), 10),
        "prune-used-password-reset-tokens" | "prune-auth-lockouts" => (every(300), 10),
        "approval-expire-due" => (every(3), 10),
        "health-check" => (every(300), 30),
        "refresh-antiphish-contact-graph" => (every(300), 60),
        "reset-sending-quotas" => (cron(0, None, None, None), 30),
        "enforce-retention" => (cron(5, Some(2), None, None), 60),
        "purge-deleted-messages" => (cron(30, Some(2), None, None), 60),
        "chat-chain-anchor" => (cron(40, Some(2), None, None), 120),
        "chat-purge-expired" => (cron(50, Some(2), None, None), 300),
        "prune-dmarc-reports" | "prune-health-history" => (cron(0, Some(3), None, None), 30),
        "prune-spam" => (cron(15, Some(3), None, None), 60),
        "prune-log-tables" => (cron(30, Some(3), None, None), 60),
        "prune-ca-signin-log" | "prune-bulk-role-jobs" => (cron(45, Some(3), None, None), 30),
        "prune-login-events" | "prune-vacation-replies" => (cron(0, Some(4), None, None), 30),
        "prune-session-runtime" => (cron(15, Some(4), None, None), 30),
        "prune-changes-journal" => (cron(30, Some(4), None, None), 60),
        "prune-greylist" => (cron(30, Some(3), None, None), 30),
        "purge-expired-tokens" => (cron(0, Some(4), None, Some(0)), 30),
        "purge-saml-assertions" => (cron(15, Some(4), None, Some(1)), 30),
        "create-monthly-partitions" => (cron(0, Some(0), Some(25), None), 60),
        _ => return None,
    };
    Some((schedule, seconds))
}

/// Go's registry entry for `name` as `(schedule text, timeout seconds)`,
/// rendered the way `tasks.go` spells it (`@every 2s`, `5 2 * * *`).
pub fn go_task_spec(name: &str) -> Option<(String, u64)> {
    let (schedule, seconds) = task_spec(name)?;
    let text = match schedule {
        Schedule::Every(d) if d.as_secs() % 60 == 0 => format!("@every {}m", d.as_secs() / 60),
        Schedule::Every(d) => format!("@every {}s", d.as_secs()),
        Schedule::Cron(fields) => fields
            .iter()
            .map(|f| f.map_or("*".to_string(), |n| n.to_string()))
            .collect::<Vec<_>>()
            .join(" "),
    };
    Some((text, seconds))
}

/// Whether `GO_WORKERS_OFF` stops Go's copy of cron task `name`: either its own
/// `cron:<name>` entry or `cron`, which stops Go's whole scheduler (#259).
pub fn go_cron_task_is_off(go_workers_off: &str, name: &str) -> bool {
    let task = format!("cron:{name}");
    go_workers_off
        .split(',')
        .map(str::trim)
        .any(|entry| entry == "cron" || entry == task)
}

/// Either Go's whole-scheduler lock (`acquire`, the #260 shape, which cannot
/// run beside a live Go scheduler) or one lock per task (`per_task`, #365):
/// each task registered with `register_transferred` holds `cron-task:<name>`
/// instead, so tasks leave Go one at a time while Go keeps its own lock.
pub struct CronScheduler {
    lease: Option<SingletonLease>,
    per_task: Option<WorkerDatabase>,
    tasks: Vec<Task>,
}

impl CronScheduler {
    pub async fn acquire(db: WorkerDatabase) -> Result<Option<Self>, WorkerError> {
        Ok(db.try_cron_singleton().await?.map(|lease| Self {
            lease: Some(lease),
            per_task: None,
            tasks: Vec::new(),
        }))
    }

    /// A scheduler that never touches Go's lock; see `register_transferred`.
    pub fn per_task(db: WorkerDatabase) -> Self {
        Self {
            lease: None,
            per_task: Some(db),
            tasks: Vec::new(),
        }
    }

    /// Take over a task from Go. Refuses unless Go's copy is listed off in
    /// `go_workers_off` (the value of `GO_WORKERS_OFF`) and no other Rust
    /// scheduler holds this task's lock, so a task never runs in both.
    pub async fn register_transferred(
        &mut self,
        name: &str,
        action: Action,
        go_workers_off: &str,
    ) -> Result<(), WorkerError> {
        let Some(db) = self.per_task.clone() else {
            return Err("register_transferred needs a per_task scheduler".into());
        };
        if !go_cron_task_is_off(go_workers_off, name) {
            return Err(format!(
                "cron:{name} requires GO_WORKERS_OFF=cron:{name} before Rust starts shared effects"
            )
            .into());
        }
        self.register(name, action)?;
        let lease = db
            .try_cron_task_lock(name)
            .await?
            .ok_or_else(|| format!("cron task {name} is already held by another Rust scheduler"));
        match lease {
            Ok(lease) => {
                self.tasks.last_mut().expect("just registered").lease = Some(lease);
                Ok(())
            }
            Err(error) => {
                self.tasks.pop();
                Err(error.into())
            }
        }
    }

    pub fn register(&mut self, name: &str, action: Action) -> Result<(), String> {
        if self.tasks.iter().any(|t| t.name == name) {
            return Err(format!("duplicate cron task {name}"));
        }
        let Some((schedule, seconds)) = task_spec(name) else {
            return Err(format!("unknown cron task {name}"));
        };
        let timeout = Duration::from_secs(seconds);
        self.tasks.push(Task {
            name: name.into(),
            schedule,
            timeout,
            last_run: None,
            running: None,
            action,
            lease: None,
        });
        Ok(())
    }

    /// Admit due work without allowing two instances of the same task.
    pub async fn tick(&mut self, now: DateTime<Local>) -> Result<(), WorkerError> {
        let mut health = Ok(());
        for lease in self
            .lease
            .iter()
            .chain(self.tasks.iter().filter_map(|t| t.lease.as_ref()))
        {
            if let Err(error) = lease.ensure_connected().await {
                health = Err(error);
                break;
            }
        }
        if let Err(error) = health {
            self.abort_running().await;
            return Err(error);
        }
        for task in &mut self.tasks {
            if task.running.as_ref().is_some_and(|h| h.is_finished()) {
                if let Some(handle) = task.running.take() {
                    let _ = handle.await;
                }
            }
            if task.running.is_some() || !task.schedule.due(now, task.last_run) {
                continue;
            }
            task.last_run = Some(now);
            let action = task.action.clone();
            let timeout = task.timeout;
            let name = task.name.clone();
            // Held until the job's future has actually stopped.
            let lease = task.lease.clone().or_else(|| self.lease.clone());
            task.running = Some(tokio::spawn(async move {
                // A dropped scheduler aborts its jobs, but the lock must stay
                // held until their futures have actually stopped.
                let _lease = lease;
                match tokio::time::timeout(timeout, action()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => eprintln!("cron {name} failed: {err}"),
                    Err(_) => eprintln!("cron {name} timed out"),
                }
            }));
        }
        Ok(())
    }

    pub async fn wait_idle(&mut self) {
        for task in &mut self.tasks {
            if let Some(handle) = task.running.as_mut() {
                let _ = handle.await;
            }
            task.running = None;
        }
    }

    pub async fn shutdown(mut self) -> Result<(), WorkerError> {
        // Go cancels each task's parent context before joining. Stop these
        // futures immediately, retaining the singleton until they are joined.
        self.abort_running().await;
        let mut result = Ok(());
        for task in &mut self.tasks {
            if let Some(lease) = task.lease.take() {
                if let Err(error) = lease.release().await {
                    result = Err(error);
                }
            }
        }
        if let Some(lease) = self.lease.take() {
            lease.release().await?;
        }
        result
    }

    async fn abort_running(&mut self) {
        for task in &self.tasks {
            if let Some(handle) = &task.running {
                handle.abort();
            }
        }
        self.wait_idle().await;
    }

    /// Go checks once a second. Stop admission and cancel work if the backend
    /// which holds the singleton lock is lost.
    pub async fn run_until(
        mut self,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), WorkerError> {
        tokio::pin!(shutdown);
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;
        loop {
            enum Event {
                Stop,
                Lost,
                Tick,
            }
            let event = tokio::select! {
                _ = &mut shutdown => Event::Stop,
                _ = async {
                    match self.lease.as_ref() {
                        Some(lease) => lease.connection_lost().await,
                        // Per-task locks are checked by every tick instead.
                        None => std::future::pending().await,
                    }
                } => Event::Lost,
                _ = ticker.tick() => Event::Tick,
            };
            match event {
                Event::Stop => return self.shutdown().await,
                Event::Lost => {
                    self.abort_running().await;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "cron singleton connection lost",
                    )
                    .into());
                }
                Event::Tick => self.tick(Local::now()).await?,
            }
        }
    }
}

impl Drop for CronScheduler {
    fn drop(&mut self) {
        for task in &self.tasks {
            if let Some(handle) = &task.running {
                handle.abort();
            }
        }
    }
}

type CloseSession = Arc<dyn Fn() + Send + Sync>;

struct LiveSession {
    user_id: i64,
    issued_at_nanos: i128,
    jti: String,
    family: String,
    close: CloseSession,
}

#[derive(Default)]
struct DenylistState {
    rows: Vec<SessionRevocation>,
    protocol_rows: HashMap<(i64, String, String), SessionRevocation>,
    loaded: bool,
    listening: bool,
    generation: u64,
    next_session: u64,
    sessions: HashMap<u64, LiveSession>,
}

/// Process-local revocation mirror and registry of stateful sessions. The
/// snapshot is fetched across tenants using only the worker credential.
pub struct SessionDenylist {
    db: WorkerDatabase,
    state: Arc<Mutex<DenylistState>>,
    refresh_gate: tokio::sync::Mutex<()>,
    imap_registry: Mutex<Option<Arc<setjoin_imap::ProtocolSessionRegistry>>>,
}

impl SessionDenylist {
    pub fn new(db: WorkerDatabase) -> Self {
        Self {
            db,
            state: Arc::new(Mutex::new(DenylistState::default())),
            refresh_gate: tokio::sync::Mutex::new(()),
            imap_registry: Mutex::new(None),
        }
    }

    /// SMTP submission shares the one registry type with IMAP (#501); each runtime
    /// owns its own denylist and attaches its own registry.
    pub fn attach_protocol(&self,registry:Arc<setjoin_imap::ProtocolSessionRegistry>){self.attach_imap(registry)}

    pub fn attach_imap(&self,registry:Arc<setjoin_imap::ProtocolSessionRegistry>){
        let rows=self.state.lock().expect("denylist lock").protocol_rows.values().filter_map(imap_row).collect::<Vec<_>>();
        registry.reconcile(&rows);
        *self.imap_registry.lock().expect("IMAP registry lock")=Some(registry);
    }

    pub fn loaded(&self) -> bool {
        self.state.lock().expect("denylist lock").loaded
    }

    pub fn listening(&self) -> bool {
        self.state.lock().expect("denylist lock").listening
    }

    pub fn is_revoked(
        &self,
        user_id: i64,
        jti: &str,
        family: &str,
        issued_at: DateTime<Utc>,
    ) -> bool {
        self.state
            .lock()
            .expect("denylist lock")
            .rows
            .iter()
            .any(|row| matches_session(row, user_id, utc_nanos(issued_at), jti, family))
    }

    /// A registration stays active until its handle is dropped or revoked.
    pub fn register_session(
        &self,
        user_id: i64,
        issued_at: DateTime<Utc>,
        jti: &str,
        family: &str,
        close: CloseSession,
    ) -> SessionRegistration {
        let mut state = self.state.lock().expect("denylist lock");
        if user_id <= 0 || utc_nanos(issued_at) == GO_ZERO_TIME {
            return SessionRegistration {
                state: Weak::new(),
                id: None,
            };
        }
        prune_protocol_rows(&mut state, utc_nanos(Utc::now()));
        if state
            .protocol_rows
            .values()
            .any(|row| matches_session(row, user_id, utc_nanos(issued_at), jti, family))
        {
            drop(state);
            close();
            return SessionRegistration {
                state: Weak::new(),
                id: None,
            };
        }
        state.next_session += 1;
        let id = state.next_session;
        state.sessions.insert(
            id,
            LiveSession {
                user_id,
                issued_at_nanos: utc_nanos(issued_at),
                jti: jti.to_owned(),
                family: family.to_owned(),
                close,
            },
        );
        SessionRegistration {
            state: Arc::downgrade(&self.state),
            id: Some(id),
        }
    }

    /// One Go-equivalent reconciliation tick. Failed reads keep the previous
    /// snapshot; a concurrent notification cannot be overwritten by a stale read.
    pub async fn refresh_once(&self) -> Result<(), WorkerError> {
        let _guard = self.refresh_gate.lock().await;
        let generation = self.state.lock().expect("denylist lock").generation;
        let mut rows = self.db.active_session_revocations().await?;
        if let Some(registry)=self.imap_registry.lock().expect("IMAP registry lock").as_ref(){registry.reconcile(&rows.iter().filter_map(imap_row).collect::<Vec<_>>());}
        let mut state = self.state.lock().expect("denylist lock");
        let now = utc_nanos(Utc::now());
        prune_protocol_rows(&mut state, now);
        for row in &rows {
            apply_protocol_row(&mut state, row.clone(), now);
        }
        if state.generation != generation {
            rows.extend(state.rows.clone());
        }
        state.rows = compact_rows(rows, now);
        state.loaded = true;
        let closures = take_revoked_sessions(&mut state);
        drop(state);
        for close in closures {
            close();
        }
        Ok(())
    }

    fn apply_notification(&self, payload: &str) -> Result<(), WorkerError> {
        let value: serde_json::Value = serde_json::from_str(payload)?;
        let string = |key: &str| -> Result<&str, WorkerError> {
            match value.get(key) {
                None | Some(serde_json::Value::Null) => Ok(""),
                Some(serde_json::Value::String(value)) => Ok(value),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid revocation field",
                )
                .into()),
            }
        };
        let user_id = match value.get("user_id") {
            None | Some(serde_json::Value::Null) => 0,
            Some(value) => value.as_i64().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid revocation user")
            })?,
        };
        let not_before =
            utc_nanos(DateTime::parse_from_rfc3339(string("not_before")?)?.with_timezone(&Utc));
        let expires = match string("expires_at")? {
            "" => None,
            value => Some(utc_nanos(
                DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc),
            )),
        };
        let row = SessionRevocation {
            user_id,
            scope: string("scope")?.to_owned(),
            jti: string("jti")?.to_owned(),
            family: string("family_id")?.to_owned(),
            not_before_nanos: not_before,
            expires_at_nanos: expires,
        };
        if let Some(registry)=self.imap_registry.lock().expect("IMAP registry lock").as_ref(){if let Some(row)=imap_row(&row){registry.apply(&row);}}
        let mut state = self.state.lock().expect("denylist lock");
        let now = utc_nanos(Utc::now());
        prune_protocol_rows(&mut state, now);
        apply_protocol_row(&mut state, row.clone(), now);
        let mut rows = std::mem::take(&mut state.rows);
        rows.push(row);
        state.rows = compact_rows(rows, now);
        state.generation = state.generation.wrapping_add(1);
        let closures = take_revoked_sessions(&mut state);
        drop(state);
        for close in closures {
            close();
        }
        Ok(())
    }

    async fn listen(self: Arc<Self>, direct_dsn: String) {
        let mut backoff = Duration::from_secs(1);
        loop {
            let connection = tokio::time::timeout(
                Duration::from_secs(2),
                DirectListener::connect(&direct_dsn, "session_revoke"),
            )
            .await;
            let mut listener = match connection {
                Ok(Ok(listener)) => listener,
                _ => {
                    eprintln!("session denylist: direct LISTEN unavailable; retrying");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    continue;
                }
            };
            backoff = Duration::from_secs(1);
            self.state.lock().expect("denylist lock").listening = true;
            let _guard = ListenerReadiness(self.state.clone());
            // Subscribe before reconciling, so reconnect gaps are repaired now
            // and changes racing this snapshot remain queued on the listener.
            if !matches!(tokio::time::timeout(Duration::from_secs(2), self.refresh_once()).await, Ok(Ok(()))) {
                eprintln!("session denylist: reconnect reconcile failed; keeping prior snapshot");
            }
            while let Some(notification) = listener.recv().await {
                if self.apply_notification(notification.payload()).is_err() {
                    eprintln!("session denylist: malformed session_revoke notification");
                }
            }
            let _ = listener.close().await;
            drop(_guard);
            tokio::time::sleep(backoff).await;
        }
    }

    /// Run reconciliation independently of the direct LISTEN reconnect loop.
    pub async fn run(
        self: Arc<Self>,
        direct_dsn: String,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), WorkerError> {
        let listener = self.clone().listen(direct_dsn);
        tokio::pin!(listener);
        tokio::pin!(shutdown);
        let mut ticker = tokio::time::interval(Duration::from_secs(30));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = &mut shutdown => return Ok(()),
                _ = &mut listener => return Err(std::io::Error::other("session listener stopped").into()),
                _ = ticker.tick() => {
                    if !matches!(tokio::time::timeout(Duration::from_secs(2), self.refresh_once()).await, Ok(Ok(()))) {
                        eprintln!("session denylist: reconcile failed; keeping prior snapshot");
                    }
                }
            }
        }
    }
}

fn imap_row(row:&SessionRevocation)->Option<setjoin_imap::RevocationRow>{
    if row.scope!="all"||row.not_before_nanos<=0{return None}
    let time=|n:i128|std::time::UNIX_EPOCH.checked_add(Duration::from_nanos(u64::try_from(n).ok()?));
    Some(setjoin_imap::RevocationRow{user_id:row.user_id,not_before:time(row.not_before_nanos)?,expires_at:row.expires_at_nanos.and_then(time),scope_all:true})
}

struct ListenerReadiness(Arc<Mutex<DenylistState>>);

impl Drop for ListenerReadiness {
    fn drop(&mut self) {
        self.0.lock().expect("denylist lock").listening = false;
    }
}

fn utc_nanos(time: DateTime<Utc>) -> i128 {
    i128::from(time.timestamp()) * 1_000_000_000 + i128::from(time.timestamp_subsec_nanos())
}

const GO_ZERO_TIME: i128 = -62_135_596_800_i128 * 1_000_000_000;

fn prune_protocol_rows(state: &mut DenylistState, now: i128) {
    state
        .protocol_rows
        .retain(|_, row| row.expires_at_nanos.is_none_or(|expires| expires > now));
}

fn apply_protocol_row(state: &mut DenylistState, mut row: SessionRevocation, now: i128) {
    if row.user_id <= 0
        || row.not_before_nanos == GO_ZERO_TIME
        || row.expires_at_nanos.is_some_and(|expires| expires <= now)
    {
        return;
    }
    let key_part = match row.scope.as_str() {
        "all" => "",
        "jti" if !row.jti.is_empty() => &row.jti,
        "family" if !row.family.is_empty() => &row.family,
        _ => return,
    };
    let key = (row.user_id, row.scope.clone(), key_part.to_owned());
    if row.scope == "all"
        && state
            .protocol_rows
            .get(&key)
            .is_some_and(|old| old.not_before_nanos >= row.not_before_nanos)
    {
        return;
    }
    // Go's protocol registry keeps pre-expires_at notifications for 31 days.
    if row.expires_at_nanos.is_none() {
        row.expires_at_nanos = Some(now + 31_i128 * 24 * 60 * 60 * 1_000_000_000);
    }
    state.protocol_rows.insert(key, row);
}

fn matches_session(
    row: &SessionRevocation,
    user_id: i64,
    issued: i128,
    jti: &str,
    family: &str,
) -> bool {
    row.user_id == user_id
        && match row.scope.as_str() {
            "all" => issued <= row.not_before_nanos,
            "jti" => !jti.is_empty() && row.jti == jti,
            "family" => !family.is_empty() && row.family == family,
            _ => false,
        }
}

fn compact_rows(rows: Vec<SessionRevocation>, now: i128) -> Vec<SessionRevocation> {
    let mut compact: HashMap<(i64, String, String), SessionRevocation> = HashMap::new();
    for row in rows {
        if row.user_id <= 0
            || row.not_before_nanos == GO_ZERO_TIME
            || row.expires_at_nanos.is_some_and(|expires| expires <= now)
        {
            continue;
        }
        let key_part = match row.scope.as_str() {
            "all" => "",
            "jti" if !row.jti.is_empty() => &row.jti,
            "family" if !row.family.is_empty() => &row.family,
            _ => continue,
        };
        let key = (row.user_id, row.scope.clone(), key_part.to_owned());
        if compact
            .get(&key)
            .is_none_or(|old| row.not_before_nanos > old.not_before_nanos)
        {
            compact.insert(key, row);
        }
    }
    compact.into_values().collect()
}

fn take_revoked_sessions(state: &mut DenylistState) -> Vec<CloseSession> {
    let ids: Vec<_> = state
        .sessions
        .iter()
        .filter_map(|(id, session)| {
            state
                .protocol_rows
                .values()
                .any(|row| {
                    matches_session(
                        row,
                        session.user_id,
                        session.issued_at_nanos,
                        &session.jti,
                        &session.family,
                    )
                })
                .then_some(*id)
        })
        .collect();
    ids.into_iter()
        .filter_map(|id| state.sessions.remove(&id).map(|s| s.close))
        .collect()
}

pub struct SessionRegistration {
    state: Weak<Mutex<DenylistState>>,
    id: Option<u64>,
}

impl Drop for SessionRegistration {
    fn drop(&mut self) {
        if let (Some(state), Some(id)) = (self.state.upgrade(), self.id) {
            state.lock().expect("denylist lock").sessions.remove(&id);
        }
    }
}
