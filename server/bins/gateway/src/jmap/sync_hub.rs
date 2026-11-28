//! Scope-keyed `SyncWakeup` push hub with batched authorization and live
//! `scope_revoked` detachment (Wave 2.5, #552).
//!
//! Multiplexes five PostgreSQL `LISTEN` channels over a single [`ListenHub`]:
//! - `sync` (cap 2048): Wave 2.1 content-free scope wakeup bells
//! - `scope_revoked` (cap 4096): opaque `public.scope_revocations.id` pointers
//! - `drive_access` (cap 1024): Drive ACL / subtree invalidations
//! - `group_membership_changed` (cap 1024): org/AD group membership changes
//! - `chat_ephemeral` (cap 1024): O(1) ephemeral typing events fanned out in memory
//!
//! Each connection owns two strictly separated outbound rails:
//! 1. **Priority control rail** (cap 64): `ScopeRevoked`, `SessionRevoked`,
//!    `offline.wipe`, `Restart`. Never drops a revocation; on overflow closes
//!    the connection cleanly with `CloseCode::Restart`.
//! 2. **Coalescing wakeup rail** (`HashMap<ScopeKey, PendingWakeup>`): merges
//!    `dataTypes` (capped at 64) and takes `MAX(seq)` for `space`/`channel`
//!    (`0` for `mailbox`), so slow clients never backpressure the hub or drop
//!    control frames.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use serde_json::{json, Value};
use setjoin_contracts::ids::ActorId;
use setjoin_pg::{ListenEvent, ListenHub, ScopedExecutor, Type};
use tokio::sync::{mpsc, Notify};
use tokio_util::sync::CancellationToken;

/// Maximum scopes a single connection may attach concurrently (aligned with
/// `#555` `validate.ts:MAX_ATTACHED_SCOPES`).
pub const MAX_ATTACHED_SCOPES: usize = 512;
/// Maximum `dataTypes` entries carried on a single `SyncWakeup` frame.
pub const MAX_WAKEUP_DATA_TYPES: usize = 64;
/// Maximum length of a scope identifier string.
pub const MAX_SCOPE_ID_LENGTH: usize = 128;
/// Bounded capacity for the per-connection priority control rail.
pub const CONTROL_RAIL_CAPACITY: usize = 64;
/// Bounded capacity for per-connection ephemeral chat events (typing).
pub const EPHEMERAL_RAIL_CAPACITY: usize = 32;
/// Authorization batch deadline for `ScopeAttach`.
pub const ATTACH_AUTH_DEADLINE: Duration = Duration::from_secs(5);

pub const SYNC_LISTEN_CAPACITY: usize = 2048;
pub const SCOPE_REVOKED_LISTEN_CAPACITY: usize = 4096;
pub const DRIVE_ACCESS_LISTEN_CAPACITY: usize = 1024;
pub const GROUP_MEMBERSHIP_LISTEN_CAPACITY: usize = 1024;
pub const CHAT_EPHEMERAL_LISTEN_CAPACITY: usize = 1024;

/// Scope family key aligned with `#555` `ScopeKind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ScopeKind {
    Mailbox,
    Space,
    Channel,
}

impl ScopeKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mailbox => "mailbox",
            Self::Space => "space",
            Self::Channel => "channel",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "mailbox" => Some(Self::Mailbox),
            "space" => Some(Self::Space),
            "channel" => Some(Self::Channel),
            _ => None,
        }
    }
}

/// Canonical `(kind, numeric_id)` scope key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScopeKey {
    pub kind: ScopeKind,
    pub id: i64,
}

/// Client-supplied scope descriptor (`scopeId` may be `"primary"` for mailbox).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeDescriptor {
    pub kind: ScopeKind,
    pub raw_id: String,
}

/// Single denied scope entry returned in `ScopeAttachResponse`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeniedScope {
    pub scope_kind: ScopeKind,
    pub scope_id: String,
    pub reason: &'static str,
}

/// Result of a batched `ScopeAttach` operation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScopeAttachResult {
    pub attached: Vec<ScopeDescriptor>,
    pub denied: Vec<DeniedScope>,
}

/// Granular allowed JMAP data types on an attached mailbox scope, reflecting
/// both mailbox delegation / calendar ACL rights and per-app entitlements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MailboxDataTypes {
    pub mail: bool,
    pub calendar: bool,
    pub contacts: bool,
    pub tasks: bool,
}

impl MailboxDataTypes {
    pub const ALL: Self = Self {
        mail: true,
        calendar: true,
        contacts: true,
        tasks: true,
    };

    pub const CALENDAR_ONLY: Self = Self {
        mail: false,
        calendar: true,
        contacts: false,
        tasks: false,
    };

    pub const fn is_empty(self) -> bool {
        !self.mail && !self.calendar && !self.contacts && !self.tasks
    }

    pub const fn narrowed_from(self, prev: Self) -> bool {
        (prev.mail && !self.mail)
            || (prev.calendar && !self.calendar)
            || (prev.contacts && !self.contacts)
            || (prev.tasks && !self.tasks)
    }

    pub fn allows(self, data_type: &str) -> bool {
        match data_type {
            "Email" | "Mailbox" | "Thread" | "Identity" | "EmailSubmission" | "Reminder" => {
                self.mail
            }
            "Calendar" | "CalendarEvent" => self.calendar,
            "Contact" | "AddressBook" => self.contacts,
            "Task" | "TaskList" => self.tasks,
            _ => self.mail,
        }
    }

    pub fn filter(self, types: &[String]) -> Vec<String> {
        types.iter().filter(|dt| self.allows(dt)).cloned().collect()
    }
}

/// Wire payload for `ScopeRevoked` (WS) / `scope_revoked` (SSE).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeRevokedWire {
    pub scope_kind: ScopeKind,
    pub scope_id: String,
    pub subtree_anchor_id: Option<String>,
    pub reason: Option<String>,
}

impl ScopeRevokedWire {
    pub fn to_event_json(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("scopeKind".into(), json!(self.scope_kind.as_str()));
        obj.insert("scopeId".into(), json!(self.scope_id));
        if let Some(anchor) = &self.subtree_anchor_id {
            obj.insert("subtreeAnchorId".into(), json!(anchor));
        }
        if let Some(reason) = &self.reason {
            obj.insert("reason".into(), json!(reason));
        }
        Value::Object(obj)
    }

    pub fn to_ws_frame(&self) -> String {
        format!(
            "{}\n",
            json!({"@type": "ScopeRevoked", "event": self.to_event_json()})
        )
    }

    pub fn to_sse_frame(&self) -> String {
        format!("event: scope_revoked\ndata: {}\n\n", self.to_event_json())
    }
}

/// Priority control-rail message for a single connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlMessage {
    ScopeRevoked(ScopeRevokedWire),
    SessionRevoked,
    OfflineWipe(String),
    Restart(&'static str),
}

/// Coalesced wakeup payload ready for delivery to a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveredWakeup {
    pub scope_kind: ScopeKind,
    pub scope_id: String,
    pub seq: i64,
    pub data_types: Vec<String>,
}

impl DeliveredWakeup {
    pub fn to_event_json(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("scopeKind".into(), json!(self.scope_kind.as_str()));
        obj.insert("scopeId".into(), json!(self.scope_id));
        obj.insert("seq".into(), json!(self.seq));
        if !self.data_types.is_empty() {
            obj.insert("dataTypes".into(), json!(self.data_types));
        }
        Value::Object(obj)
    }

    pub fn to_ws_frame(&self) -> String {
        format!(
            "{}\n",
            json!({"@type": "SyncWakeup", "event": self.to_event_json()})
        )
    }

    pub fn to_sse_frame(&self) -> String {
        format!("event: sync_wakeup\ndata: {}\n\n", self.to_event_json())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingWakeup {
    alias: String,
    seq: i64,
    data_types: Vec<String>,
}

/// Per-connection coalescing wakeup mailbox.
///
/// Bounded by `<= MAX_ATTACHED_SCOPES` entries; never blocks the hub or drops
/// control frames.
pub struct WakeupMailbox {
    pending: Mutex<BTreeMap<ScopeKey, PendingWakeup>>,
    notify: Notify,
}

impl Default for WakeupMailbox {
    fn default() -> Self {
        Self::new()
    }
}

impl WakeupMailbox {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(BTreeMap::new()),
            notify: Notify::new(),
        }
    }

    pub fn push(&self, key: ScopeKey, alias: &str, seq: i64, data_types: &[String]) {
        let mut map = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let effective_seq = if key.kind == ScopeKind::Mailbox {
            0
        } else {
            seq.max(0)
        };
        match map.get_mut(&key) {
            Some(entry) => {
                entry.alias = alias.to_owned();
                if key.kind == ScopeKind::Mailbox {
                    entry.seq = 0;
                } else if key.kind == ScopeKind::Channel && (entry.seq == 0 || effective_seq == 0) {
                    // Preserve seq = 0 for non-seq-advancing Chat events
                    // (reactions, polls, pins, roster) so #555 never skips
                    // them behind an already-applied message seq.
                    entry.seq = 0;
                } else {
                    entry.seq = entry.seq.max(effective_seq);
                }
                for dt in data_types {
                    if entry.data_types.len() >= MAX_WAKEUP_DATA_TYPES {
                        break;
                    }
                    if !entry.data_types.iter().any(|existing| existing == dt) {
                        entry.data_types.push(dt.clone());
                    }
                }
            }
            None => {
                let mut dts = Vec::new();
                for dt in data_types {
                    if dts.len() >= MAX_WAKEUP_DATA_TYPES {
                        break;
                    }
                    if !dts.iter().any(|existing| existing == dt) {
                        dts.push(dt.clone());
                    }
                }
                map.insert(
                    key,
                    PendingWakeup {
                        alias: alias.to_owned(),
                        seq: effective_seq,
                        data_types: dts,
                    },
                );
            }
        }
        drop(map);
        self.notify.notify_one();
    }

    pub fn remove(&self, key: ScopeKey) {
        let mut map = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.remove(&key);
    }

    /// Filter queued data types for `key` after a scope privilege narrowing
    /// (e.g. `All` -> `CalendarOnly`), dropping any disallowed entries.
    pub fn retain_data_types(&self, key: ScopeKey, allowed: MailboxDataTypes) {
        let mut map = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let remove_entry = if let Some(entry) = map.get_mut(&key) {
            entry.data_types.retain(|dt| allowed.allows(dt));
            entry.data_types.is_empty()
        } else {
            false
        };
        if remove_entry {
            map.remove(&key);
        }
    }

    /// Remove queued Calendar/CalendarEvent data types for `key` (used when
    /// one shared calendar is revoked while another shared calendar remains).
    pub fn remove_calendar_data_types(&self, key: ScopeKey) {
        let mut map = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let remove_entry = if let Some(entry) = map.get_mut(&key) {
            entry
                .data_types
                .retain(|dt| !matches!(dt.as_str(), "Calendar" | "CalendarEvent"));
            entry.data_types.is_empty()
        } else {
            false
        };
        if remove_entry {
            map.remove(&key);
        }
    }

    pub fn take_one(&self) -> Option<DeliveredWakeup> {
        let mut map = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (key, pending) = map.pop_first()?;
        Some(DeliveredWakeup {
            scope_kind: key.kind,
            scope_id: pending.alias,
            seq: pending.seq,
            data_types: pending.data_types,
        })
    }

    /// Pop a single coalesced wakeup so callers can return to `tokio::select!`
    /// between frames and let priority control frames preempt immediately.
    pub async fn next_one(&self) -> DeliveredWakeup {
        loop {
            let notified = self.notify.notified();
            if let Some(one) = self.take_one() {
                return one;
            }
            notified.await;
        }
    }

    pub fn take_all(&self) -> Vec<DeliveredWakeup> {
        let drained = {
            let mut map = self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if map.is_empty() {
                return Vec::new();
            }
            std::mem::take(&mut *map)
        };
        drained
            .into_iter()
            .map(|(key, pending)| DeliveredWakeup {
                scope_kind: key.kind,
                scope_id: pending.alias,
                seq: pending.seq,
                data_types: pending.data_types,
            })
            .collect()
    }

    pub async fn next_batch(&self) -> Vec<DeliveredWakeup> {
        loop {
            let notified = self.notify.notified();
            let batch = self.take_all();
            if !batch.is_empty() {
                return batch;
            }
            notified.await;
        }
    }
}

#[derive(Clone, Debug)]
struct AttachedScope {
    alias: String,
    grant_generation: u64,
    mailbox_types: Option<MailboxDataTypes>,
}

struct ConnEntry {
    user_id: i64,
    primary_mailbox: Option<i64>,
    is_guest: bool,
    scopes: HashMap<ScopeKey, AttachedScope>,
    op_seq: u64,
    active_attach_ops: BTreeSet<u64>,
    detached_at: HashMap<ScopeKey, u64>,
    control_tx: mpsc::Sender<ControlMessage>,
    wakeups: Arc<WakeupMailbox>,
    ephemeral_tx: mpsc::Sender<String>,
    restart_close: Arc<dyn Fn(&'static str) + Send + Sync>,
}

impl ConnEntry {
    fn prune_stale_detached_markers(&mut self) {
        if self.detached_at.len() < MAX_ATTACHED_SCOPES * 4 {
            return;
        }
        if let Some(&min_active) = self.active_attach_ops.first() {
            // Only markers strictly newer than `min_active` can ever match
            // `detached_seq > attach_op_seq` for an in-flight ScopeAttach.
            self.detached_at.retain(|_, &mut seq| seq > min_active);
        } else {
            self.detached_at.clear();
        }
    }
}

struct ActiveAttachGuard<'a> {
    hub: &'a SyncWakeupHub,
    conn_id: u64,
    seq: u64,
}

impl Drop for ActiveAttachGuard<'_> {
    fn drop(&mut self) {
        if self.seq == 0 {
            return;
        }
        let mut reg = self
            .hub
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(conn) = reg.connections.get_mut(&self.conn_id) {
            conn.active_attach_ops.remove(&self.seq);
            conn.prune_stale_detached_markers();
        }
    }
}

/// Outcome of an attach operation that also verifies session revocation before
/// installing scopes into the live routing index.
#[derive(Clone, Debug, Default)]
pub struct ScopeAttachOutcome {
    pub result: ScopeAttachResult,
    pub session_revoked: bool,
}

#[derive(Default)]
struct Registry {
    connections: HashMap<u64, ConnEntry>,
    scope_index: HashMap<ScopeKey, HashSet<u64>>,
    user_index: HashMap<i64, HashSet<u64>>,
}

impl Registry {
    fn attach_scope(
        &mut self,
        conn_id: u64,
        key: ScopeKey,
        alias: String,
        grant_generation: u64,
        mailbox_types: Option<MailboxDataTypes>,
        attach_op_seq: u64,
    ) -> AttachSlotOutcome {
        let Some(conn) = self.connections.get_mut(&conn_id) else {
            return AttachSlotOutcome::ConnectionGone;
        };
        if conn
            .detached_at
            .get(&key)
            .is_some_and(|&detached_seq| detached_seq > attach_op_seq)
        {
            return AttachSlotOutcome::DetachedDuringAttach;
        }
        if !conn.scopes.contains_key(&key) && conn.scopes.len() >= MAX_ATTACHED_SCOPES {
            return AttachSlotOutcome::LimitExceeded;
        }
        conn.scopes.insert(
            key,
            AttachedScope {
                alias,
                grant_generation,
                mailbox_types,
            },
        );
        self.scope_index.entry(key).or_default().insert(conn_id);
        AttachSlotOutcome::Attached
    }

    fn detach_scope(&mut self, conn_id: u64, key: ScopeKey) -> Option<AttachedScope> {
        let conn = self.connections.get_mut(&conn_id)?;
        let removed = conn.scopes.remove(&key);
        if removed.is_some() {
            conn.wakeups.remove(key);
            if let Some(set) = self.scope_index.get_mut(&key) {
                set.remove(&conn_id);
                if set.is_empty() {
                    self.scope_index.remove(&key);
                }
            }
        }
        removed
    }

    fn remove_connection(&mut self, conn_id: u64) {
        if let Some(conn) = self.connections.remove(&conn_id) {
            for key in conn.scopes.keys() {
                if let Some(set) = self.scope_index.get_mut(key) {
                    set.remove(&conn_id);
                    if set.is_empty() {
                        self.scope_index.remove(key);
                    }
                }
            }
            if let Some(set) = self.user_index.get_mut(&conn.user_id) {
                set.remove(&conn_id);
                if set.is_empty() {
                    self.user_index.remove(&conn.user_id);
                }
            }
        }
    }
}

/// RAII guard for a registered [`SyncWakeupHub`] connection after splitting
/// its receiver channels. Dropping this guard unregisters the connection.
pub struct HubConnectionGuard {
    pub id: u64,
    hub: Arc<SyncWakeupHub>,
}

impl HubConnectionGuard {
    pub async fn attach_scopes(&self, raw_scopes: &[ScopeDescriptor]) -> ScopeAttachResult {
        self.hub.attach_scopes(self.id, raw_scopes).await
    }

    pub fn detach_scopes(&self, raw_scopes: &[ScopeDescriptor]) -> Vec<ScopeDescriptor> {
        self.hub.detach_scopes(self.id, raw_scopes)
    }

    pub async fn attach_guest_default_scopes(&self) -> ScopeAttachResult {
        self.hub.attach_guest_default_scopes(self.id).await
    }
}

impl Drop for HubConnectionGuard {
    fn drop(&mut self) {
        self.hub.unregister_connection(self.id);
    }
}

/// Handle returned when a WS or SSE connection registers with [`SyncWakeupHub`].
///
/// Dropping this handle automatically unregisters the connection and releases
/// all of its scope index entries.
pub struct HubConnection {
    pub id: u64,
    pub control_rx: mpsc::Receiver<ControlMessage>,
    pub wakeups: Arc<WakeupMailbox>,
    pub ephemeral_rx: mpsc::Receiver<String>,
    guard: HubConnectionGuard,
}

impl HubConnection {
    pub async fn attach_scopes(&self, raw_scopes: &[ScopeDescriptor]) -> ScopeAttachResult {
        self.guard.attach_scopes(raw_scopes).await
    }

    pub fn detach_scopes(&self, raw_scopes: &[ScopeDescriptor]) -> Vec<ScopeDescriptor> {
        self.guard.detach_scopes(raw_scopes)
    }

    pub async fn attach_guest_default_scopes(&self) -> ScopeAttachResult {
        self.guard.attach_guest_default_scopes().await
    }

    /// Split into an RAII registration guard plus independently borrowable
    /// control, coalescing wakeup, and ephemeral channels for `tokio::select!`.
    pub fn split(
        self,
    ) -> (
        HubConnectionGuard,
        mpsc::Receiver<ControlMessage>,
        Arc<WakeupMailbox>,
        mpsc::Receiver<String>,
    ) {
        (self.guard, self.control_rx, self.wakeups, self.ephemeral_rx)
    }
}

/// Process-local scope-keyed `SyncWakeup` push hub over PostgreSQL `LISTEN`.
pub struct SyncWakeupHub {
    exec: ScopedExecutor,
    worker: ScopedExecutor,
    registry: Mutex<Registry>,
    next_conn_id: AtomicU64,
    next_grant_gen: AtomicU64,
    last_seen_revocation_id: AtomicI64,
    last_seen_drive_invalidation_cursor: AtomicI64,
    revocation_signal_epoch: AtomicU64,
    shutdown: CancellationToken,
    ready: Arc<Notify>,
    ready_flag: std::sync::atomic::AtomicBool,
    _owned_listen_hub: Option<ListenHub>,
}

impl Drop for SyncWakeupHub {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl SyncWakeupHub {
    /// Start a `SyncWakeupHub` sharing an existing process-wide [`ListenHub`].
    pub fn with_listen_hub(
        listen_hub: ListenHub,
        exec: ScopedExecutor,
        worker: ScopedExecutor,
    ) -> Arc<Self> {
        let shutdown = CancellationToken::new();
        let hub = Arc::new(Self {
            exec,
            worker,
            registry: Mutex::new(Registry::default()),
            next_conn_id: AtomicU64::new(1),
            next_grant_gen: AtomicU64::new(1),
            last_seen_revocation_id: AtomicI64::new(0),
            last_seen_drive_invalidation_cursor: AtomicI64::new(0),
            revocation_signal_epoch: AtomicU64::new(0),
            shutdown: shutdown.clone(),
            ready: Arc::new(Notify::new()),
            ready_flag: std::sync::atomic::AtomicBool::new(false),
            _owned_listen_hub: None,
        });
        // Hold only a Weak reference inside the spawned task so dropping the
        // last external Arc<SyncWakeupHub> triggers Drop -> shutdown.cancel()
        // and exits the listener loop with zero task leak.
        let weak = Arc::downgrade(&hub);
        tokio::spawn(async move {
            Self::run_listener_loop(weak, listen_hub, shutdown).await;
        });
        hub
    }

    /// Start a `SyncWakeupHub` with its own [`ListenHub`] over `direct_dsn`.
    /// Returns `None` if `direct_dsn` is empty or invalid.
    pub fn from_direct_dsn(
        direct_dsn: &str,
        exec: ScopedExecutor,
        worker: ScopedExecutor,
    ) -> Option<Arc<Self>> {
        if direct_dsn.trim().is_empty() {
            return None;
        }
        let shutdown = CancellationToken::new();
        let listen_hub = ListenHub::spawn(direct_dsn.to_owned(), shutdown.clone()).ok()?;
        let hub = Arc::new(Self {
            exec,
            worker,
            registry: Mutex::new(Registry::default()),
            next_conn_id: AtomicU64::new(1),
            next_grant_gen: AtomicU64::new(1),
            last_seen_revocation_id: AtomicI64::new(0),
            last_seen_drive_invalidation_cursor: AtomicI64::new(0),
            revocation_signal_epoch: AtomicU64::new(0),
            shutdown: shutdown.clone(),
            ready: Arc::new(Notify::new()),
            ready_flag: std::sync::atomic::AtomicBool::new(false),
            _owned_listen_hub: Some(listen_hub.clone()),
        });
        let weak = Arc::downgrade(&hub);
        tokio::spawn(async move {
            Self::run_listener_loop(weak, listen_hub, shutdown).await;
        });
        Some(hub)
    }

    /// Wait until all 5 `ListenHub` subscriptions and initial revocation
    /// watermark are initialized (bounded by `timeout`).
    pub async fn wait_ready(&self, timeout: Duration) -> bool {
        if self.ready_flag.load(Ordering::Acquire) {
            return true;
        }
        let notified = self.ready.notified();
        if self.ready_flag.load(Ordering::Acquire) {
            return true;
        }
        tokio::time::timeout(timeout, notified).await.is_ok()
    }

    /// Shut down the hub listener tasks cleanly.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }

    /// Register a new WS/SSE connection with the hub.
    pub fn register_connection(
        self: &Arc<Self>,
        user_id: i64,
        primary_mailbox: Option<i64>,
        is_guest: bool,
        restart_close: Arc<dyn Fn(&'static str) + Send + Sync>,
    ) -> HubConnection {
        let id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let (control_tx, control_rx) = mpsc::channel(CONTROL_RAIL_CAPACITY);
        let (ephemeral_tx, ephemeral_rx) = mpsc::channel(EPHEMERAL_RAIL_CAPACITY);
        let wakeups = Arc::new(WakeupMailbox::new());
        {
            let mut reg = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            reg.connections.insert(
                id,
                ConnEntry {
                    user_id,
                    primary_mailbox,
                    is_guest,
                    scopes: HashMap::new(),
                    op_seq: 0,
                    active_attach_ops: BTreeSet::new(),
                    detached_at: HashMap::new(),
                    control_tx,
                    wakeups: wakeups.clone(),
                    ephemeral_tx,
                    restart_close,
                },
            );
            reg.user_index.entry(user_id).or_default().insert(id);
        }
        HubConnection {
            id,
            control_rx,
            wakeups,
            ephemeral_rx,
            guard: HubConnectionGuard {
                id,
                hub: self.clone(),
            },
        }
    }

    fn unregister_connection(&self, conn_id: u64) {
        let mut reg = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reg.remove_connection(conn_id);
    }

    /// Snapshot attached scopes for a connection (for diagnostics & tests).
    pub fn attached_scopes_for(&self, conn_id: u64) -> Vec<(ScopeKey, String)> {
        let reg = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reg.connections
            .get(&conn_id)
            .map(|c| {
                c.scopes
                    .iter()
                    .map(|(k, v)| (*k, v.alias.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Record the start of an off-loop `ScopeAttach` operation synchronously on
    /// the connection loop so any subsequent `ScopeDetach` receives a strictly
    /// higher sequence number and wins against an in-flight attach.
    pub fn begin_attach_op(&self, conn_id: u64) -> u64 {
        let mut reg = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(conn) = reg.connections.get_mut(&conn_id) else {
            return 0;
        };
        conn.op_seq = conn.op_seq.saturating_add(1);
        conn.active_attach_ops.insert(conn.op_seq);
        conn.op_seq
    }

    /// Detach a list of client-supplied scopes immediately.
    pub fn detach_scopes(
        &self,
        conn_id: u64,
        raw_scopes: &[ScopeDescriptor],
    ) -> Vec<ScopeDescriptor> {
        let mut detached = Vec::new();
        let mut reg = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (primary_mailbox, detach_seq) = {
            let Some(conn) = reg.connections.get_mut(&conn_id) else {
                return detached;
            };
            conn.op_seq = conn.op_seq.saturating_add(1);
            (conn.primary_mailbox, conn.op_seq)
        };
        for desc in raw_scopes {
            let resolved_id = if desc.kind == ScopeKind::Mailbox && desc.raw_id == "primary" {
                primary_mailbox
            } else {
                parse_positive_scope_id(&desc.raw_id)
            };
            if let Some(id) = resolved_id {
                let key = ScopeKey {
                    kind: desc.kind,
                    id,
                };
                if let Some(conn) = reg.connections.get_mut(&conn_id) {
                    conn.prune_stale_detached_markers();
                    conn.detached_at.insert(key, detach_seq);
                }
                if reg.detach_scope(conn_id, key).is_some() {
                    detached.push(desc.clone());
                }
            }
        }
        detached
    }

    /// Authorize and attach requested scopes in at most 3 batched SQL queries
    /// (bounded by [`ATTACH_AUTH_DEADLINE`]), enforcing `MAX_ATTACHED_SCOPES = 512`
    /// with partial denials, keeping scopes unroutable until authorized and
    /// revocation-fenced.
    pub async fn attach_scopes(
        &self,
        conn_id: u64,
        raw_scopes: &[ScopeDescriptor],
    ) -> ScopeAttachResult {
        let seq = self.begin_attach_op(conn_id);
        self.attach_scopes_with_seq(conn_id, raw_scopes, seq).await
    }

    /// Same as [`Self::attach_scopes`] using an operation sequence captured
    /// synchronously before spawning the async attach task.
    pub async fn attach_scopes_with_seq(
        &self,
        conn_id: u64,
        raw_scopes: &[ScopeDescriptor],
        attach_op_seq: u64,
    ) -> ScopeAttachResult {
        self.attach_scopes_with_seq_checked(conn_id, raw_scopes, attach_op_seq, || async { false })
            .await
            .result
    }

    /// Authorize and attach requested scopes using a pre-captured `attach_op_seq`
    /// and a caller-supplied `session_revoked` check that runs BEFORE any scope
    /// is inserted into `scope_index`.
    pub async fn attach_scopes_with_seq_checked<F, Fut>(
        &self,
        conn_id: u64,
        raw_scopes: &[ScopeDescriptor],
        attach_op_seq: u64,
        session_revoked: F,
    ) -> ScopeAttachOutcome
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let _active_guard = ActiveAttachGuard {
            hub: self,
            conn_id,
            seq: attach_op_seq,
        };
        let (user_id, primary_mailbox, is_guest, already_attached) = {
            let reg = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(conn) = reg.connections.get(&conn_id) else {
                return ScopeAttachOutcome::default();
            };
            (
                conn.user_id,
                conn.primary_mailbox,
                conn.is_guest,
                conn.scopes.keys().copied().collect::<HashSet<_>>(),
            )
        };

        let mut result = ScopeAttachResult::default();
        let mut seen = HashSet::new();
        let mut mailbox_reqs: Vec<(i64, String)> = Vec::new();
        let mut channel_reqs: Vec<(i64, String)> = Vec::new();
        let mut space_reqs: Vec<(i64, String)> = Vec::new();
        let mut new_count = 0usize;
        let existing_count = already_attached.len();

        for desc in raw_scopes {
            if !is_valid_scope_id_wire(&desc.raw_id) {
                result.denied.push(DeniedScope {
                    scope_kind: desc.kind,
                    scope_id: desc.raw_id.clone(),
                    reason: "invalid_scope_id",
                });
                continue;
            }
            let resolved = if desc.kind == ScopeKind::Mailbox && desc.raw_id == "primary" {
                if is_guest {
                    result.denied.push(DeniedScope {
                        scope_kind: desc.kind,
                        scope_id: desc.raw_id.clone(),
                        reason: "forbidden",
                    });
                    continue;
                }
                match primary_mailbox {
                    Some(mb) if mb > 0 => mb,
                    _ => {
                        result.denied.push(DeniedScope {
                            scope_kind: desc.kind,
                            scope_id: desc.raw_id.clone(),
                            reason: "no_primary_mailbox",
                        });
                        continue;
                    }
                }
            } else {
                match parse_positive_scope_id(&desc.raw_id) {
                    Some(id) => id,
                    None => {
                        result.denied.push(DeniedScope {
                            scope_kind: desc.kind,
                            scope_id: desc.raw_id.clone(),
                            reason: "invalid_scope_id",
                        });
                        continue;
                    }
                }
            };

            let key = ScopeKey {
                kind: desc.kind,
                id: resolved,
            };
            if !seen.insert(key) {
                continue;
            }
            if !already_attached.contains(&key) {
                if existing_count + new_count >= MAX_ATTACHED_SCOPES {
                    result.denied.push(DeniedScope {
                        scope_kind: desc.kind,
                        scope_id: desc.raw_id.clone(),
                        reason: "scope_limit_exceeded",
                    });
                    continue;
                }
                new_count += 1;
            }

            match desc.kind {
                ScopeKind::Mailbox => mailbox_reqs.push((resolved, desc.raw_id.clone())),
                ScopeKind::Channel => channel_reqs.push((resolved, desc.raw_id.clone())),
                ScopeKind::Space => space_reqs.push((resolved, desc.raw_id.clone())),
            }
        }

        if mailbox_reqs.is_empty() && channel_reqs.is_empty() && space_reqs.is_empty() {
            return ScopeAttachOutcome {
                result,
                session_revoked: false,
            };
        }

        let deny_all_pending = |res: &mut ScopeAttachResult,
                                mbs: &[(i64, String)],
                                chs: &[(i64, String)],
                                sps: &[(i64, String)],
                                reason: &'static str| {
            for (id, raw) in mbs {
                res.denied.push(DeniedScope {
                    scope_kind: ScopeKind::Mailbox,
                    scope_id: if raw.is_empty() {
                        id.to_string()
                    } else {
                        raw.clone()
                    },
                    reason,
                });
            }
            for (_, raw) in chs {
                res.denied.push(DeniedScope {
                    scope_kind: ScopeKind::Channel,
                    scope_id: raw.clone(),
                    reason,
                });
            }
            for (_, raw) in sps {
                res.denied.push(DeniedScope {
                    scope_kind: ScopeKind::Space,
                    scope_id: raw.clone(),
                    reason,
                });
            }
        };

        let Ok(actor) = ActorId::new(user_id) else {
            deny_all_pending(
                &mut result,
                &mailbox_reqs,
                &channel_reqs,
                &space_reqs,
                "forbidden",
            );
            return ScopeAttachOutcome {
                result,
                session_revoked: false,
            };
        };

        // Pre-install revocation fence: keep scopes completely unroutable until
        // batched authorization, revocation-epoch stability (with 1 bounded
        // retry on drift), and session-revocation verification ALL succeed.
        let mut watermark_checked = self.last_seen_revocation_id.load(Ordering::Acquire);
        let mut epoch_checked = self.revocation_signal_epoch.load(Ordering::Acquire);
        let mut authorized = match tokio::time::timeout(
            ATTACH_AUTH_DEADLINE,
            self.authorize_batched(actor, is_guest, &mailbox_reqs, &channel_reqs, &space_reqs),
        )
        .await
        {
            Ok(Ok(auth)) => auth,
            Ok(Err(_)) | Err(_) => {
                deny_all_pending(
                    &mut result,
                    &mailbox_reqs,
                    &channel_reqs,
                    &space_reqs,
                    "authorization_unavailable",
                );
                return ScopeAttachOutcome {
                    result,
                    session_revoked: false,
                };
            }
        };

        if self.last_seen_revocation_id.load(Ordering::Acquire) > watermark_checked
            || self.revocation_signal_epoch.load(Ordering::Acquire) != epoch_checked
        {
            watermark_checked = self.last_seen_revocation_id.load(Ordering::Acquire);
            epoch_checked = self.revocation_signal_epoch.load(Ordering::Acquire);
            authorized = match tokio::time::timeout(
                ATTACH_AUTH_DEADLINE,
                self.authorize_batched(actor, is_guest, &mailbox_reqs, &channel_reqs, &space_reqs),
            )
            .await
            {
                Ok(Ok(auth)) => auth,
                Ok(Err(_)) | Err(_) => {
                    deny_all_pending(
                        &mut result,
                        &mailbox_reqs,
                        &channel_reqs,
                        &space_reqs,
                        "authorization_unavailable",
                    );
                    return ScopeAttachOutcome {
                        result,
                        session_revoked: false,
                    };
                }
            };
            if self.last_seen_revocation_id.load(Ordering::Acquire) > watermark_checked
                || self.revocation_signal_epoch.load(Ordering::Acquire) != epoch_checked
            {
                deny_all_pending(
                    &mut result,
                    &mailbox_reqs,
                    &channel_reqs,
                    &space_reqs,
                    "revoked",
                );
                return ScopeAttachOutcome {
                    result,
                    session_revoked: false,
                };
            }
        }

        // Verify session revocation BEFORE inserting into `scope_index` so a
        // mid-attach revoked session never becomes routable even briefly.
        if session_revoked().await {
            return ScopeAttachOutcome {
                result: ScopeAttachResult::default(),
                session_revoked: true,
            };
        }

        {
            let mut reg = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Final epoch/watermark check under the registry lock before
            // exposing any scope in `scope_index`.
            if self.last_seen_revocation_id.load(Ordering::Acquire) > watermark_checked
                || self.revocation_signal_epoch.load(Ordering::Acquire) != epoch_checked
            {
                deny_all_pending(
                    &mut result,
                    &mailbox_reqs,
                    &channel_reqs,
                    &space_reqs,
                    "revoked",
                );
                return ScopeAttachOutcome {
                    result,
                    session_revoked: false,
                };
            }

            for (id, raw_id) in mailbox_reqs {
                let key = ScopeKey {
                    kind: ScopeKind::Mailbox,
                    id,
                };
                if let Some(&mb_types) = authorized.mailboxes.get(&id) {
                    let gen = self.next_grant_gen.fetch_add(1, Ordering::AcqRel);
                    match reg.attach_scope(
                        conn_id,
                        key,
                        raw_id.clone(),
                        gen,
                        Some(mb_types),
                        attach_op_seq,
                    ) {
                        AttachSlotOutcome::Attached => {
                            result.attached.push(ScopeDescriptor {
                                kind: ScopeKind::Mailbox,
                                raw_id,
                            });
                        }
                        AttachSlotOutcome::DetachedDuringAttach => {
                            result.denied.push(DeniedScope {
                                scope_kind: ScopeKind::Mailbox,
                                scope_id: raw_id,
                                reason: "detached_during_attach",
                            });
                        }
                        AttachSlotOutcome::LimitExceeded | AttachSlotOutcome::ConnectionGone => {
                            result.denied.push(DeniedScope {
                                scope_kind: ScopeKind::Mailbox,
                                scope_id: raw_id,
                                reason: "scope_limit_exceeded",
                            });
                        }
                    }
                } else {
                    result.denied.push(DeniedScope {
                        scope_kind: ScopeKind::Mailbox,
                        scope_id: raw_id,
                        reason: "forbidden",
                    });
                }
            }
            for (id, raw_id) in channel_reqs {
                let key = ScopeKey {
                    kind: ScopeKind::Channel,
                    id,
                };
                if authorized.channels.contains(&id) {
                    let gen = self.next_grant_gen.fetch_add(1, Ordering::AcqRel);
                    match reg.attach_scope(conn_id, key, raw_id.clone(), gen, None, attach_op_seq) {
                        AttachSlotOutcome::Attached => {
                            result.attached.push(ScopeDescriptor {
                                kind: ScopeKind::Channel,
                                raw_id,
                            });
                        }
                        AttachSlotOutcome::DetachedDuringAttach => {
                            result.denied.push(DeniedScope {
                                scope_kind: ScopeKind::Channel,
                                scope_id: raw_id,
                                reason: "detached_during_attach",
                            });
                        }
                        AttachSlotOutcome::LimitExceeded | AttachSlotOutcome::ConnectionGone => {
                            result.denied.push(DeniedScope {
                                scope_kind: ScopeKind::Channel,
                                scope_id: raw_id,
                                reason: "scope_limit_exceeded",
                            });
                        }
                    }
                } else {
                    result.denied.push(DeniedScope {
                        scope_kind: ScopeKind::Channel,
                        scope_id: raw_id,
                        reason: "forbidden",
                    });
                }
            }
            for (id, raw_id) in space_reqs {
                let key = ScopeKey {
                    kind: ScopeKind::Space,
                    id,
                };
                if authorized.spaces.contains(&id) {
                    let gen = self.next_grant_gen.fetch_add(1, Ordering::AcqRel);
                    match reg.attach_scope(conn_id, key, raw_id.clone(), gen, None, attach_op_seq) {
                        AttachSlotOutcome::Attached => {
                            result.attached.push(ScopeDescriptor {
                                kind: ScopeKind::Space,
                                raw_id,
                            });
                        }
                        AttachSlotOutcome::DetachedDuringAttach => {
                            result.denied.push(DeniedScope {
                                scope_kind: ScopeKind::Space,
                                scope_id: raw_id,
                                reason: "detached_during_attach",
                            });
                        }
                        AttachSlotOutcome::LimitExceeded | AttachSlotOutcome::ConnectionGone => {
                            result.denied.push(DeniedScope {
                                scope_kind: ScopeKind::Space,
                                scope_id: raw_id,
                                reason: "scope_limit_exceeded",
                            });
                        }
                    }
                } else {
                    result.denied.push(DeniedScope {
                        scope_kind: ScopeKind::Space,
                        scope_id: raw_id,
                        reason: "forbidden",
                    });
                }
            }
        }

        ScopeAttachOutcome {
            result,
            session_revoked: false,
        }
    }

    /// Enumerate and attach a guest connection's authorized Chat channels and
    /// Drive spaces (covering explicit, chat-bound, and meeting-bound spaces
    /// via `drive_user_has_space_access`), capped at `MAX_ATTACHED_SCOPES = 512`.
    pub async fn attach_guest_default_scopes(&self, conn_id: u64) -> ScopeAttachResult {
        let (user_id, is_guest) = {
            let reg = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(conn) = reg.connections.get(&conn_id) else {
                return ScopeAttachResult::default();
            };
            (conn.user_id, conn.is_guest)
        };
        let Ok(actor) = ActorId::new(user_id) else {
            return ScopeAttachResult::default();
        };

        let mut descriptors = Vec::new();
        let limit = MAX_ATTACHED_SCOPES as i64;
        if let Ok(Ok(rows)) = tokio::time::timeout(
            ATTACH_AUTH_DEADLINE,
            self.exec.read_user_scoped(
                actor,
                "SELECT cm.channel_id \
                   FROM public.chat_channel_members cm \
                  WHERE cm.user_id = $1 \
                    AND public.check_user_app_entitlement($1, 'chat') \
                  ORDER BY cm.channel_id \
                  LIMIT $2",
                &[(&user_id, Type::INT8), (&limit, Type::INT8)],
            ),
        )
        .await
        {
            for row in rows {
                if let Ok(ch_id) = row.try_get::<_, i64>(0) {
                    descriptors.push(ScopeDescriptor {
                        kind: ScopeKind::Channel,
                        raw_id: ch_id.to_string(),
                    });
                }
            }
        }

        let remaining = MAX_ATTACHED_SCOPES.saturating_sub(descriptors.len()) as i64;
        if remaining > 0 {
            if let Ok(Ok(rows)) = tokio::time::timeout(
                ATTACH_AUTH_DEADLINE,
                self.exec.read_user_scoped(
                    actor,
                    "SELECT s.id \
                       FROM public.drive_spaces s \
                      WHERE public.check_user_app_entitlement($1, 'drive') \
                        AND public.drive_user_has_space_access($1, s.id) \
                      ORDER BY s.id \
                      LIMIT $2",
                    &[(&user_id, Type::INT8), (&remaining, Type::INT8)],
                ),
            )
            .await
            {
                for row in rows {
                    if let Ok(sp_id) = row.try_get::<_, i64>(0) {
                        descriptors.push(ScopeDescriptor {
                            kind: ScopeKind::Space,
                            raw_id: sp_id.to_string(),
                        });
                    }
                }
            }
        }

        let _ = is_guest;
        if descriptors.is_empty() {
            return ScopeAttachResult::default();
        }
        self.attach_scopes(conn_id, &descriptors).await
    }

    async fn authorize_batched(
        &self,
        actor: ActorId,
        is_guest: bool,
        mailbox_reqs: &[(i64, String)],
        channel_reqs: &[(i64, String)],
        space_reqs: &[(i64, String)],
    ) -> Result<AuthorizedBatch, String> {
        let user_id = actor.get();
        let mut out = AuthorizedBatch::default();

        // Query 1: Mailbox scopes (at most 1 batched query with = ANY($2::bigint[])).
        // Uses `self.worker` (matching `check_live_scope_access`) because Wave 1.8
        // FORCE RLS on `mailboxes` intentionally hides mailbox rows from users who
        // hold only a `calendar_acls` share (not `mailbox_delegates`); `$1 = user_id`
        // binds every ownership/delegate/ACL predicate to the authenticated actor.
        if !mailbox_reqs.is_empty() && !is_guest {
            let ids: Vec<i64> = mailbox_reqs.iter().map(|(id, _)| *id).collect();
            let rows = self
                .worker
                .read(
                    "SELECT m.id, \
                            (m.user_id = $1) AS is_owner, \
                            COALESCE(m.enabled, false) \
                              AND COALESCE(public.mailbox_lifecycle_access_allowed(m.id), true) AS active, \
                            COALESCE(( \
                              SELECT array_agg(DISTINCT md.permission::text) \
                                FROM public.mailbox_delegates md \
                               WHERE md.mailbox_id = m.id \
                                 AND md.user_id = $1 \
                            ), ARRAY[]::text[]) AS delegate_perms, \
                            EXISTS ( \
                              SELECT 1 \
                                FROM public.calendars c \
                                JOIN public.calendar_acls ca ON ca.calendar_id = c.id \
                               WHERE c.mailbox_id = m.id \
                                 AND ca.user_id = $1 \
                                 AND ca.permission <> 'freebusy' \
                            ) AS has_calendar_acl, \
                            public.check_user_app_entitlement($1, 'mail') AS mail_entitled, \
                            public.check_user_app_entitlement($1, 'calendar') AS cal_entitled, \
                            public.check_user_app_entitlement($1, 'contacts') AS contacts_entitled, \
                            public.check_user_app_entitlement($1, 'tasks') AS tasks_entitled \
                       FROM public.mailboxes m \
                      WHERE m.id = ANY($2::bigint[])",
                    &[(&user_id, Type::INT8), (&ids, Type::INT8_ARRAY)],
                )
                .await
                .map_err(|e| e.message)?;

            for row in rows {
                let id: i64 = row.try_get(0).map_err(|e| e.to_string())?;
                let is_owner: bool = row.try_get(1).unwrap_or(false);
                let active: bool = row.try_get(2).unwrap_or(false);
                let perms: Vec<String> = row.try_get(3).unwrap_or_default();
                let has_calendar_acl: bool = row.try_get(4).unwrap_or(false);
                let mail_entitled: bool = row.try_get(5).unwrap_or(false);
                let cal_entitled: bool = row.try_get(6).unwrap_or(false);
                let contacts_entitled: bool = row.try_get(7).unwrap_or(false);
                let tasks_entitled: bool = row.try_get(8).unwrap_or(false);

                if !active {
                    continue;
                }
                if let Some(level) = classify_mailbox_access(
                    is_owner,
                    &perms,
                    has_calendar_acl,
                    mail_entitled,
                    cal_entitled,
                    contacts_entitled,
                    tasks_entitled,
                ) {
                    out.mailboxes.insert(id, level);
                }
            }
        }

        // Query 2: Channel scopes (at most 1 batched query with = ANY($2::bigint[]))
        if !channel_reqs.is_empty() {
            let ids: Vec<i64> = channel_reqs.iter().map(|(id, _)| *id).collect();
            let rows = self
                .exec
                .read_user_scoped(
                    actor,
                    "SELECT cm.channel_id \
                       FROM public.chat_channel_members cm \
                       JOIN public.chat_channels c ON c.id = cm.channel_id \
                      WHERE cm.user_id = $1 \
                        AND cm.channel_id = ANY($2::bigint[]) \
                        AND public.check_user_app_entitlement($1, 'chat') \
                        AND (NOT public.is_guest_account($1) OR EXISTS ( \
                          SELECT 1 FROM public.guest_accounts ga \
                           WHERE ga.user_id = $1 \
                             AND ga.status = 'active' \
                             AND (ga.expires_at IS NULL OR ga.expires_at >= now()) \
                        ))",
                    &[(&user_id, Type::INT8), (&ids, Type::INT8_ARRAY)],
                )
                .await
                .map_err(|e| e.message)?;
            for row in rows {
                if let Ok(ch_id) = row.try_get::<_, i64>(0) {
                    out.channels.insert(ch_id);
                }
            }
        }

        // Query 3: Space scopes (at most 1 batched query with = ANY($2::bigint[]))
        if !space_reqs.is_empty() {
            let ids: Vec<i64> = space_reqs.iter().map(|(id, _)| *id).collect();
            let rows = self
                .exec
                .read_user_scoped(
                    actor,
                    "SELECT s.id \
                       FROM public.drive_spaces s \
                      WHERE s.id = ANY($2::bigint[]) \
                        AND public.check_user_app_entitlement($1, 'drive') \
                        AND public.drive_user_has_space_access($1, s.id)",
                    &[(&user_id, Type::INT8), (&ids, Type::INT8_ARRAY)],
                )
                .await
                .map_err(|e| e.message)?;
            for row in rows {
                if let Ok(sp_id) = row.try_get::<_, i64>(0) {
                    out.spaces.insert(sp_id);
                }
            }
        }

        Ok(out)
    }

    async fn run_listener_loop(
        weak_hub: Weak<Self>,
        listen_hub: ListenHub,
        shutdown: CancellationToken,
    ) {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => return,
            _ = listen_hub.wait_connected() => {}
        }

        let (mut sync_sub, mut revoke_sub, mut drive_sub, mut group_sub, mut ephemeral_sub) = match (
            listen_hub
                .subscribe_with_capacity("sync", SYNC_LISTEN_CAPACITY)
                .await,
            listen_hub
                .subscribe_with_capacity("scope_revoked", SCOPE_REVOKED_LISTEN_CAPACITY)
                .await,
            listen_hub
                .subscribe_with_capacity("drive_access", DRIVE_ACCESS_LISTEN_CAPACITY)
                .await,
            listen_hub
                .subscribe_with_capacity(
                    "group_membership_changed",
                    GROUP_MEMBERSHIP_LISTEN_CAPACITY,
                )
                .await,
            listen_hub
                .subscribe_with_capacity("chat_ephemeral", CHAT_EPHEMERAL_LISTEN_CAPACITY)
                .await,
        ) {
            (Ok(a), Ok(b), Ok(c), Ok(d), Ok(e)) => (a, b, c, d, e),
            _ => return,
        };

        if let Some(hub) = weak_hub.upgrade() {
            if let Ok(rows) = hub
                .worker
                .read(
                    "SELECT COALESCE((SELECT MAX(id) FROM public.scope_revocations), 0)::bigint, \
                            COALESCE((SELECT MAX(cursor) FROM public.drive_access_invalidations), 0)::bigint",
                    &[],
                )
                .await
            {
                if let Some(r) = rows.first() {
                    if let Ok(max_id) = r.try_get::<_, i64>(0) {
                        hub.last_seen_revocation_id
                            .fetch_max(max_id, Ordering::AcqRel);
                    }
                    if let Ok(max_cur) = r.try_get::<_, i64>(1) {
                        hub.last_seen_drive_invalidation_cursor
                            .fetch_max(max_cur, Ordering::AcqRel);
                    }
                }
            }
            hub.ready_flag.store(true, Ordering::Release);
            hub.ready.notify_waiters();
        } else {
            return;
        }

        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                ev = revoke_sub.recv() => {
                    let Some(hub) = weak_hub.upgrade() else { break };
                    match ev {
                        Some(ListenEvent::Notification(notif)) => {
                            hub.handle_scope_revoked_bell(&notif.payload).await;
                        }
                        Some(ListenEvent::ResyncRequired { .. }) => {
                            hub.handle_revocation_resync().await;
                        }
                        None => break,
                    }
                }
                ev = drive_sub.recv() => {
                    let Some(hub) = weak_hub.upgrade() else { break };
                    match ev {
                        Some(ListenEvent::Notification(notif)) => {
                            hub.handle_drive_access_notification(&notif.payload).await;
                        }
                        Some(ListenEvent::ResyncRequired { .. }) => {
                            hub.handle_revocation_resync().await;
                        }
                        None => break,
                    }
                }
                ev = group_sub.recv() => {
                    let Some(hub) = weak_hub.upgrade() else { break };
                    match ev {
                        Some(ListenEvent::Notification(notif)) => {
                            hub.handle_group_membership_notification(&notif.payload).await;
                        }
                        Some(ListenEvent::ResyncRequired { .. }) => {
                            hub.handle_revocation_resync().await;
                        }
                        None => break,
                    }
                }
                ev = sync_sub.recv() => {
                    let Some(hub) = weak_hub.upgrade() else { break };
                    match ev {
                        Some(ListenEvent::Notification(notif)) => {
                            hub.handle_sync_bell(&notif.payload);
                        }
                        Some(ListenEvent::ResyncRequired { .. }) => {
                            hub.handle_sync_resync();
                        }
                        None => break,
                    }
                }
                ev = ephemeral_sub.recv() => {
                    let Some(hub) = weak_hub.upgrade() else { break };
                    match ev {
                        Some(ListenEvent::Notification(notif)) => {
                            hub.handle_chat_ephemeral(&notif.payload);
                        }
                        Some(ListenEvent::ResyncRequired { .. }) => {}
                        None => break,
                    }
                }
            }
        }
        // Explicitly drop all subscriptions on shutdown.
        drop((sync_sub, revoke_sub, drive_sub, group_sub, ephemeral_sub));
    }

    fn handle_sync_bell(&self, payload: &str) {
        let Some(bell) = parse_sync_bell(payload) else {
            return;
        };
        let reg = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(conn_ids) = reg.scope_index.get(&bell.key) else {
            return;
        };
        for conn_id in conn_ids {
            let Some(conn) = reg.connections.get(conn_id) else {
                continue;
            };
            let Some(attached) = conn.scopes.get(&bell.key) else {
                continue;
            };
            if bell.key.kind == ScopeKind::Mailbox {
                let allowed = attached
                    .mailbox_types
                    .unwrap_or(MailboxDataTypes::ALL)
                    .filter(&bell.data_types);
                if allowed.is_empty() {
                    continue;
                }
                conn.wakeups.push(bell.key, &attached.alias, 0, &allowed);
            } else {
                conn.wakeups
                    .push(bell.key, &attached.alias, bell.seq, &bell.data_types);
            }
        }
    }

    fn handle_chat_ephemeral(&self, payload: &str) {
        let Ok(val) = serde_json::from_str::<Value>(payload) else {
            return;
        };
        let Some(channel_id) = val.get("channelId").and_then(Value::as_i64) else {
            return;
        };
        if channel_id <= 0 {
            return;
        }
        let compact = super::reply::go_compact(payload).unwrap_or_else(|| payload.to_owned());
        let key = ScopeKey {
            kind: ScopeKind::Channel,
            id: channel_id,
        };
        let reg = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(conn_ids) = reg.scope_index.get(&key) else {
            return;
        };
        for conn_id in conn_ids {
            if let Some(conn) = reg.connections.get(conn_id) {
                let _ = conn.ephemeral_tx.try_send(compact.clone());
            }
        }
    }

    fn handle_sync_resync(&self) {
        let targets: Vec<(
            mpsc::Sender<ControlMessage>,
            Arc<dyn Fn(&'static str) + Send + Sync>,
        )> = {
            let reg = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            reg.connections
                .values()
                .filter(|c| !c.scopes.is_empty())
                .map(|c| (c.control_tx.clone(), c.restart_close.clone()))
                .collect()
        };
        for (tx, restart) in targets {
            send_control_or_restart(
                &tx,
                &restart,
                ControlMessage::Restart("sync resync required"),
            );
        }
    }

    async fn handle_scope_revoked_bell(&self, payload: &str) {
        let Ok(rev_id) = payload.trim().parse::<i64>() else {
            return;
        };
        if rev_id <= 0 {
            return;
        }
        self.revocation_signal_epoch.fetch_add(1, Ordering::AcqRel);
        let rows = match self
            .worker
            .read(
                "SELECT id, user_id, scope_kind, scope_id, subtree_anchor_id, reason \
                   FROM public.scope_revocations \
                  WHERE id = $1",
                &[(&rev_id, Type::INT8)],
            )
            .await
        {
            Ok(rows) => rows,
            Err(_) => {
                self.fail_closed_all_connections("scope revocation lookup unavailable");
                return;
            }
        };
        for row in rows {
            let id: i64 = match row.try_get(0) {
                Ok(v) => v,
                Err(_) => continue,
            };
            self.last_seen_revocation_id.fetch_max(id, Ordering::AcqRel);
            let target_user: Option<i64> = row.try_get(1).ok().flatten();
            let scope_kind_str: String = match row.try_get(2) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let Some(scope_kind) = ScopeKind::parse(&scope_kind_str) else {
                continue;
            };
            let scope_id: i64 = match row.try_get(3) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let subtree_anchor_id: Option<i64> = row.try_get(4).ok().flatten();
            let reason: String = row.try_get(5).unwrap_or_default();

            self.apply_revocation_row(
                target_user,
                ScopeKey {
                    kind: scope_kind,
                    id: scope_id,
                },
                subtree_anchor_id,
                reason,
            )
            .await;
        }
    }

    async fn apply_revocation_row(
        &self,
        target_user: Option<i64>,
        key: ScopeKey,
        subtree_anchor_id: Option<i64>,
        reason: String,
    ) {
        let candidates: Vec<(u64, i64, bool, String, u64)> = {
            let reg = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(conn_ids) = reg.scope_index.get(&key) else {
                return;
            };
            conn_ids
                .iter()
                .filter_map(|cid| {
                    let conn = reg.connections.get(cid)?;
                    if let Some(uid) = target_user {
                        if conn.user_id != uid {
                            return None;
                        }
                    }
                    let attached = conn.scopes.get(&key)?;
                    Some((
                        *cid,
                        conn.user_id,
                        conn.is_guest,
                        attached.alias.clone(),
                        attached.grant_generation,
                    ))
                })
                .collect()
        };

        for (conn_id, user_id, is_guest, alias, gen) in candidates {
            if let Some(anchor) = subtree_anchor_id {
                let still_has_access = self.check_live_scope_access(user_id, is_guest, key).await;
                match still_has_access {
                    Ok(LiveAccess::Allowed(_)) => {
                        self.send_control_for_conn(
                            conn_id,
                            ControlMessage::ScopeRevoked(ScopeRevokedWire {
                                scope_kind: key.kind,
                                scope_id: alias,
                                subtree_anchor_id: Some(anchor.to_string()),
                                reason: (!reason.is_empty()).then_some(reason.clone()),
                            }),
                        );
                    }
                    Ok(LiveAccess::Denied) => {
                        self.detach_if_generation_matches(
                            conn_id,
                            key,
                            gen,
                            None,
                            (!reason.is_empty()).then_some(reason.clone()),
                        );
                    }
                    Err(_) => {
                        self.restart_connection(conn_id, "revocation verification unavailable");
                    }
                }
            } else {
                self.reverify_single_connection_scope(
                    conn_id,
                    user_id,
                    is_guest,
                    key,
                    gen,
                    (!reason.is_empty()).then_some(reason.clone()),
                )
                .await;
            }
        }
    }

    async fn handle_drive_access_notification(&self, payload: &str) {
        let Ok(val) = serde_json::from_str::<Value>(payload) else {
            return;
        };
        let cursor = val.get("cursor").and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        });
        let Some(cursor) = cursor else {
            return;
        };
        self.last_seen_drive_invalidation_cursor
            .fetch_max(cursor, Ordering::AcqRel);
        let rows = match self
            .worker
            .read(
                "SELECT space_id, principal_kind, principal_id, anchor_node_id, reason \
                   FROM public.drive_access_invalidations \
                  WHERE cursor = $1",
                &[(&cursor, Type::INT8)],
            )
            .await
        {
            Ok(rows) => rows,
            Err(_) => {
                self.handle_revocation_resync().await;
                return;
            }
        };
        for row in rows {
            let space_id: i64 = match row.try_get(0) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let principal_kind: String = row.try_get(1).unwrap_or_default();
            let principal_id: Option<i64> = row.try_get(2).ok().flatten();
            let anchor_node_id: Option<i64> = row.try_get(3).ok().flatten();
            let reason: String = row.try_get(4).unwrap_or_default();

            // Pure grants & tree moves MUST NOT detach or purge the space!
            if is_non_revoking_drive_reason(&reason) {
                continue;
            }
            self.revocation_signal_epoch.fetch_add(1, Ordering::AcqRel);

            let target_user = if principal_kind == "user" {
                principal_id
            } else {
                None
            };
            self.apply_revocation_row(
                target_user,
                ScopeKey {
                    kind: ScopeKind::Space,
                    id: space_id,
                },
                anchor_node_id,
                reason,
            )
            .await;
        }
    }

    async fn handle_group_membership_notification(&self, payload: &str) {
        self.revocation_signal_epoch.fetch_add(1, Ordering::AcqRel);
        let Ok(val) = serde_json::from_str::<Value>(payload) else {
            return;
        };
        let all = val.get("all").and_then(Value::as_bool).unwrap_or(false);
        let user_id = val.get("user_id").and_then(Value::as_i64);

        let targets: Vec<(u64, i64, bool, ScopeKey, u64)> = {
            let reg = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let conn_ids: Vec<u64> = if all || user_id.is_none() {
                reg.connections.keys().copied().collect()
            } else if let Some(uid) = user_id {
                reg.user_index
                    .get(&uid)
                    .map(|s| s.iter().copied().collect())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            let mut out = Vec::new();
            for cid in conn_ids {
                if let Some(conn) = reg.connections.get(&cid) {
                    for (key, attached) in &conn.scopes {
                        if key.kind == ScopeKind::Space {
                            out.push((
                                cid,
                                conn.user_id,
                                conn.is_guest,
                                *key,
                                attached.grant_generation,
                            ));
                        }
                    }
                }
            }
            out
        };

        for (cid, uid, is_guest, key, gen) in targets {
            self.reverify_single_connection_scope(
                cid,
                uid,
                is_guest,
                key,
                gen,
                Some("group_membership_changed".to_owned()),
            )
            .await;
        }
    }

    /// Public trigger used both by `ListenEvent::ResyncRequired` and by tests
    /// simulating a `ListenHub` overflow / reconnect.
    pub async fn handle_revocation_resync(&self) {
        self.revocation_signal_epoch.fetch_add(1, Ordering::AcqRel);

        // 1. Replay every durable scope_revocations row with a safe lookback
        //    window so out-of-order SKIP LOCKED IDs committed below
        //    last_seen_revocation_id are never missed (bounded 1000-row pages).
        let mut cursor = self
            .last_seen_revocation_id
            .load(Ordering::Acquire)
            .saturating_sub(1000);
        loop {
            let rows = match self
                .worker
                .read(
                    "SELECT id, user_id, scope_kind, scope_id, subtree_anchor_id, reason \
                       FROM public.scope_revocations \
                      WHERE id > $1 \
                      ORDER BY id ASC \
                      LIMIT 1000",
                    &[(&cursor, Type::INT8)],
                )
                .await
            {
                Ok(rows) => rows,
                Err(_) => {
                    self.fail_closed_all_connections("revocation resync failed");
                    return;
                }
            };
            if rows.is_empty() {
                break;
            }
            let batch_len = rows.len();
            for row in rows {
                let Ok(id) = row.try_get::<_, i64>(0) else {
                    continue;
                };
                cursor = cursor.max(id);
                self.last_seen_revocation_id.fetch_max(id, Ordering::AcqRel);
                let target_user: Option<i64> = row.try_get(1).ok().flatten();
                let Ok(scope_kind_str) = row.try_get::<_, String>(2) else {
                    continue;
                };
                let Some(scope_kind) = ScopeKind::parse(&scope_kind_str) else {
                    continue;
                };
                let Ok(scope_id) = row.try_get::<_, i64>(3) else {
                    continue;
                };
                let subtree_anchor_id: Option<i64> = row.try_get(4).ok().flatten();
                let reason: String = row.try_get(5).unwrap_or_default();
                self.apply_revocation_row(
                    target_user,
                    ScopeKey {
                        kind: scope_kind,
                        id: scope_id,
                    },
                    subtree_anchor_id,
                    reason,
                )
                .await;
            }
            if batch_len < 1000 {
                break;
            }
        }

        // 2. Replay revoking drive_access_invalidations rows (including subtree
        //    anchor invalidations where the user retains space access!) with
        //    BOTH a cursor lookback window AND a 15-minute `created_at` fallback
        //    (backed by `drive_access_invalidations_created_idx`), deduplicated
        //    by `cursor`, so delayed out-of-order transactions whose `cursor`
        //    was allocated >1,000 IDs earlier can never be missed on overflow.
        let drive_cursor_floor = self
            .last_seen_drive_invalidation_cursor
            .load(Ordering::Acquire)
            .saturating_sub(1000);
        let mut drive_page_after: i64 = 0;
        let mut seen_drive_cursors: HashSet<i64> = HashSet::new();
        loop {
            let rows = match self
                .worker
                .read(
                    "SELECT cursor, space_id, principal_kind, principal_id, anchor_node_id, reason \
                       FROM public.drive_access_invalidations \
                      WHERE cursor > $2 \
                        AND (cursor > $1 OR created_at >= now() - interval '15 minutes') \
                        AND reason NOT IN ( \
                            'member_grant', 'grant', 'folder_admin_grant', \
                            'inheritance_resume', 'tree_move' \
                        ) \
                      ORDER BY cursor ASC \
                      LIMIT 1000",
                    &[(&drive_cursor_floor, Type::INT8), (&drive_page_after, Type::INT8)],
                )
                .await
            {
                Ok(rows) => rows,
                Err(_) => {
                    self.fail_closed_all_connections("drive revocation resync failed");
                    return;
                }
            };
            if rows.is_empty() {
                break;
            }
            let batch_len = rows.len();
            for row in rows {
                let Ok(cur) = row.try_get::<_, i64>(0) else {
                    continue;
                };
                drive_page_after = drive_page_after.max(cur);
                if !seen_drive_cursors.insert(cur) {
                    continue;
                }
                self.last_seen_drive_invalidation_cursor
                    .fetch_max(cur, Ordering::AcqRel);
                let Ok(space_id) = row.try_get::<_, i64>(1) else {
                    continue;
                };
                let principal_kind: String = row.try_get(2).unwrap_or_default();
                let principal_id: Option<i64> = row.try_get(3).ok().flatten();
                let anchor_node_id: Option<i64> = row.try_get(4).ok().flatten();
                let reason: String = row.try_get(5).unwrap_or_default();
                let target_user = if principal_kind == "user" {
                    principal_id
                } else {
                    None
                };
                self.apply_revocation_row(
                    target_user,
                    ScopeKey {
                        kind: ScopeKind::Space,
                        id: space_id,
                    },
                    anchor_node_id,
                    reason,
                )
                .await;
            }
            if batch_len < 1000 {
                break;
            }
        }

        // 3. Re-verify EVERY attached scope across all live connections on this
        //    replica (catches group/ACL/lifecycle changes that didn't emit a
        //    scope_revocations row or overflowed drive_access/group_membership).
        let all_attached: Vec<(u64, i64, bool, ScopeKey, u64)> = {
            let reg = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut out = Vec::new();
            for (&cid, conn) in &reg.connections {
                for (&key, attached) in &conn.scopes {
                    out.push((
                        cid,
                        conn.user_id,
                        conn.is_guest,
                        key,
                        attached.grant_generation,
                    ));
                }
            }
            out
        };

        for (cid, uid, is_guest, key, gen) in all_attached {
            let _ = self
                .reverify_single_connection_scope(
                    cid,
                    uid,
                    is_guest,
                    key,
                    gen,
                    Some("resync_revoked".to_owned()),
                )
                .await;
        }
    }

    async fn reverify_single_connection_scope(
        &self,
        conn_id: u64,
        user_id: i64,
        is_guest: bool,
        key: ScopeKey,
        expected_gen: u64,
        reason: Option<String>,
    ) -> bool {
        match self.check_live_scope_access(user_id, is_guest, key).await {
            Ok(LiveAccess::Allowed(new_mb_types)) => {
                if let Some(new_types) = new_mb_types {
                    let narrowed_notify = {
                        let mut reg = self
                            .registry
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if let Some(conn) = reg.connections.get_mut(&conn_id) {
                            if let Some(attached) = conn.scopes.get_mut(&key) {
                                if attached.grant_generation == expected_gen {
                                    let prev_types =
                                        attached.mailbox_types.unwrap_or(MailboxDataTypes::ALL);
                                    let is_narrowed = new_types.narrowed_from(prev_types);
                                    let is_partial_cal_revoke =
                                        reason.as_deref() == Some("calendar_share_revoked");
                                    attached.mailbox_types = Some(new_types);
                                    if is_narrowed {
                                        conn.wakeups.retain_data_types(key, new_types);
                                    }
                                    if is_partial_cal_revoke {
                                        conn.wakeups.remove_calendar_data_types(key);
                                    }
                                    if is_narrowed || is_partial_cal_revoke {
                                        Some((
                                            conn.control_tx.clone(),
                                            conn.restart_close.clone(),
                                            attached.alias.clone(),
                                        ))
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    };
                    if let Some((tx, restart, alias)) = narrowed_notify {
                        send_control_or_restart(
                            &tx,
                            &restart,
                            ControlMessage::ScopeRevoked(ScopeRevokedWire {
                                scope_kind: key.kind,
                                scope_id: alias,
                                subtree_anchor_id: None,
                                reason: reason.or_else(|| Some("scope_narrowed".to_owned())),
                            }),
                        );
                    }
                }
                false
            }
            Ok(LiveAccess::Denied) => {
                self.detach_if_generation_matches(conn_id, key, expected_gen, None, reason);
                true
            }
            Err(_) => {
                self.restart_connection(conn_id, "revocation verification failed");
                true
            }
        }
    }

    async fn check_live_scope_access(
        &self,
        user_id: i64,
        is_guest: bool,
        key: ScopeKey,
    ) -> Result<LiveAccess, String> {
        match key.kind {
            ScopeKind::Mailbox => {
                if is_guest {
                    return Ok(LiveAccess::Denied);
                }
                let rows = self
                    .worker
                    .read(
                        "SELECT (m.user_id = $1) AS is_owner, \
                                COALESCE(m.enabled, false) \
                                  AND COALESCE(public.mailbox_lifecycle_access_allowed(m.id), true) AS active, \
                                COALESCE(( \
                                  SELECT array_agg(DISTINCT md.permission::text) \
                                    FROM public.mailbox_delegates md \
                                   WHERE md.mailbox_id = m.id \
                                     AND md.user_id = $1 \
                                ), ARRAY[]::text[]) AS delegate_perms, \
                                EXISTS ( \
                                  SELECT 1 \
                                    FROM public.calendars c \
                                    JOIN public.calendar_acls ca ON ca.calendar_id = c.id \
                                   WHERE c.mailbox_id = m.id \
                                     AND ca.user_id = $1 \
                                     AND ca.permission <> 'freebusy' \
                                ) AS has_calendar_acl, \
                                public.check_user_app_entitlement($1, 'mail') AS mail_entitled, \
                                public.check_user_app_entitlement($1, 'calendar') AS cal_entitled, \
                                public.check_user_app_entitlement($1, 'contacts') AS contacts_entitled, \
                                public.check_user_app_entitlement($1, 'tasks') AS tasks_entitled \
                           FROM public.mailboxes m \
                          WHERE m.id = $2",
                        &[(&user_id, Type::INT8), (&key.id, Type::INT8)],
                    )
                    .await
                    .map_err(|e| e.message)?;
                let Some(row) = rows.first() else {
                    return Ok(LiveAccess::Denied);
                };
                let is_owner: bool = row.try_get(0).unwrap_or(false);
                let active: bool = row.try_get(1).unwrap_or(false);
                let perms: Vec<String> = row.try_get(2).unwrap_or_default();
                let has_calendar_acl: bool = row.try_get(3).unwrap_or(false);
                let mail_entitled: bool = row.try_get(4).unwrap_or(false);
                let cal_entitled: bool = row.try_get(5).unwrap_or(false);
                let contacts_entitled: bool = row.try_get(6).unwrap_or(false);
                let tasks_entitled: bool = row.try_get(7).unwrap_or(false);
                if !active {
                    return Ok(LiveAccess::Denied);
                }
                match classify_mailbox_access(
                    is_owner,
                    &perms,
                    has_calendar_acl,
                    mail_entitled,
                    cal_entitled,
                    contacts_entitled,
                    tasks_entitled,
                ) {
                    Some(level) => Ok(LiveAccess::Allowed(Some(level))),
                    None => Ok(LiveAccess::Denied),
                }
            }
            ScopeKind::Channel => {
                let rows = self
                    .worker
                    .read(
                        "SELECT EXISTS ( \
                           SELECT 1 \
                             FROM public.chat_channel_members cm \
                            WHERE cm.channel_id = $2 \
                              AND cm.user_id = $1 \
                         ) AND public.check_user_app_entitlement($1, 'chat') \
                           AND (NOT public.is_guest_account($1) OR EXISTS ( \
                             SELECT 1 FROM public.guest_accounts ga \
                              WHERE ga.user_id = $1 \
                                AND ga.status = 'active' \
                                AND (ga.expires_at IS NULL OR ga.expires_at >= now()) \
                           ))",
                        &[(&user_id, Type::INT8), (&key.id, Type::INT8)],
                    )
                    .await
                    .map_err(|e| e.message)?;
                let allowed = rows
                    .first()
                    .and_then(|r| r.try_get::<_, bool>(0).ok())
                    .unwrap_or(false);
                Ok(if allowed {
                    LiveAccess::Allowed(None)
                } else {
                    LiveAccess::Denied
                })
            }
            ScopeKind::Space => {
                let rows = self
                    .worker
                    .read(
                        "SELECT public.check_user_app_entitlement($1, 'drive') \
                            AND public.drive_user_has_space_access($1, $2)",
                        &[(&user_id, Type::INT8), (&key.id, Type::INT8)],
                    )
                    .await
                    .map_err(|e| e.message)?;
                let allowed = rows
                    .first()
                    .and_then(|r| r.try_get::<_, bool>(0).ok())
                    .unwrap_or(false);
                Ok(if allowed {
                    LiveAccess::Allowed(None)
                } else {
                    LiveAccess::Denied
                })
            }
        }
    }

    fn detach_if_generation_matches(
        &self,
        conn_id: u64,
        key: ScopeKey,
        expected_gen: u64,
        subtree_anchor_id: Option<String>,
        reason: Option<String>,
    ) {
        let delivery = {
            let mut reg = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let matches = reg
                .connections
                .get(&conn_id)
                .and_then(|c| c.scopes.get(&key))
                .is_some_and(|a| a.grant_generation == expected_gen);
            if !matches {
                return;
            }
            let Some(removed) = reg.detach_scope(conn_id, key) else {
                return;
            };
            let Some(conn) = reg.connections.get(&conn_id) else {
                return;
            };
            (
                conn.control_tx.clone(),
                conn.restart_close.clone(),
                removed.alias,
            )
        };
        let (tx, restart, alias) = delivery;
        send_control_or_restart(
            &tx,
            &restart,
            ControlMessage::ScopeRevoked(ScopeRevokedWire {
                scope_kind: key.kind,
                scope_id: alias,
                subtree_anchor_id,
                reason,
            }),
        );
    }

    fn send_control_for_conn(&self, conn_id: u64, msg: ControlMessage) {
        let target = {
            let reg = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            reg.connections
                .get(&conn_id)
                .map(|c| (c.control_tx.clone(), c.restart_close.clone()))
        };
        if let Some((tx, restart)) = target {
            send_control_or_restart(&tx, &restart, msg);
        }
    }

    fn restart_connection(&self, conn_id: u64, reason: &'static str) {
        let target = {
            let reg = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            reg.connections
                .get(&conn_id)
                .map(|c| (c.control_tx.clone(), c.restart_close.clone()))
        };
        if let Some((tx, restart)) = target {
            send_control_or_restart(&tx, &restart, ControlMessage::Restart(reason));
        }
    }

    fn fail_closed_all_connections(&self, reason: &'static str) {
        let targets: Vec<(
            mpsc::Sender<ControlMessage>,
            Arc<dyn Fn(&'static str) + Send + Sync>,
        )> = {
            let reg = self
                .registry
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            reg.connections
                .values()
                .map(|c| (c.control_tx.clone(), c.restart_close.clone()))
                .collect()
        };
        for (tx, restart) in targets {
            send_control_or_restart(&tx, &restart, ControlMessage::Restart(reason));
        }
    }
}

enum AttachSlotOutcome {
    Attached,
    DetachedDuringAttach,
    LimitExceeded,
    ConnectionGone,
}

#[derive(Default)]
struct AuthorizedBatch {
    mailboxes: HashMap<i64, MailboxDataTypes>,
    channels: HashSet<i64>,
    spaces: HashSet<i64>,
}

enum LiveAccess {
    Allowed(Option<MailboxDataTypes>),
    Denied,
}

fn send_control_or_restart(
    tx: &mpsc::Sender<ControlMessage>,
    restart: &Arc<dyn Fn(&'static str) + Send + Sync>,
    msg: ControlMessage,
) {
    match tx.try_send(msg) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            restart("control rail overflow");
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {}
    }
}

fn classify_mailbox_access(
    is_owner: bool,
    delegate_perms: &[String],
    has_calendar_acl: bool,
    mail_entitled: bool,
    cal_entitled: bool,
    contacts_entitled: bool,
    tasks_entitled: bool,
) -> Option<MailboxDataTypes> {
    let has_full_mail_delegate = delegate_perms
        .iter()
        .any(|p| matches!(p.as_str(), "read" | "full_access"));
    let has_manage_calendar = delegate_perms.iter().any(|p| p == "manage_calendar");

    if is_owner || has_full_mail_delegate {
        let allowed = MailboxDataTypes {
            mail: mail_entitled,
            calendar: cal_entitled,
            contacts: contacts_entitled,
            tasks: tasks_entitled,
        };
        return (!allowed.is_empty()).then_some(allowed);
    }
    if (has_manage_calendar || has_calendar_acl) && cal_entitled {
        return Some(MailboxDataTypes::CALENDAR_ONLY);
    }
    None
}

fn is_non_revoking_drive_reason(reason: &str) -> bool {
    matches!(
        reason,
        "member_grant" | "grant" | "folder_admin_grant" | "inheritance_resume" | "tree_move"
    )
}

fn is_valid_scope_id_wire(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= MAX_SCOPE_ID_LENGTH
        && !matches!(raw, "__proto__" | "constructor" | "prototype")
        && !raw.contains("..")
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:@/-".contains(&b))
}

fn parse_positive_scope_id(raw: &str) -> Option<i64> {
    raw.parse::<i64>().ok().filter(|&v| v > 0)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedSyncBell {
    key: ScopeKey,
    seq: i64,
    data_types: Vec<String>,
}

fn parse_sync_bell(payload: &str) -> Option<ParsedSyncBell> {
    let mut parts = payload.split(':');
    let kind_str = parts.next()?;
    let id_str = parts.next()?;
    let seq_str = parts.next()?;
    let kind = ScopeKind::parse(kind_str)?;
    let id = parse_positive_scope_id(id_str)?;
    let seq = seq_str.parse::<i64>().ok().filter(|&v| v >= 0)?;

    let data_types = match kind {
        ScopeKind::Mailbox => {
            let dt = parts.next()?;
            if parts.next().is_some() || dt.is_empty() || dt.len() > 64 {
                return None;
            }
            expand_mailbox_data_type(dt)
        }
        ScopeKind::Space | ScopeKind::Channel => {
            if parts.next().is_some() {
                return None;
            }
            Vec::new()
        }
    };

    Some(ParsedSyncBell {
        key: ScopeKey { kind, id },
        seq: if kind == ScopeKind::Mailbox { 0 } else { seq },
        data_types,
    })
}

fn expand_mailbox_data_type(dt: &str) -> Vec<String> {
    match dt {
        "Email" => vec!["Email".into(), "Mailbox".into(), "Thread".into()],
        "Calendar" => vec!["Calendar".into(), "CalendarEvent".into()],
        other => vec![other.to_owned()],
    }
}

/// Format a `ScopeAttachResponse` JSON envelope.
pub fn format_scope_attach_response(request_id: &str, res: &ScopeAttachResult) -> String {
    let attached: Vec<Value> = res
        .attached
        .iter()
        .map(|s| json!({"scopeKind": s.kind.as_str(), "scopeId": s.raw_id}))
        .collect();
    let denied: Vec<Value> = res
        .denied
        .iter()
        .map(|d| json!({"scopeKind": d.scope_kind.as_str(), "scopeId": d.scope_id, "reason": d.reason}))
        .collect();
    let mut obj = serde_json::Map::new();
    obj.insert("@type".into(), json!("ScopeAttachResponse"));
    if !request_id.is_empty() {
        obj.insert("requestId".into(), json!(request_id));
    }
    obj.insert("attached".into(), Value::Array(attached));
    obj.insert("denied".into(), Value::Array(denied));
    Value::Object(obj).to_string()
}

/// Format a `ScopeDetachResponse` JSON envelope.
pub fn format_scope_detach_response(request_id: &str, detached: &[ScopeDescriptor]) -> String {
    let list: Vec<Value> = detached
        .iter()
        .map(|s| json!({"scopeKind": s.kind.as_str(), "scopeId": s.raw_id}))
        .collect();
    let mut obj = serde_json::Map::new();
    obj.insert("@type".into(), json!("ScopeDetachResponse"));
    if !request_id.is_empty() {
        obj.insert("requestId".into(), json!(request_id));
    }
    obj.insert("detached".into(), Value::Array(list));
    Value::Object(obj).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn parses_sync_bells_for_all_scope_kinds() {
        let mail = parse_sync_bell("mailbox:42:0:Email").unwrap();
        assert_eq!(
            mail.key,
            ScopeKey {
                kind: ScopeKind::Mailbox,
                id: 42
            }
        );
        assert_eq!(mail.seq, 0);
        assert_eq!(mail.data_types, vec!["Email", "Mailbox", "Thread"]);

        let cal = parse_sync_bell("mailbox:42:99:Calendar").unwrap();
        assert_eq!(cal.seq, 0, "mailbox scopes always clamp seq to 0");
        assert_eq!(cal.data_types, vec!["Calendar", "CalendarEvent"]);

        let space = parse_sync_bell("space:77:15").unwrap();
        assert_eq!(
            space.key,
            ScopeKey {
                kind: ScopeKind::Space,
                id: 77
            }
        );
        assert_eq!(space.seq, 15);
        assert!(space.data_types.is_empty());

        let chan = parse_sync_bell("channel:99:123").unwrap();
        assert_eq!(
            chan.key,
            ScopeKey {
                kind: ScopeKind::Channel,
                id: 99
            }
        );
        assert_eq!(chan.seq, 123);

        assert!(parse_sync_bell("mailbox:0:0:Email").is_none());
        assert!(parse_sync_bell("mailbox:42:0").is_none());
        assert!(parse_sync_bell("space:42:-1").is_none());
        assert!(parse_sync_bell("unknown:1:0").is_none());
    }

    #[test]
    fn coalesces_wakeups_and_caps_data_types() {
        let mb = WakeupMailbox::new();
        let mb_key = ScopeKey {
            kind: ScopeKind::Mailbox,
            id: 10,
        };
        mb.push(mb_key, "primary", 5, &["Email".into(), "Mailbox".into()]);
        mb.push(mb_key, "primary", 99, &["Calendar".into(), "Email".into()]);
        let ch_key = ScopeKey {
            kind: ScopeKind::Channel,
            id: 20,
        };
        mb.push(ch_key, "20", 12, &[]);
        mb.push(ch_key, "20", 7, &[]);
        mb.push(ch_key, "20", 25, &[]);

        let out = mb.take_all();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].scope_id, "primary");
        assert_eq!(out[0].seq, 0);
        assert_eq!(out[0].data_types, vec!["Email", "Mailbox", "Calendar"]);
        assert_eq!(out[1].scope_id, "20");
        assert_eq!(out[1].seq, 25);

        // Verify dataTypes cap at 64.
        let many: Vec<String> = (0..100).map(|i| format!("Type{i}")).collect();
        mb.push(mb_key, "primary", 0, &many);
        let capped = mb.take_all();
        assert_eq!(capped[0].data_types.len(), MAX_WAKEUP_DATA_TYPES);
    }

    #[test]
    fn mailbox_access_classification_enforces_granular_permissions() {
        assert_eq!(
            classify_mailbox_access(true, &[], false, true, true, true, true),
            Some(MailboxDataTypes::ALL)
        );
        assert_eq!(
            classify_mailbox_access(false, &["read".into()], false, true, true, true, true),
            Some(MailboxDataTypes::ALL)
        );
        assert_eq!(
            classify_mailbox_access(false, &["read".into()], false, true, false, false, false),
            Some(MailboxDataTypes {
                mail: true,
                calendar: false,
                contacts: false,
                tasks: false,
            })
        );
        assert_eq!(
            classify_mailbox_access(
                false,
                &["manage_calendar".into()],
                false,
                true,
                true,
                true,
                true
            ),
            Some(MailboxDataTypes::CALENDAR_ONLY)
        );
        assert_eq!(
            classify_mailbox_access(false, &[], true, true, true, true, true),
            Some(MailboxDataTypes::CALENDAR_ONLY)
        );
        // send_as / send_on_behalf ONLY -> DENIED
        assert_eq!(
            classify_mailbox_access(false, &["send_as".into()], false, true, true, true, true),
            None
        );
        assert_eq!(
            classify_mailbox_access(
                false,
                &["send_on_behalf".into()],
                false,
                true,
                true,
                true,
                true
            ),
            None
        );
        assert_eq!(
            MailboxDataTypes::CALENDAR_ONLY.filter(&["Email".into(), "Calendar".into()]),
            vec!["Calendar"]
        );
        assert!(MailboxDataTypes::CALENDAR_ONLY.narrowed_from(MailboxDataTypes::ALL));
        assert!(!MailboxDataTypes::ALL.narrowed_from(MailboxDataTypes::CALENDAR_ONLY));
    }

    #[test]
    fn wire_frames_always_emit_string_ids() {
        let rev = ScopeRevokedWire {
            scope_kind: ScopeKind::Space,
            scope_id: "42".into(),
            subtree_anchor_id: Some("99".into()),
            reason: Some("revoke".into()),
        };
        let ws: Value = serde_json::from_str(rev.to_ws_frame().trim()).unwrap();
        assert_eq!(ws["@type"], "ScopeRevoked");
        assert!(ws["event"]["scopeId"].is_string());
        assert!(ws["event"]["subtreeAnchorId"].is_string());
        assert_eq!(ws["event"]["scopeId"], "42");
        assert_eq!(ws["event"]["subtreeAnchorId"], "99");
    }

    #[test]
    fn control_rail_overflow_invokes_restart_never_drops() {
        let (tx, _rx) = mpsc::channel(1);
        let restarted = Arc::new(AtomicBool::new(false));
        let flag = restarted.clone();
        let restart: Arc<dyn Fn(&'static str) + Send + Sync> = Arc::new(move |_| {
            flag.store(true, Ordering::SeqCst);
        });
        send_control_or_restart(&tx, &restart, ControlMessage::SessionRevoked);
        assert!(!restarted.load(Ordering::SeqCst));
        send_control_or_restart(&tx, &restart, ControlMessage::SessionRevoked);
        assert!(
            restarted.load(Ordering::SeqCst),
            "control rail overflow must trigger clean restart, never silent drop"
        );
    }

    #[test]
    fn coalescing_chat_seq_zero_preserves_zero() {
        let mb = WakeupMailbox::new();
        let ch_key = ScopeKey {
            kind: ScopeKind::Channel,
            id: 42,
        };
        // Positive seq followed by non-seq-advancing event (seq = 0) -> seq = 0
        mb.push(ch_key, "42", 10, &[]);
        mb.push(ch_key, "42", 0, &[]);
        let out1 = mb.take_all();
        assert_eq!(out1.len(), 1);
        assert_eq!(
            out1[0].seq, 0,
            "coalescing (channel, seq=10) then (channel, seq=0) must yield seq=0"
        );

        // Non-seq-advancing event (seq = 0) followed by positive seq -> seq = 0
        mb.push(ch_key, "42", 0, &[]);
        mb.push(ch_key, "42", 10, &[]);
        let out2 = mb.take_all();
        assert_eq!(out2.len(), 1);
        assert_eq!(
            out2[0].seq, 0,
            "coalescing (channel, seq=0) then (channel, seq=10) must preserve seq=0"
        );
    }

    #[test]
    fn detached_at_pruning_never_evicts_markers_newer_than_active_attach() {
        let (control_tx, _control_rx) = mpsc::channel(1);
        let (ephemeral_tx, _ephemeral_rx) = mpsc::channel(1);
        let restart_close: Arc<dyn Fn(&'static str) + Send + Sync> = Arc::new(|_| {});
        let mut conn = ConnEntry {
            user_id: 1,
            primary_mailbox: None,
            is_guest: false,
            scopes: HashMap::new(),
            op_seq: 0,
            active_attach_ops: BTreeSet::new(),
            detached_at: HashMap::new(),
            control_tx,
            wakeups: Arc::new(WakeupMailbox::new()),
            ephemeral_tx,
            restart_close,
        };
        let active_attach_seq = 5000_u64;
        conn.active_attach_ops.insert(active_attach_seq);

        // Fill with old markers (<= active_attach_seq) and one live marker (> active_attach_seq)
        for i in 1..=(MAX_ATTACHED_SCOPES * 4) as i64 {
            conn.detached_at.insert(
                ScopeKey {
                    kind: ScopeKind::Channel,
                    id: i,
                },
                i as u64,
            );
        }
        let live_key = ScopeKey {
            kind: ScopeKind::Channel,
            id: 999_999,
        };
        conn.detached_at.insert(live_key, active_attach_seq + 1);

        conn.prune_stale_detached_markers();
        assert_eq!(
            conn.detached_at.get(&live_key),
            Some(&(active_attach_seq + 1)),
            "markers newer than the smallest active attach op must never be pruned"
        );
        assert_eq!(conn.detached_at.len(), 1);

        // Once all active attach ops complete, pruning may clear all markers at capacity.
        conn.active_attach_ops.remove(&active_attach_seq);
        for i in 1..=(MAX_ATTACHED_SCOPES * 4) as i64 {
            conn.detached_at.insert(
                ScopeKey {
                    kind: ScopeKind::Channel,
                    id: i,
                },
                i as u64,
            );
        }
        conn.prune_stale_detached_markers();
        assert!(conn.detached_at.is_empty());
    }
}
