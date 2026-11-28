//! Multiplexed single-backend `DB_DIRECT_DSN` PostgreSQL `LISTEN`/`NOTIFY` hub (#543).
//!
//! Instead of opening one direct PostgreSQL connection per subsystem or worker,
//! [`ListenHub`] runs a single actor on `DB_DIRECT_DSN` that:
//!
//! 1. Serializes ref-counted `LISTEN` (`0 -> 1`) and `UNLISTEN` (`1 -> 0`) on
//!    one direct backend.
//! 2. Re-`LISTEN`s every active channel on reconnect **before** publishing
//!    [`ListenEvent::ResyncRequired`] so subscribers never miss a notification
//!    committed after their resync snapshot.
//! 3. Uses a bounded per-subscriber queue paired with a coalesced
//!    `watch::Sender<(u64, u64)>` dirty-epoch signal so a slow or overflowing
//!    subscriber never blocks any other subscriber (such as `session_revoke`)
//!    and never loses [`ListenEvent::ResyncRequired`].
//! 4. Transitions cleanly into the reconnect loop on `UNLISTEN` errors instead
//!    of terminating the actor.
//! 5. Stops cleanly when the root [`CancellationToken`] is cancelled (or via
//!    [`ListenHub::shutdown`]), awaiting driver teardown without `Drop::abort`
//!    leaks.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::poll_fn;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_postgres::{AsyncMessage, Config, NoTls, Notification};
use tokio_util::sync::CancellationToken;

/// Default bounded per-subscriber notification queue capacity.
pub const DEFAULT_SUBSCRIBER_CAPACITY: usize = 256;

const INITIAL_BACKOFF: Duration = Duration::from_millis(50);
const MAX_BACKOFF: Duration = Duration::from_secs(2);
const DRIVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// A PostgreSQL `NOTIFY` payload delivered by [`ListenHub`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenNotification {
    pub channel: String,
    pub payload: String,
}

/// Event delivered to a [`ListenSubscription`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenEvent {
    /// A committed PostgreSQL `NOTIFY` on the subscribed channel.
    Notification(ListenNotification),
    /// The underlying connection reconnected or this subscriber's bounded queue
    /// overflowed. Callers must re-read authoritative state from PostgreSQL.
    /// All active channels are guaranteed to be `LISTEN`ing again before this
    /// event is emitted.
    ResyncRequired { epoch: u64 },
}

/// Errors returned by [`ListenHub`] construction and subscription methods.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenHubError {
    InvalidDsn(String),
    InvalidChannel(String),
    Closed,
}

impl fmt::Display for ListenHubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDsn(msg) => write!(f, "invalid DB_DIRECT_DSN: {msg}"),
            Self::InvalidChannel(ch) => write!(f, "invalid notification channel: {ch:?}"),
            Self::Closed => f.write_str("listen hub has shut down"),
        }
    }
}

impl std::error::Error for ListenHubError {}

#[derive(Clone, Debug)]
struct QueuedNotification {
    seq: u64,
    notification: ListenNotification,
}

struct SubscriberEntry {
    id: u64,
    tx: mpsc::Sender<QueuedNotification>,
    dirty_state: watch::Sender<(u64, u64)>,
}

struct SubscribeReply {
    rx: mpsc::Receiver<QueuedNotification>,
    dirty_rx: watch::Receiver<(u64, u64)>,
    initial_epoch: u64,
}

enum Command {
    Subscribe {
        id: u64,
        channel: String,
        capacity: usize,
        reply: oneshot::Sender<SubscribeReply>,
    },
    Unsubscribe {
        id: u64,
        channel: String,
    },
}

struct ListenHubInner {
    cmd_tx: mpsc::UnboundedSender<Command>,
    next_sub_id: AtomicU64,
    epoch: Arc<AtomicU64>,
    shutdown: CancellationToken,
    connected_rx: watch::Receiver<bool>,
    done_rx: watch::Receiver<bool>,
}

/// Cloneable handle to the single-backend `DB_DIRECT_DSN` [`ListenHub`] actor.
#[derive(Clone)]
pub struct ListenHub {
    inner: Arc<ListenHubInner>,
}

impl ListenHub {
    /// Validate `direct_dsn` and spawn the single-connection `ListenHub` actor.
    ///
    /// Cancelling `shutdown` stops the actor cleanly and closes all
    /// subscriptions.
    pub fn spawn(
        direct_dsn: impl Into<String>,
        shutdown: CancellationToken,
    ) -> Result<Self, ListenHubError> {
        let dsn = direct_dsn.into();
        let config: Config = dsn
            .parse()
            .map_err(|e: tokio_postgres::Error| ListenHubError::InvalidDsn(e.to_string()))?;
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let epoch = Arc::new(AtomicU64::new(0));
        let (connected_tx, connected_rx) = watch::channel(false);
        let (done_tx, done_rx) = watch::channel(false);

        let actor = Actor {
            config,
            cmd_rx,
            channels: HashMap::new(),
            epoch: epoch.clone(),
            seq: 0,
            shutdown: shutdown.clone(),
            connected_tx,
        };

        tokio::spawn(async move {
            actor.run().await;
            let _ = done_tx.send(true);
        });

        Ok(Self {
            inner: Arc::new(ListenHubInner {
                cmd_tx,
                next_sub_id: AtomicU64::new(1),
                epoch,
                shutdown,
                connected_rx,
                done_rx,
            }),
        })
    }

    /// Convenience constructor that bridges a `watch::Receiver<bool>` shutdown
    /// signal (treating `true` or sender drop as cancellation) into a root
    /// [`CancellationToken`].
    pub fn spawn_with_watch(
        direct_dsn: impl Into<String>,
        mut stop: watch::Receiver<bool>,
    ) -> Result<Self, ListenHubError> {
        let shutdown = CancellationToken::new();
        let trigger = shutdown.clone();
        tokio::spawn(async move {
            if *stop.borrow() {
                trigger.cancel();
                return;
            }
            loop {
                tokio::select! {
                    _ = trigger.cancelled() => break,
                    changed = stop.changed() => {
                        if changed.is_err() || *stop.borrow() {
                            trigger.cancel();
                            break;
                        }
                    }
                }
            }
        });
        Self::spawn(direct_dsn, shutdown)
    }

    /// Spawn the hub and wait until its initial PostgreSQL `DB_DIRECT_DSN`
    /// connection is established (or shutdown occurs).
    pub async fn spawn_connected(
        direct_dsn: impl Into<String>,
        shutdown: CancellationToken,
    ) -> Result<Self, ListenHubError> {
        let hub = Self::spawn(direct_dsn, shutdown)?;
        hub.wait_connected().await?;
        Ok(hub)
    }

    /// Wait until the actor has an active direct PostgreSQL connection.
    pub async fn wait_connected(&self) -> Result<(), ListenHubError> {
        let mut rx = self.inner.connected_rx.clone();
        if *rx.borrow() {
            return Ok(());
        }
        loop {
            tokio::select! {
                _ = self.inner.shutdown.cancelled() => return Err(ListenHubError::Closed),
                res = rx.changed() => {
                    if res.is_err() {
                        return Err(ListenHubError::Closed);
                    }
                    if *rx.borrow() {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Current monotonic connection / resync epoch.
    pub fn epoch(&self) -> u64 {
        self.inner.epoch.load(Ordering::Acquire)
    }

    /// Subscribe to `channel` with [`DEFAULT_SUBSCRIBER_CAPACITY`].
    pub async fn subscribe(
        &self,
        channel: impl Into<String>,
    ) -> Result<ListenSubscription, ListenHubError> {
        self.subscribe_with_capacity(channel, DEFAULT_SUBSCRIBER_CAPACITY)
            .await
    }

    /// Subscribe to `channel` with a custom bounded queue capacity (minimum 1).
    pub async fn subscribe_with_capacity(
        &self,
        channel: impl Into<String>,
        capacity: usize,
    ) -> Result<ListenSubscription, ListenHubError> {
        let channel = channel.into();
        if !valid_channel(&channel) {
            return Err(ListenHubError::InvalidChannel(channel));
        }
        let id = self.inner.next_sub_id.fetch_add(1, Ordering::Relaxed);
        let (reply_tx, reply_rx) = oneshot::channel();
        self.inner
            .cmd_tx
            .send(Command::Subscribe {
                id,
                channel: channel.clone(),
                capacity: capacity.max(1),
                reply: reply_tx,
            })
            .map_err(|_| ListenHubError::Closed)?;
        let reply = reply_rx.await.map_err(|_| ListenHubError::Closed)?;
        Ok(ListenSubscription {
            id,
            channel,
            rx: reply.rx,
            dirty_state: reply.dirty_rx,
            last_seen_epoch: reply.initial_epoch,
            pending: None,
            cmd_tx: self.inner.cmd_tx.clone(),
        })
    }

    /// Cancel the hub's root token and wait for the actor and PostgreSQL
    /// connection driver to shut down cleanly.
    pub async fn shutdown(&self) {
        self.inner.shutdown.cancel();
        let mut done = self.inner.done_rx.clone();
        while !*done.borrow() {
            if done.changed().await.is_err() {
                break;
            }
        }
    }
}

/// Active subscription handle on a single channel managed by [`ListenHub`].
///
/// Dropping this handle automatically decrements the channel's reference count
/// and issues `UNLISTEN` on the `1 -> 0` transition.
pub struct ListenSubscription {
    id: u64,
    channel: String,
    rx: mpsc::Receiver<QueuedNotification>,
    dirty_state: watch::Receiver<(u64, u64)>,
    last_seen_epoch: u64,
    pending: Option<QueuedNotification>,
    cmd_tx: mpsc::UnboundedSender<Command>,
}

impl ListenSubscription {
    /// Channel name this subscription listens on.
    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// Receive the next notification or coalesced [`ListenEvent::ResyncRequired`].
    /// Returns `None` once the owning [`ListenHub`] has shut down.
    pub async fn recv(&mut self) -> Option<ListenEvent> {
        loop {
            let (dirty_epoch, watermark_seq) = *self.dirty_state.borrow_and_update();
            if dirty_epoch > self.last_seen_epoch {
                self.last_seen_epoch = dirty_epoch;
                // Drop any previously stashed pending notification from before
                // the new resync/overflow watermark.
                if self
                    .pending
                    .as_ref()
                    .is_some_and(|queued| queued.seq <= watermark_seq)
                {
                    self.pending = None;
                }
                // Drain stale buffered notifications from before the resync/overflow
                // watermark so the bounded queue regains headroom immediately, while
                // preserving any notification committed after the watermark.
                if self.pending.is_none() {
                    while let Ok(item) = self.rx.try_recv() {
                        if item.seq > watermark_seq {
                            self.pending = Some(item);
                            break;
                        }
                    }
                }
                return Some(ListenEvent::ResyncRequired { epoch: dirty_epoch });
            }
            if let Some(queued) = self.pending.take() {
                return Some(ListenEvent::Notification(queued.notification));
            }
            tokio::select! {
                biased;
                changed = self.dirty_state.changed() => {
                    match changed {
                        Ok(()) => continue,
                        Err(_) => return None,
                    }
                }
                item = self.rx.recv() => {
                    match item {
                        Some(queued) => {
                            let (latest_epoch, latest_watermark) = *self.dirty_state.borrow();
                            if latest_epoch > self.last_seen_epoch {
                                if queued.seq > latest_watermark {
                                    self.pending = Some(queued);
                                }
                                continue;
                            }
                            return Some(ListenEvent::Notification(queued.notification));
                        }
                        None => return None,
                    }
                }
            }
        }
    }
}

impl Drop for ListenSubscription {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(Command::Unsubscribe {
            id: self.id,
            channel: std::mem::take(&mut self.channel),
        });
    }
}

fn valid_channel(channel: &str) -> bool {
    !channel.is_empty()
        && channel
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_:.-".contains(&c))
}

struct LiveConnection {
    client: tokio_postgres::Client,
    notifications: mpsc::UnboundedReceiver<Notification>,
    driver: tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>,
}

impl LiveConnection {
    async fn connect(config: &Config) -> Result<Self, tokio_postgres::Error> {
        let (client, mut connection) = config.connect(NoTls).await?;
        let (tx, notifications) = mpsc::unbounded_channel();
        let driver = tokio::spawn(async move {
            loop {
                match poll_fn(|cx| connection.poll_message(cx)).await {
                    Some(Ok(AsyncMessage::Notification(notification))) => {
                        let _ = tx.send(notification);
                    }
                    Some(Ok(_)) => {}
                    Some(Err(err)) => break Err(err),
                    None => break Ok(()),
                }
            }
        });
        Ok(Self {
            client,
            notifications,
            driver,
        })
    }

    async fn listen(&self, channel: &str) -> Result<(), tokio_postgres::Error> {
        self.client
            .batch_execute(&format!("LISTEN \"{channel}\""))
            .await
    }

    async fn unlisten(&self, channel: &str) -> Result<(), tokio_postgres::Error> {
        self.client
            .batch_execute(&format!("UNLISTEN \"{channel}\""))
            .await
    }

    async fn close(self) {
        let Self {
            client,
            notifications,
            mut driver,
        } = self;
        drop(client);
        drop(notifications);
        if tokio::time::timeout(DRIVER_SHUTDOWN_TIMEOUT, &mut driver)
            .await
            .is_err()
        {
            driver.abort();
            let _ = driver.await;
        }
    }
}

struct Actor {
    config: Config,
    cmd_rx: mpsc::UnboundedReceiver<Command>,
    channels: HashMap<String, Vec<SubscriberEntry>>,
    epoch: Arc<AtomicU64>,
    seq: u64,
    shutdown: CancellationToken,
    connected_tx: watch::Sender<bool>,
}

impl Actor {
    fn next_epoch(&self) -> u64 {
        self.epoch.fetch_add(1, Ordering::AcqRel) + 1
    }

    fn current_epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    fn next_seq(&mut self) -> u64 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    async fn run(mut self) {
        let mut has_connected_before = false;
        let mut backoff = INITIAL_BACKOFF;

        loop {
            if self.shutdown.is_cancelled() {
                break;
            }

            let conn = tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => break,
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(cmd) => {
                            self.handle_command_disconnected(cmd);
                            continue;
                        }
                        None => break,
                    }
                }
                res = LiveConnection::connect(&self.config) => res,
            };

            let mut conn = match conn {
                Ok(conn) => conn,
                Err(_) => {
                    let _ = self.connected_tx.send(false);
                    if !self.sleep_with_commands(backoff).await {
                        break;
                    }
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    continue;
                }
            };

            // Re-LISTEN every active channel BEFORE broadcasting ResyncRequired!
            self.prune_closed_subscribers();
            let active_channels: Vec<String> = self.channels.keys().cloned().collect();
            let mut listen_ok = true;
            for channel in &active_channels {
                let res = tokio::select! {
                    biased;
                    _ = self.shutdown.cancelled() => {
                        conn.close().await;
                        return;
                    }
                    res = conn.listen(channel) => res,
                };
                if res.is_err() {
                    listen_ok = false;
                    break;
                }
            }
            if !listen_ok {
                conn.close().await;
                let _ = self.connected_tx.send(false);
                if !self.sleep_with_commands(backoff).await {
                    break;
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }

            backoff = INITIAL_BACKOFF;
            let new_epoch = self.next_epoch();
            let _ = self.connected_tx.send(true);

            // Emit ResyncRequired AFTER all active channels are re-LISTENed.
            // On initial connect (before any drop), only subscribers that joined
            // while disconnected (initial_epoch == 0 < new_epoch) need resync;
            // on reconnect, ALL active subscribers receive ResyncRequired.
            if has_connected_before || !self.channels.is_empty() {
                let seq = self.next_seq();
                self.broadcast_resync(new_epoch, seq);
            }
            has_connected_before = true;

            let keep_running = self.run_connected(&mut conn).await;
            let _ = self.connected_tx.send(false);
            conn.close().await;
            if !keep_running {
                break;
            }
            // Brief backoff before reconnecting after an unexpected disconnect or UNLISTEN error.
            if !self.sleep_with_commands(INITIAL_BACKOFF).await {
                break;
            }
        }

        // Dropping self.channels closes every subscriber's mpsc + watch senders cleanly.
        self.channels.clear();
    }

    async fn sleep_with_commands(&mut self, duration: Duration) -> bool {
        let timer = tokio::time::sleep(duration);
        tokio::pin!(timer);
        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => return false,
                _ = &mut timer => return true,
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(cmd) => self.handle_command_disconnected(cmd),
                        None => return false,
                    }
                }
            }
        }
    }

    async fn run_connected(&mut self, conn: &mut LiveConnection) -> bool {
        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => return false,
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(cmd) => {
                            if !self.handle_command_connected(conn, cmd).await {
                                // LISTEN or UNLISTEN error -> transition cleanly to reconnect loop.
                                return true;
                            }
                        }
                        None => return false,
                    }
                }
                notif = conn.notifications.recv() => {
                    match notif {
                        Some(notification) => {
                            if !self.dispatch_notification(conn, notification).await {
                                // UNLISTEN error while pruning closed subscribers -> reconnect.
                                return true;
                            }
                        }
                        None => {
                            // Underlying PG backend disconnected -> reconnect loop.
                            return true;
                        }
                    }
                }
            }
        }
    }

    fn handle_command_disconnected(&mut self, cmd: Command) {
        match cmd {
            Command::Subscribe {
                id,
                channel,
                capacity,
                reply,
            } => {
                let current_epoch = self.current_epoch();
                let (tx, rx) = mpsc::channel(capacity);
                let (dirty_tx, dirty_rx) = watch::channel((current_epoch, self.seq));
                self.channels
                    .entry(channel)
                    .or_default()
                    .push(SubscriberEntry {
                        id,
                        tx,
                        dirty_state: dirty_tx,
                    });
                let _ = reply.send(SubscribeReply {
                    rx,
                    dirty_rx,
                    initial_epoch: current_epoch,
                });
            }
            Command::Unsubscribe { id, channel } => {
                if let Some(subs) = self.channels.get_mut(&channel) {
                    subs.retain(|s| s.id != id);
                    if subs.is_empty() {
                        self.channels.remove(&channel);
                    }
                }
            }
        }
    }

    async fn handle_command_connected(&mut self, conn: &LiveConnection, cmd: Command) -> bool {
        match cmd {
            Command::Subscribe {
                id,
                channel,
                capacity,
                reply,
            } => {
                let first_on_channel = !self.channels.contains_key(&channel);
                let current_epoch = self.current_epoch();
                let (tx, rx) = mpsc::channel(capacity);
                let (dirty_tx, dirty_rx) = watch::channel((current_epoch, self.seq));
                self.channels
                    .entry(channel.clone())
                    .or_default()
                    .push(SubscriberEntry {
                        id,
                        tx,
                        dirty_state: dirty_tx,
                    });
                let listen_ok = if first_on_channel {
                    conn.listen(&channel).await.is_ok()
                } else {
                    true
                };
                let _ = reply.send(SubscribeReply {
                    rx,
                    dirty_rx,
                    initial_epoch: current_epoch,
                });
                listen_ok
            }
            Command::Unsubscribe { id, channel } => {
                let became_empty = match self.channels.get_mut(&channel) {
                    Some(subs) => {
                        subs.retain(|s| s.id != id);
                        if subs.is_empty() {
                            self.channels.remove(&channel);
                            true
                        } else {
                            false
                        }
                    }
                    None => false,
                };
                if became_empty {
                    // Transition cleanly to reconnect loop on UNLISTEN error; never kill actor.
                    return conn.unlisten(&channel).await.is_ok();
                }
                true
            }
        }
    }

    async fn dispatch_notification(
        &mut self,
        conn: &LiveConnection,
        notification: Notification,
    ) -> bool {
        let channel = notification.channel().to_owned();
        let payload = notification.payload().to_owned();
        let seq = self.next_seq();
        let notif = ListenNotification {
            channel: channel.clone(),
            payload,
        };
        let mut became_empty = false;
        if let Some(subs) = self.channels.get_mut(&channel) {
            let mut dead_ids = Vec::new();
            for sub in subs.iter() {
                let queued = QueuedNotification {
                    seq,
                    notification: notif.clone(),
                };
                match sub.tx.try_send(queued) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // Slow/overflowing subscriber: NEVER stall other subscribers
                        // and NEVER drop ResyncRequired.
                        let resync_epoch = self.epoch.fetch_add(1, Ordering::AcqRel) + 1;
                        let _ = sub.dirty_state.send((resync_epoch, seq));
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        dead_ids.push(sub.id);
                    }
                }
            }
            if !dead_ids.is_empty() {
                subs.retain(|s| !dead_ids.contains(&s.id));
                if subs.is_empty() {
                    self.channels.remove(&channel);
                    became_empty = true;
                }
            }
        }
        if became_empty {
            return conn.unlisten(&channel).await.is_ok();
        }
        true
    }

    fn broadcast_resync(&self, epoch: u64, seq: u64) {
        for subs in self.channels.values() {
            for sub in subs {
                sub.dirty_state.send_modify(|state| {
                    state.0 = state.0.max(epoch);
                    state.1 = state.1.max(seq);
                });
            }
        }
    }

    fn prune_closed_subscribers(&mut self) {
        self.channels.retain(|_, subs| {
            subs.retain(|s| !s.tx.is_closed());
            !subs.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_channel_names() {
        assert!(valid_channel("session_revoke"));
        assert!(valid_channel("feature_toggles:v1.0-a"));
        assert!(!valid_channel(""));
        assert!(!valid_channel("bad; DROP TABLE users;"));
        assert!(!valid_channel("bad\"quote"));
        assert!(!valid_channel("bad space"));
    }

    #[tokio::test]
    async fn rejects_invalid_dsn_and_channel() {
        let token = CancellationToken::new();
        assert!(matches!(
            ListenHub::spawn("not a valid dsn ::::", token.clone()),
            Err(ListenHubError::InvalidDsn(_))
        ));
        let hub = ListenHub::spawn(
            "postgres://mail@127.0.0.1:1/nonexistent?connect_timeout=1",
            token,
        )
        .unwrap();
        assert!(matches!(
            hub.subscribe("bad;channel").await,
            Err(ListenHubError::InvalidChannel(_))
        ));
        hub.shutdown().await;
    }

    #[tokio::test]
    async fn stale_pending_notification_is_dropped_across_subsequent_epoch_bump() {
        let (tx, rx) = mpsc::channel(8);
        let (dirty_tx, dirty_rx) = watch::channel((1u64, 0u64));
        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();
        let mut sub = ListenSubscription {
            id: 1,
            channel: "session_revoke".into(),
            rx,
            dirty_state: dirty_rx,
            last_seen_epoch: 1,
            pending: None,
            cmd_tx,
        };

        // Pre-resync item (seq 3) and post-epoch-2 item (seq 5) arrive before caller polls.
        tx.send(QueuedNotification {
            seq: 3,
            notification: ListenNotification {
                channel: "session_revoke".into(),
                payload: "stale_before_epoch2".into(),
            },
        })
        .await
        .unwrap();
        tx.send(QueuedNotification {
            seq: 5,
            notification: ListenNotification {
                channel: "session_revoke".into(),
                payload: "post_epoch2_but_before_epoch3".into(),
            },
        })
        .await
        .unwrap();

        // Epoch 2 bumps with watermark_seq = 4 -> drops seq 3, stashes seq 5 in self.pending.
        dirty_tx.send((2, 4)).unwrap();
        assert_eq!(
            sub.recv().await,
            Some(ListenEvent::ResyncRequired { epoch: 2 })
        );
        assert_eq!(sub.pending.as_ref().map(|p| p.seq), Some(5));

        // Before caller consumes self.pending (seq 5), epoch 3 bumps with watermark_seq = 10
        // and a fresh post-epoch-3 notification (seq 11) arrives.
        tx.send(QueuedNotification {
            seq: 11,
            notification: ListenNotification {
                channel: "session_revoke".into(),
                payload: "fresh_after_epoch3".into(),
            },
        })
        .await
        .unwrap();
        dirty_tx.send((3, 10)).unwrap();

        // Epoch 3 ResyncRequired must evict stale self.pending (seq 5 <= 10) and preserve seq 11.
        assert_eq!(
            sub.recv().await,
            Some(ListenEvent::ResyncRequired { epoch: 3 })
        );
        assert_eq!(
            sub.recv().await,
            Some(ListenEvent::Notification(ListenNotification {
                channel: "session_revoke".into(),
                payload: "fresh_after_epoch3".into(),
            }))
        );
    }
}
