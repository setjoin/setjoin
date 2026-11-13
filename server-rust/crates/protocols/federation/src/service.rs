//! The reconcile-driven federation daemon: the accept loop, one dial loop per
//! dialled peer, the live stream and sender registries, and the typing relay.
//!
//! Two independent gates: STATIC (constructed only when a local domain and a
//! leaf certificate are configured) and DYNAMIC (every reconcile tick
//! re-reads feature.federation and the enabled allow-list and converges the
//! live set, actively dropping a stream whose peer stopped being enabled:
//! eviction, never a TTL). No authority lives here: sequencing, dedup,
//! allow-list and apply are reducer calls.

use crate::{
    db::{BoxFut, FedDb},
    discover::{resolve_peer, Resolver, SystemResolver},
    error::FedError,
    flags::Flags,
    log::Logger,
    receiver::Receiver,
    sender::{
        encode_ephemeral, encode_ephemeral_dm, Sender, TokenBucket, EPHEMERAL_BUCKET,
        EPHEMERAL_REFILL,
    },
    stream::{dial, listen, AnchorLookup, Bounds, PeerStream},
    trust::{Anchor, Identity},
    wire::Hello,
};
use setjoin_pg::{workers::DirectListener, Type};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::TcpListener, sync::Notify};
use tokio_util::sync::CancellationToken;

/// Lost-wakeup fallback for the allow-list NOTIFY.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(20);

#[derive(Clone)]
pub struct Config {
    /// This instance's federation domain, e.g. `mail.corp.com`.
    pub local_domain: String,
    /// s2s TLS listen address; empty means `:7443`.
    pub listen_addr: String,
    /// SRV discovery; `None` means the system resolver.
    pub resolver: Option<Arc<dyn Resolver>>,
    pub bounds: Bounds,
    /// Direct (non-pooled) DSN for LISTEN/NOTIFY wakes; `None` leaves only the tickers.
    pub direct_dsn: Option<String>,
    /// Accept-loop poll while the feature is OFF (Go: 250 ms).
    pub accept_poll: Duration,
}

impl Config {
    pub fn new(local_domain: &str) -> Self {
        Config {
            local_domain: local_domain.to_string(),
            listen_addr: String::new(),
            resolver: None,
            bounds: Bounds::default(),
            direct_dsn: None,
            accept_poll: Duration::from_millis(250),
        }
    }
    pub fn listen_addr(&self) -> String {
        if self.listen_addr.is_empty() {
            ":7443".to_string()
        } else {
            self.listen_addr.clone()
        }
    }
}

/// An enabled allow-list row the reconcile loop acts on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowlistPeer {
    pub domain: String,
    pub scope: String,
}

pub type AllowlistLister =
    Arc<dyn Fn() -> BoxFut<'static, Result<Vec<AllowlistPeer>, FedError>> + Send + Sync>;

/// `federation_allowlist` enabled rows (FORCE RLS: worker credential only).
pub fn allowlist_lister(db: Arc<dyn FedDb>) -> AllowlistLister {
    Arc::new(move || {
        let db = db.clone();
        Box::pin(async move {
            let rows = db
                .query(
                    "SELECT peer_domain, scope FROM federation_allowlist WHERE enabled",
                    &[],
                )
                .await
                .map_err(|e| {
                    FedError::other(format!("federation: list enabled allow-list peers: {e}"))
                })?;
            let mut out = Vec::new();
            for r in rows {
                out.push(AllowlistPeer {
                    domain: r.try_get(0).map_err(|e| {
                        FedError::other(format!("federation: scan allow-list peer: {e}"))
                    })?,
                    scope: r.try_get(1).map_err(|e| {
                        FedError::other(format!("federation: scan allow-list peer: {e}"))
                    })?,
                });
            }
            Ok(out)
        })
    })
}

/// A peer's pinned anchor: ANY allow-list row, enabled or not (the enabled and
/// scope policy is `federation_peer_authorize`'s job at handshake time).
pub fn anchor_lookup(db: Arc<dyn FedDb>) -> AnchorLookup {
    Arc::new(move |domain: String| {
        let db = db.clone();
        Box::pin(async move {
            let rows = db
                .query(
                    "SELECT peer_anchor FROM federation_allowlist WHERE peer_domain = $1",
                    &[(&domain, Type::TEXT)],
                )
                .await
                .map_err(|e| {
                    FedError::other(format!("federation: read anchor for {domain}: {e}"))
                })?;
            let Some(r) = rows.first() else {
                return Ok(None);
            };
            let pem: String = r.try_get(0).map_err(|e| {
                FedError::other(format!("federation: read anchor for {domain}: {e}"))
            })?;
            Anchor::from_pem(&pem)
                .map(Some)
                .map_err(|e| FedError::other(format!("federation: anchor for {domain}: {e}")))
        })
    })
}

/// Exactly one side of an ordered pair dials; the other accepts.
pub fn dials_first(local: &str, peer: &str) -> bool {
    local < peer
}

/// What the chat package hands `send_typing` (read under its own RLS scope).
///
///   DM:         room_id == "", peer_domain != ""
///   spoke room: room_id != "", peer_domain != "" (the bound hub)
///   hub room:   room_id != "", peer_domain == "" (fanned to the roster)
#[derive(Clone, Debug, Default)]
pub struct TypingChannel {
    pub channel_id: i64,
    pub peer_domain: String,
    pub room_id: String,
    pub remote_id: String,
    pub local_user_email: String,
}

#[derive(Default)]
struct State {
    dialers: HashMap<String, CancellationToken>,
    outbox_subs: HashMap<String, CancellationToken>,
}

pub struct Service {
    cfg: Config,
    db: Arc<dyn FedDb>,
    flags: Arc<dyn Flags>,
    identity: Identity,
    resolver: Arc<dyn Resolver>,
    anchor_lu: AnchorLookup,
    list_allow: AllowlistLister,
    log: Logger,
    senders: Mutex<HashMap<String, Arc<Sender>>>,
    streams: Mutex<HashMap<String, Arc<PeerStream>>>,
    state: Mutex<State>,
    wake: Notify,
    ephemeral_out: Mutex<HashMap<String, Arc<TokenBucket>>>,
}

fn same<T>(a: &Arc<T>, b: &Arc<T>) -> bool {
    Arc::ptr_eq(a, b)
}

impl Service {
    /// `None` when `cfg.local_domain` is empty: the static-gate inert posture.
    pub fn new(
        cfg: Config,
        db: Arc<dyn FedDb>,
        flags: Arc<dyn Flags>,
        identity: Identity,
        log: Logger,
    ) -> Option<Arc<Service>> {
        if cfg.local_domain.trim().is_empty() {
            return None;
        }
        let resolver = cfg
            .resolver
            .clone()
            .unwrap_or_else(|| Arc::new(SystemResolver));
        Some(Arc::new(Service {
            anchor_lu: anchor_lookup(db.clone()),
            list_allow: allowlist_lister(db.clone()),
            cfg,
            db,
            flags,
            identity,
            resolver,
            log,
            senders: Mutex::new(HashMap::new()),
            streams: Mutex::new(HashMap::new()),
            state: Mutex::new(State::default()),
            wake: Notify::new(),
            ephemeral_out: Mutex::new(HashMap::new()),
        }))
    }

    /// Re-read the allow-list now (the allow-list NOTIFY handler).
    pub fn wake(&self) {
        self.wake.notify_one();
    }

    /// Peer domains with a tracked live stream.
    pub fn live_streams(&self) -> Vec<String> {
        self.streams.lock().unwrap().keys().cloned().collect()
    }

    /// Bind the configured address, then run until `ctx` ends.
    pub async fn run(self: Arc<Self>, ctx: CancellationToken) {
        let addr = self.cfg.listen_addr();
        let bind = match addr.strip_prefix(':') {
            Some(port) => format!("[::]:{port}"),
            None => addr.clone(),
        };
        let ln = match TcpListener::bind(&bind).await {
            Ok(l) => l,
            Err(_) if addr.starts_with(':') => {
                match TcpListener::bind(format!("0.0.0.0{addr}")).await {
                    Ok(l) => l,
                    Err(e) => {
                        self.log.error(format!(
                            "federation: listen failed — service not started addr={addr} error={e}"
                        ));
                        return;
                    }
                }
            }
            Err(e) => {
                self.log.error(format!(
                    "federation: listen failed — service not started addr={addr} error={e}"
                ));
                return;
            }
        };
        self.run_with_listener(ctx, ln).await
    }

    /// Run on an already bound (or inherited) listener.
    pub async fn run_with_listener(self: Arc<Self>, ctx: CancellationToken, ln: TcpListener) {
        self.log.info(format!(
            "federation: service starting local_domain={} listen={}",
            self.cfg.local_domain,
            self.cfg.listen_addr()
        ));
        // Go receives an already-connected notification dispatcher. Establish
        // our allow-list LISTEN before exposing a peer hello too: otherwise an
        // immediate revocation can be lost until the 20 s fallback reconcile.
        self.subscribe_allowlist(&ctx).await;
        // Accept side: the scope is the dm FLOOR, because the wiring contract
        // is exactly one stream per ordered pair and establishment only proves
        // the peer may federate at all; a room-scoped row still passes a dm
        // check, and room content is enforced per payload by the applier.
        let accept = {
            let me = self.clone();
            let ctx = ctx.clone();
            tokio::spawn(async move { me.run_accept_loop(ctx, ln).await })
        };

        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + RECONCILE_INTERVAL,
            RECONCILE_INTERVAL,
        );
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        self.reconcile_once(&ctx).await;
        loop {
            tokio::select! {
                _ = ctx.cancelled() => {
                    self.log.info("federation: service stopping");
                    break;
                }
                _ = ticker.tick() => self.reconcile_once(&ctx).await,
                _ = self.wake.notified() => self.reconcile_once(&ctx).await,
            }
        }
        accept.abort();
    }

    /// Keeps the listener dormant while the dynamic feature is OFF, then
    /// accepts when an operator enables it (no restart needed).
    async fn run_accept_loop(self: Arc<Self>, ctx: CancellationToken, ln: TcpListener) {
        let tls = match self.identity.server_config() {
            Ok(t) => t,
            Err(e) => {
                self.log.error(format!(
                    "federation: server TLS config failed — accept side not started: {e}"
                ));
                return;
            }
        };
        let hello = Hello::new(&self.cfg.local_domain);
        loop {
            while !self.flags.federation_enabled() {
                tokio::select! {
                    _ = ctx.cancelled() => return,
                    _ = tokio::time::sleep(self.cfg.accept_poll) => {}
                }
            }
            self.log.info("federation: accept loop enabled");
            let me = self.clone();
            let ctx2 = ctx.clone();
            let on_stream: Arc<dyn Fn(PeerStream) + Send + Sync> = Arc::new(move |stream| {
                me.log.info(format!(
                    "federation: accepted inbound stream peer={}",
                    stream.domain
                ));
                let me = me.clone();
                let ctx = ctx2.clone();
                tokio::spawn(async move {
                    let peer = stream.domain.clone();
                    if let Err(e) = me.wire_and_run(&ctx, stream).await {
                        if !ctx.is_cancelled() {
                            me.log.warn(format!(
                                "federation: accepted stream ended peer={peer} error={e}"
                            ));
                        }
                    }
                });
            });
            let r = listen(
                ctx.clone(),
                self.flags.clone(),
                &ln,
                tls.clone(),
                self.anchor_lu.clone(),
                hello.clone(),
                self.db.clone(),
                "dm".to_string(),
                self.cfg.bounds.clone(),
                self.log.clone(),
                on_stream,
            )
            .await;
            if ctx.is_cancelled() {
                return;
            }
            match r {
                Err(FedError::Disabled) => continue,
                Err(e) => {
                    self.log
                        .error(format!("federation: Listen exited error={e}"));
                    return;
                }
                Ok(()) => return,
            }
        }
    }

    async fn subscribe_allowlist(self: &Arc<Self>, ctx: &CancellationToken) {
        let Some(dsn) = self.cfg.direct_dsn.clone() else {
            return;
        };
        let me = self.clone();
        let ready = spawn_listener(
            ctx.clone(),
            dsn,
            "federation_allowlist_changed".into(),
            self.log.clone(),
            move || me.wake(),
        );
        tokio::select! {
            _ = ctx.cancelled() => {},
            _ = ready => {},
        }
    }

    /// Converge the live dial loops, outbox subscriptions and streams to the
    /// current toggle and enabled allow-list. A transient database error never
    /// tears down a live peer.
    pub async fn reconcile_once(self: &Arc<Self>, ctx: &CancellationToken) {
        if !self.flags.federation_enabled() {
            self.drop_all();
            return;
        }
        let peers = match (self.list_allow)().await {
            Ok(p) => p,
            Err(e) => {
                self.log.warn(format!(
                    "federation: reconcile: list enabled allow-list peers failed — leaving existing streams as-is error={e}"
                ));
                return;
            }
        };
        let mut enabled: HashMap<String, ()> = HashMap::new();
        let mut desired_dial: HashMap<String, ()> = HashMap::new();
        for p in &peers {
            enabled.insert(p.domain.clone(), ());
            if dials_first(&self.cfg.local_domain, &p.domain) {
                desired_dial.insert(p.domain.clone(), ());
            }
        }
        let (mut started, mut stopped) = (Vec::new(), Vec::new());
        {
            let mut st = self.state.lock().unwrap();
            for d in desired_dial.keys() {
                if !st.dialers.contains_key(d) {
                    let dctx = ctx.child_token();
                    st.dialers.insert(d.clone(), dctx.clone());
                    started.push(d.clone());
                    let me = self.clone();
                    let peer = d.clone();
                    tokio::spawn(async move { me.run_dialer(dctx, peer).await });
                }
            }
            let gone: Vec<String> = st
                .dialers
                .keys()
                .filter(|d| !desired_dial.contains_key(*d))
                .cloned()
                .collect();
            for d in gone {
                // Cancelling stops the dial loop AND tears down its stream.
                if let Some(c) = st.dialers.remove(&d) {
                    c.cancel();
                }
                stopped.push(d);
            }
            if let Some(dsn) = self.cfg.direct_dsn.clone() {
                for peer in enabled.keys() {
                    if !st.outbox_subs.contains_key(peer) {
                        let c = ctx.child_token();
                        st.outbox_subs.insert(peer.clone(), c.clone());
                        let me = self.clone();
                        let p = peer.clone();
                        spawn_listener(
                            c,
                            dsn.clone(),
                            format!("federation_outbox:{peer}"),
                            self.log.clone(),
                            move || me.wake_sender(&p),
                        );
                    }
                }
                let stale: Vec<String> = st
                    .outbox_subs
                    .keys()
                    .filter(|p| !enabled.contains_key(*p))
                    .cloned()
                    .collect();
                for p in stale {
                    if let Some(c) = st.outbox_subs.remove(&p) {
                        c.cancel();
                    }
                }
            }
        }
        for d in started {
            self.log
                .info(format!("federation: reconcile: started dial loop peer={d}"));
        }
        for d in stopped {
            self.log.info(format!(
                "federation: reconcile: dropped dial loop for disabled/removed peer peer={d}"
            ));
        }
        // Accept-side eviction: a peer we do not dial can still hold a live
        // inbound stream that must close the moment it stops being enabled.
        for peer in self.live_streams() {
            if !enabled.contains_key(&peer) && self.close_stream(&peer) {
                self.log.info(format!(
                    "federation: reconcile: closed live stream for disabled/removed peer peer={peer}"
                ));
            }
        }
    }

    fn wake_sender(&self, peer: &str) {
        let s = self.senders.lock().unwrap().get(peer).cloned();
        if let Some(s) = s {
            s.wake();
        }
    }

    fn close_stream(&self, peer: &str) -> bool {
        let s = self.streams.lock().unwrap().get(peer).cloned();
        match s {
            Some(s) => {
                s.close();
                true
            }
            None => false,
        }
    }

    /// feature.federation flipped OFF: tear everything down.
    fn drop_all(&self) {
        {
            let mut st = self.state.lock().unwrap();
            for (_, c) in st.dialers.drain() {
                c.cancel();
            }
            for (_, c) in st.outbox_subs.drain() {
                c.cancel();
            }
        }
        for peer in self.live_streams() {
            self.close_stream(&peer);
        }
    }

    /// The reconnect loop for ONE dialled peer: re-resolve, re-anchor and
    /// re-dial with capped exponential backoff until cancelled.
    async fn run_dialer(self: Arc<Self>, ctx: CancellationToken, peer: String) {
        const INITIAL: Duration = Duration::from_secs(1);
        const MAX: Duration = Duration::from_secs(30);
        const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
        let mut backoff = INITIAL;
        let sleep = |ctx: &CancellationToken, backoff: &mut Duration| {
            let d = *backoff;
            *backoff = (*backoff * 2).min(MAX);
            let ctx = ctx.clone();
            async move {
                tokio::select! {
                    _ = ctx.cancelled() => false,
                    _ = tokio::time::sleep(d) => true,
                }
            }
        };
        while !ctx.is_cancelled() {
            let endpoint = match resolve_peer(self.resolver.as_ref(), &peer).await {
                Ok(e) => e,
                Err(e) => {
                    self.log.warn(format!(
                        "federation: SRV resolve failed peer={peer} error={e}"
                    ));
                    if !sleep(&ctx, &mut backoff).await {
                        return;
                    }
                    continue;
                }
            };
            let anchor = match (self.anchor_lu)(peer.clone()).await {
                Ok(Some(a)) => a,
                other => {
                    let err = other.err().map(|e| e.to_string()).unwrap_or_default();
                    self.log.warn(format!(
                        "federation: no allow-list anchor for peer yet peer={peer} error={err}"
                    ));
                    if !sleep(&ctx, &mut backoff).await {
                        return;
                    }
                    continue;
                }
            };
            let hello = Hello::new(&self.cfg.local_domain);
            let stream = match dial(
                &ctx,
                self.flags.as_ref(),
                &endpoint,
                &self.identity,
                anchor,
                &hello,
                DIAL_TIMEOUT,
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    self.log.warn(format!(
                        "federation: dial failed peer={peer} target={} port={} error={e}",
                        endpoint.target, endpoint.port
                    ));
                    if !sleep(&ctx, &mut backoff).await {
                        return;
                    }
                    continue;
                }
            };
            self.log
                .info(format!("federation: dialed peer peer={peer}"));
            backoff = INITIAL; // reset only after a successful connect
            let r = self.wire_and_run(&ctx, stream).await;
            if ctx.is_cancelled() {
                return;
            }
            let err = r.err().map(|e| e.to_string()).unwrap_or_default();
            self.log.warn(format!(
                "federation: stream to peer broke, reconnecting peer={peer} error={err}"
            ));
            if !sleep(&ctx, &mut backoff).await {
                return;
            }
        }
    }

    /// Pair a Receiver and Sender with a fresh stream, register both, and block
    /// in the sender until the stream breaks or `ctx` ends. A new Sender per
    /// (re)connect resets the cursors to the durable ack point.
    pub async fn wire_and_run(
        self: &Arc<Self>,
        ctx: &CancellationToken,
        stream: PeerStream,
    ) -> Result<(), FedError> {
        let stream = Arc::new(stream);
        let peer = stream.domain.clone();
        let receiver = Receiver::new(self.db.clone(), self.flags.clone(), &peer, self.log.clone());
        let sender = Sender::new(
            self.db.clone(),
            self.flags.clone(),
            &peer,
            stream.clone(),
            receiver,
            self.log.clone(),
        );
        // The hub relay runs on its own task so the origin peer's read loop is
        // never held up by another peer's lock or write.
        let me = self.clone();
        let rctx = ctx.clone();
        sender.set_relay_ephemeral(Arc::new(move |origin, payload| {
            let me = me.clone();
            let rctx = rctx.clone();
            tokio::spawn(async move { me.relay_room_ephemeral(&rctx, &origin, &payload).await });
        }));
        self.senders
            .lock()
            .unwrap()
            .insert(peer.clone(), sender.clone());
        {
            let mut m = self.streams.lock().unwrap();
            // Supersede-and-close: a peer may open a new stream while the old
            // one is live; the old reader unwinds and cannot evict this one.
            if let Some(old) = m.insert(peer.clone(), stream.clone()) {
                if !same(&old, &stream) {
                    old.close();
                }
            }
        }
        let r = sender.clone().run(ctx.clone()).await;
        {
            let mut s = self.senders.lock().unwrap();
            if s.get(&peer).is_some_and(|x| same(x, &sender)) {
                s.remove(&peer);
            }
        }
        {
            let mut m = self.streams.lock().unwrap();
            if m.get(&peer).is_some_and(|x| same(x, &stream)) {
                m.remove(&peer);
            }
        }
        stream.close();
        r
    }

    // ---- federated typing (outbound half; the inbound half is in sender.rs)

    /// Send one federated typing signal. OFF is a silent no-op; every send is
    /// throttled per peer first; no database writes, ever.
    pub async fn send_typing(&self, ctx: &CancellationToken, ch: &TypingChannel) {
        if !self.flags.federation_enabled() {
            return;
        }
        if ch.room_id.is_empty() {
            self.send_ephemeral_to(
                &ch.peer_domain,
                encode_ephemeral_dm(&ch.local_user_email, &ch.remote_id),
            )
            .await;
        } else if !ch.peer_domain.is_empty() {
            self.send_ephemeral_to(&ch.peer_domain, encode_ephemeral("typing", &ch.room_id))
                .await;
        } else {
            self.fanout_ephemeral(
                ctx,
                &ch.room_id,
                "",
                &encode_ephemeral("typing", &ch.room_id),
            )
            .await;
        }
    }

    async fn relay_room_ephemeral(&self, ctx: &CancellationToken, origin: &str, payload: &[u8]) {
        // Only ever called with a room-shaped payload.
        let Some(room) = room_of(payload) else {
            return;
        };
        self.fanout_ephemeral(ctx, &room, origin, payload).await;
    }

    /// The active (non-left, non-parked) roster, origin excluded: a plain read,
    /// never `federation_enqueue`; ephemeral bypasses the outbox rail.
    async fn fanout_ephemeral(
        &self,
        _ctx: &CancellationToken,
        room_id: &str,
        exclude: &str,
        payload: &[u8],
    ) {
        let rows = match self
            .db
            .query(
                "SELECT member_domain FROM federation_room_members
		  WHERE room_id=$1 AND left_at IS NULL AND parked_at IS NULL AND member_domain <> $2",
                &[(&room_id, Type::TEXT), (&exclude, Type::TEXT)],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                self.log.warn(format!(
                    "federation: ephemeral roster read failed error={e}"
                ));
                return;
            }
        };
        let mut members = Vec::new();
        for r in rows {
            match r.try_get::<_, String>(0) {
                Ok(m) => members.push(m),
                Err(e) => {
                    self.log.warn(format!(
                        "federation: ephemeral roster scan failed error={e}"
                    ));
                    return;
                }
            }
        }
        for m in members {
            self.send_ephemeral_to(&m, payload.to_vec()).await;
        }
    }

    async fn send_ephemeral_to(&self, peer: &str, payload: Vec<u8>) {
        let bucket = {
            let mut m = self.ephemeral_out.lock().unwrap();
            m.entry(peer.to_string())
                .or_insert_with(|| Arc::new(TokenBucket::new(EPHEMERAL_BUCKET, EPHEMERAL_REFILL)))
                .clone()
        };
        if !bucket.allow() {
            return;
        }
        let sender = self.senders.lock().unwrap().get(peer).cloned();
        let Some(sender) = sender else {
            return;
        };
        if let Err(e) = sender.send_ephemeral(payload).await {
            self.log.warn(format!(
                "federation: send ephemeral failed peer={peer} error={e}"
            ));
        }
    }
}

fn room_of(payload: &[u8]) -> Option<String> {
    use crate::gojson;
    let members = gojson::object_members(payload).ok()??;
    let mut room = String::new();
    for m in members {
        if gojson::key_matches(&m.key, "roomId") {
            if let Ok(Some(s)) = gojson::field_string(m.value) {
                room = s;
            }
        }
    }
    if room.is_empty() {
        None
    } else {
        Some(room)
    }
}

/// One LISTEN connection per channel, reconnecting until `ctx` ends.
fn spawn_listener(
    ctx: CancellationToken,
    dsn: String,
    channel: String,
    log: Logger,
    on_notify: impl Fn() + Send + Sync + 'static,
) -> tokio::sync::oneshot::Receiver<()> {
    let (ready, first_attempt) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut ready = Some(ready);
        while !ctx.is_cancelled() {
            let connected = tokio::select! {
                _ = ctx.cancelled() => return,
                result = DirectListener::connect(&dsn, &channel) => result,
            };
            // Even a failed initial connection releases startup; the normal
            // reconnect loop and periodic reconcile remain available.
            if let Some(ready) = ready.take() {
                let _ = ready.send(());
            }
            match connected {
                Ok(mut l) => loop {
                    tokio::select! {
                        _ = ctx.cancelled() => return,
                        n = l.recv() => match n {
                            Some(_) => on_notify(),
                            None => break,
                        },
                    }
                },
                Err(e) => log.warn(format!("federation: subscribe {channel} failed error={e}")),
            }
            tokio::select! {
                _ = ctx.cancelled() => return,
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
    });
    first_attempt
}
