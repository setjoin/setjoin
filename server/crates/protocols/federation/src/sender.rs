//! One peer's stream driver: exactly one `Sender` per peer owns both
//! directions of the single stream. The drain loop writes `federation_outbox`
//! strictly in `peer_seq` order (a write failure halts the peer so the daemon
//! re-dials; a failed seq is never skipped); the read loop is the stream's
//! single reader and handles acks, replay requests, inbound messages and
//! ephemeral frames. Wakeups come from `wake()`; a 3 s ticker only covers a
//! lost wakeup. All authority (sequence assignment, apply, ack) is in the
//! reducers.

use crate::{
    db::{FedDb, JsonbText, RawJsonb},
    error::FedError,
    flags::Flags,
    gojson,
    log::Logger,
    receiver::Receiver,
    stream::PeerStream,
    wire::{
        self, Frame, MsgEnvelope, KIND_ACK, KIND_EPHEMERAL, KIND_HELLO, KIND_MSG, KIND_RECEIPT,
        KIND_REPLAY_REQ,
    },
};
use setjoin_pg::Type;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// How far the sender may run ahead of durable acks.
pub const DEFAULT_WINDOW: i64 = 256;
/// Honoured replay requests: a burst of 5, then 1/s.
const REPLAY_BUCKET: f64 = 5.0;
const REPLAY_REFILL: f64 = 1.0;
/// Typing tokens (both directions): ~5, refill 1/s.
pub const EPHEMERAL_BUCKET: f64 = 5.0;
pub const EPHEMERAL_REFILL: f64 = 1.0;
/// Bound on an ephemeral wire write.
const EPHEMERAL_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// A tiny in-memory token bucket for loss-tolerant traffic.
pub struct TokenBucket {
    inner: Mutex<(f64, Instant)>,
    max: f64,
    refill: f64,
}

impl TokenBucket {
    pub fn new(max: f64, refill_per_sec: f64) -> Self {
        TokenBucket {
            inner: Mutex::new((max, Instant::now())),
            max,
            refill: refill_per_sec,
        }
    }
    pub fn allow(&self) -> bool {
        let mut g = self.inner.lock().unwrap();
        let now = Instant::now();
        g.0 += now.duration_since(g.1).as_secs_f64() * self.refill;
        if g.0 > self.max {
            g.0 = self.max;
        }
        g.1 = now;
        if g.0 < 1.0 {
            return false;
        }
        g.0 -= 1.0;
        true
    }
}

/// Hub-room relay hook: (origin peer, minimal payload).
pub type RelayEphemeral = Arc<dyn Fn(String, Vec<u8>) + Send + Sync>;

struct Cursors {
    /// Highest seq written to THIS stream.
    sent: i64,
    /// Highest seq the peer durably acked (mirror of federation_peers.last_acked_seq).
    acked: i64,
}

pub struct Sender {
    db: Arc<dyn FedDb>,
    flags: Arc<dyn Flags>,
    peer: String,
    stream: Arc<PeerStream>,
    receiver: Receiver,
    log: Logger,
    window: i64,
    cursors: Mutex<Cursors>,
    wake: Notify,
    ephemeral_in: TokenBucket,
    replay_in: TokenBucket,
    relay_ephemeral: Mutex<Option<RelayEphemeral>>,
}

fn pg<T>(r: Result<T, String>) -> Result<T, FedError> {
    r.map_err(FedError::Other)
}

impl Sender {
    pub fn new(
        db: Arc<dyn FedDb>,
        flags: Arc<dyn Flags>,
        peer: &str,
        stream: Arc<PeerStream>,
        receiver: Receiver,
        log: Logger,
    ) -> Arc<Self> {
        Arc::new(Sender {
            db,
            flags,
            peer: peer.to_string(),
            stream,
            receiver,
            log,
            window: DEFAULT_WINDOW,
            cursors: Mutex::new(Cursors { sent: 0, acked: 0 }),
            wake: Notify::new(),
            ephemeral_in: TokenBucket::new(EPHEMERAL_BUCKET, EPHEMERAL_REFILL),
            replay_in: TokenBucket::new(REPLAY_BUCKET, REPLAY_REFILL),
            relay_ephemeral: Mutex::new(None),
        })
    }

    pub fn set_relay_ephemeral(&self, hook: RelayEphemeral) {
        *self.relay_ephemeral.lock().unwrap() = Some(hook);
    }

    /// Non-blocking, coalescing: "check the cursor".
    pub fn wake(&self) {
        self.wake.notify_one();
    }

    /// Drive the peer until `ctx` ends or the stream breaks (the error makes
    /// the daemon re-dial). A no-op error while feature.federation is OFF.
    pub async fn run(self: Arc<Self>, ctx: CancellationToken) -> Result<(), FedError> {
        if !self.flags.federation_enabled() {
            return Err(FedError::Disabled);
        }
        self.init_cursors().await.map_err(|e| {
            FedError::other(format!("federation: init cursors for {}: {e}", self.peer))
        })?;

        let reader = {
            let s = self.clone();
            let ctx = ctx.clone();
            tokio::spawn(async move { s.read_loop(ctx).await })
        };
        let result = self.clone().drive(&ctx, reader).await;
        result
    }

    async fn drive(
        self: Arc<Self>,
        ctx: &CancellationToken,
        mut reader: tokio::task::JoinHandle<Result<(), FedError>>,
    ) -> Result<(), FedError> {
        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(3),
            Duration::from_secs(3),
        );
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        self.wake();
        let out = loop {
            tokio::select! {
                _ = ctx.cancelled() => break Err(FedError::other("context canceled")),
                r = &mut reader => {
                    break match r {
                        Ok(r) => r,
                        Err(e) => Err(FedError::other(format!("federation: read loop: {e}"))),
                    };
                }
                _ = ticker.tick() => {
                    if let Err(e) = self.drain().await { break Err(e); }
                }
                _ = self.wake.notified() => {
                    if let Err(e) = self.drain().await { break Err(e); }
                }
            }
        };
        reader.abort();
        out
    }

    /// Reset the cursors to the durable `last_acked_seq`: the reconnect-resume.
    async fn init_cursors(&self) -> Result<(), String> {
        let rows = self
            .db
            .query(
                "SELECT COALESCE((SELECT last_acked_seq FROM federation_peers WHERE peer_domain=$1),0)",
                &[(&self.peer, Type::TEXT)],
            )
            .await?;
        let acked: i64 = rows
            .first()
            .ok_or("no rows")?
            .try_get(0)
            .map_err(|e| e.to_string())?;
        let mut c = self.cursors.lock().unwrap();
        c.sent = acked;
        c.acked = acked;
        Ok(())
    }

    async fn send(&self, f: &Frame) -> Result<(), FedError> {
        self.stream
            .write_frame(f)
            .await
            .map_err(|e| FedError::other(e.to_string()))
    }

    /// Write every outbox row past the send cursor, in seq order, up to the
    /// in-flight window, halting on the first write failure.
    async fn drain(&self) -> Result<(), FedError> {
        loop {
            let (low, limit) = {
                let c = self.cursors.lock().unwrap();
                (c.sent, self.window - (c.sent - c.acked))
            };
            if limit <= 0 {
                return Ok(()); // window full: an ack wakes us
            }
            let rows = pg(self
                .db
                .query(
                    "SELECT peer_seq, stanza_id, content_type, payload
			   FROM federation_outbox
			  WHERE peer_domain=$1 AND peer_seq > $2
			  ORDER BY peer_seq
			  LIMIT $3",
                    &[
                        (&self.peer, Type::TEXT),
                        (&low, Type::INT8),
                        (&limit, Type::INT8),
                    ],
                )
                .await)?;
            if rows.is_empty() {
                return Ok(());
            }
            for row in rows {
                let seq: i64 = row.try_get(0).map_err(|e| FedError::other(e.to_string()))?;
                let stanza: String = row.try_get(1).map_err(|e| FedError::other(e.to_string()))?;
                let ct: String = row.try_get(2).map_err(|e| FedError::other(e.to_string()))?;
                let payload: Option<JsonbText> =
                    row.try_get(3).map_err(|e| FedError::other(e.to_string()))?;
                let env = MsgEnvelope {
                    peer_seq: seq,
                    content_type: ct,
                    payload: payload.map(|p| p.0),
                };
                let f = Frame::new(KIND_MSG, &stanza, Some(env.encode()));
                self.send(&f).await?; // sent cursor NOT advanced on failure
                self.cursors.lock().unwrap().sent = seq;
            }
        }
    }

    /// The single reader of the stream.
    async fn read_loop(self: Arc<Self>, ctx: CancellationToken) -> Result<(), FedError> {
        loop {
            let f = self.stream.read_frame().await.map_err(|e| {
                FedError::other(format!("federation: read from {}: {e}", self.peer))
            })?;
            match f.kind.as_str() {
                KIND_ACK | KIND_RECEIPT => {
                    let seq = wire::decode_seq(f.payload.as_deref()).map_err(|e| {
                        FedError::other(format!(
                            "federation: unmarshal ack from {}: {e}",
                            self.peer
                        ))
                    })?;
                    self.apply_ack(seq).await?;
                    self.wake();
                }
                KIND_REPLAY_REQ => {
                    let seq = wire::decode_seq(f.payload.as_deref()).map_err(|e| {
                        FedError::other(format!(
                            "federation: unmarshal replay_req from {}: {e}",
                            self.peer
                        ))
                    })?;
                    if self.apply_replay_req(seq)? {
                        self.wake();
                    }
                }
                KIND_MSG => {
                    let resp = self.receiver.handle(&f).await.map_err(|e| {
                        FedError::other(format!(
                            "federation: handle inbound from {}: {e}",
                            self.peer
                        ))
                    })?;
                    self.send(&resp).await?;
                }
                // A reconnect hello's ResumeFromSeq is honoured at dial time.
                KIND_HELLO => {}
                KIND_EPHEMERAL => self.handle_ephemeral(&ctx, &f).await,
                other => self.log.warn(format!(
                    "federation: unknown frame kind peer={} kind={other:?}",
                    self.peer
                )),
            }
        }
    }

    /// A forged future ack would mark unsent rows acked and lose them on the
    /// next reconnect, so it is a protocol violation that halts the peer; the
    /// guard runs before the database is touched.
    async fn apply_ack(&self, peer_seq: i64) -> Result<(), FedError> {
        let sent = self.cursors.lock().unwrap().sent;
        if peer_seq < 0 || peer_seq > sent {
            return Err(FedError::other(format!(
                "federation: forged ack {peer_seq} from {}: beyond highest sent seq {sent} — stream halted",
                self.peer
            )));
        }
        self.db
            .query(
                "SELECT federation_ack($1,$2)",
                &[(&self.peer, Type::TEXT), (&peer_seq, Type::INT8)],
            )
            .await
            .map_err(|e| {
                FedError::other(format!("federation: ack {peer_seq} for {}: {e}", self.peer))
            })?;
        let mut c = self.cursors.lock().unwrap();
        if peer_seq > c.acked {
            c.acked = peer_seq;
        }
        Ok(())
    }

    /// Validate one replay request; true when the send cursor actually moved.
    /// A resume point beyond the send cursor is a forge (halts the peer); a
    /// rewind behind the durable ack is clamped; honoured rewinds are
    /// rate-capped so replay cannot amplify the retained outbox.
    pub fn apply_replay_req(&self, peer_seq: i64) -> Result<bool, FedError> {
        let sent = self.cursors.lock().unwrap().sent;
        if peer_seq < 0 || peer_seq - 1 > sent {
            return Err(FedError::other(format!(
                "federation: forged replay_req {peer_seq} from {}: beyond highest sent seq {sent} — stream halted",
                self.peer
            )));
        }
        if !self.replay_in.allow() {
            self.log.debug(format!(
                "federation: inbound replay throttled peer={}",
                self.peer
            ));
            return Ok(false);
        }
        let mut rewound = false;
        {
            let mut c = self.cursors.lock().unwrap();
            let mut resume = peer_seq - 1;
            if resume < c.acked {
                resume = c.acked;
            }
            if resume < c.sent {
                c.sent = resume;
                rewound = true;
            }
        }
        if rewound {
            self.log.warn(format!(
                "federation: peer requested replay peer={} resume_from={peer_seq}",
                self.peer
            ));
        }
        Ok(rewound)
    }

    /// Write a typing frame: no seq, no outbox row, no ack. Dropped (Ok) when
    /// the stream is busy or the write stalls, so it can never delay the
    /// ordered rail.
    pub async fn send_ephemeral(&self, payload: Vec<u8>) -> Result<(), FedError> {
        let f = Frame::new(KIND_EPHEMERAL, "", Some(payload));
        self.stream
            .try_write_frame(&f, EPHEMERAL_WRITE_TIMEOUT)
            .await
            .map(|_| ())
            .map_err(|e| FedError::other(e.to_string()))
    }

    /// Apply one inbound ephemeral frame. Never logs payload or addresses.
    async fn handle_ephemeral(&self, _ctx: &CancellationToken, f: &Frame) {
        if !self.flags.federation_enabled() {
            return;
        }
        // Throttle before any database round trip.
        if !self.ephemeral_in.allow() {
            self.log.debug(format!(
                "federation: inbound ephemeral throttled peer={}",
                self.peer
            ));
            return;
        }
        let Some(payload) = f.payload.as_deref() else {
            self.log.debug(format!(
                "federation: inbound ephemeral unmarshal failed — dropped peer={}",
                self.peer
            ));
            return;
        };
        let (op, room_id) = match decode_ephemeral(payload) {
            Ok(v) => v,
            Err(_) => {
                self.log.debug(format!(
                    "federation: inbound ephemeral unmarshal failed — dropped peer={}",
                    self.peer
                ));
                return;
            }
        };
        if op != "typing" {
            self.log.debug(format!(
                "federation: inbound ephemeral non-typing op dropped peer={}",
                self.peer
            ));
            return;
        }
        let jp = Some(RawJsonb(payload));
        let rows = match self
            .db
            .query(
                "SELECT federation_typing_notify($1,$2)",
                &[(&self.peer, Type::TEXT), (&jp, Type::JSONB)],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                self.log.warn(format!(
                    "federation: federation_typing_notify failed peer={} error={e}",
                    self.peer
                ));
                return;
            }
        };
        let verdict = rows
            .first()
            .and_then(|r| r.try_get::<_, JsonbText>(0).ok())
            .and_then(|j| decode_verdict(&j.0));
        let Some((ok, relay)) = verdict else {
            self.log.warn(format!(
                "federation: federation_typing_notify returned unparseable verdict peer={}",
                self.peer
            ));
            return;
        };
        if !ok {
            return; // untrusted/unresolvable: silently dropped
        }
        let hook = self.relay_ephemeral.lock().unwrap().clone();
        if relay {
            if let Some(h) = hook {
                // Rebuilt from the validated roomId only, never forwarded verbatim.
                h(self.peer.clone(), encode_ephemeral("typing", &room_id));
            }
        }
    }
}

/// `{"op":..,"roomId":..,"fromAddr":..,"toAddr":..}` (Go: `ephemeralPayload`).
fn decode_ephemeral(payload: &[u8]) -> Result<(String, String), gojson::JsonError> {
    let (mut op, mut room) = (String::new(), String::new());
    let mut first_err = None;
    if let Some(members) = gojson::object_members(payload)? {
        for m in members {
            let target = if gojson::key_matches(&m.key, "op") {
                Some(&mut op)
            } else if gojson::key_matches(&m.key, "roomId") {
                Some(&mut room)
            } else {
                None
            };
            if let Some(t) = target {
                match gojson::field_string(m.value) {
                    Ok(Some(s)) => *t = s,
                    Ok(None) => {}
                    Err(e) => first_err = first_err.or(Some(e)),
                }
            }
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok((op, room)),
    }
}

pub fn encode_ephemeral(op: &str, room_id: &str) -> Vec<u8> {
    let mut o = b"{\"op\":".to_vec();
    gojson::push_string(&mut o, op);
    if !room_id.is_empty() {
        o.extend_from_slice(b",\"roomId\":");
        gojson::push_string(&mut o, room_id);
    }
    o.push(b'}');
    o
}

/// A DM typing payload (`fromAddr`, `toAddr`).
pub fn encode_ephemeral_dm(from_addr: &str, to_addr: &str) -> Vec<u8> {
    let mut o = b"{\"op\":\"typing\"".to_vec();
    if !from_addr.is_empty() {
        o.extend_from_slice(b",\"fromAddr\":");
        gojson::push_string(&mut o, from_addr);
    }
    if !to_addr.is_empty() {
        o.extend_from_slice(b",\"toAddr\":");
        gojson::push_string(&mut o, to_addr);
    }
    o.push(b'}');
    o
}

fn decode_verdict(raw: &[u8]) -> Option<(bool, bool)> {
    let members = gojson::object_members(raw).ok()??;
    let (mut ok, mut relay) = (false, false);
    for m in members {
        if gojson::key_matches(&m.key, "ok") {
            ok = gojson::field_bool(m.value).ok()?.unwrap_or(ok);
        } else if gojson::key_matches(&m.key, "relay") {
            relay = gojson::field_bool(m.value).ok()?.unwrap_or(relay);
        }
    }
    Some((ok, relay))
}
