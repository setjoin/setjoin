//! Inbound `msg` frames for one peer domain. The reducers are the authority
//! (exactly-once, gap-fenced); this is the transport-side caller that picks
//! the reducer by content type and answers with the frame the stream must
//! write back: an ack (also for duplicates and poisoned frames, or the
//! sender's cursor would never advance) or a replay request on a gap.

use crate::{
    db::{is_code, FedDb, RawJsonb},
    error::FedError,
    flags::Flags,
    log::Logger,
    spam,
    wire::{self, Frame, MsgEnvelope, KIND_ACK, KIND_MSG, KIND_REPLAY_REQ},
};
use setjoin_pg::Type;
use std::sync::Arc;

/// Stamped on every federated-DM stanza by `chat_message_send`.
pub const CHAT_CONTENT_TYPE: &str = "application/x-setjoin-chat";
/// Federated-room stanzas (message and control ops).
pub const ROOM_CONTENT_TYPE: &str = "application/x-setjoin-room";
/// The scope-downgrade advisory; dispatched to the same room applier.
pub const ADVISORY_CONTENT_TYPE: &str = "application/x-setjoin-advisory";

pub struct Receiver {
    db: Arc<dyn FedDb>,
    flags: Arc<dyn Flags>,
    peer: String,
    log: Logger,
}

impl Receiver {
    pub fn new(db: Arc<dyn FedDb>, flags: Arc<dyn Flags>, peer: &str, log: Logger) -> Self {
        Receiver {
            db,
            flags,
            peer: peer.to_string(),
            log,
        }
    }

    fn ack(f: &Frame, seq: i64) -> Frame {
        Frame::new(KIND_ACK, &f.stanza_id, Some(wire::encode_seq(seq)))
    }

    /// Apply one inbound `msg` frame; the result is the frame to write back.
    pub async fn handle(&self, f: &Frame) -> Result<Frame, FedError> {
        if !self.flags.federation_enabled() {
            return Err(FedError::Disabled);
        }
        if f.kind != KIND_MSG {
            return Err(FedError::other(format!(
                "federation: receiver.Handle called with non-msg frame kind {:?}",
                f.kind
            )));
        }
        let env = MsgEnvelope::decode(f.payload.as_deref())
            .map_err(|e| FedError::other(format!("federation: unmarshal msg envelope: {e}")))?;
        let payload_len = env.payload.as_ref().map_or(0, Vec::len);

        // Go attempts the redacted stand-in for NUL stanzaId/contentType,
        // but still binds the original NUL text. PostgreSQL rejects the call
        // before bookkeeping, so the stream closes without an ack (parity).
        if f.stanza_id.contains('\0') || env.content_type.contains('\0') {
            self.log.warn(format!(
                "federation: frame carries NUL in stanzaId/contentType — consuming seq via redacted stand-in, then acking peer={} seq={} contentType={}",
                self.peer, env.peer_seq, env.content_type
            ));
            return self
                .apply_redacted(
                    f,
                    &env,
                    payload_len,
                    "apply inbound (NUL stanzaId/contentType redacted stand-in)",
                )
                .await;
        }

        if env.content_type == CHAT_CONTENT_TYPE {
            return self.handle_chat(f, &env).await;
        }
        if env.content_type == ROOM_CONTENT_TYPE || env.content_type == ADVISORY_CONTENT_TYPE {
            return self.handle_room(f, &env).await;
        }

        // Advisory-logged ingress gate: the verdict never changes the apply
        // (skipping would manufacture a gap the peer replays forever).
        match self.check_ingress(env.payload.as_deref()).await {
            Err(e) => self.log.warn(format!(
                "federation: ingress check failed (advisory only — apply proceeds) peer={} seq={} error={e}",
                self.peer, env.peer_seq
            )),
            Ok(v) if v != "ok" => self.log.warn(format!(
                "federation: ingress check flagged frame (advisory only — apply proceeds) peer={} seq={} verdict={v}",
                self.peer, env.peer_seq
            )),
            Ok(_) => {}
        }

        // THE FUNNEL: an unrecognised content type has no trust contract, so it
        // is consumed and acked but only a redacted, content-free envelope is
        // stored.
        self.log.warn(format!(
            "federation: unknown content_type — consumed, redacted, dropped peer={} seq={} contentType={}",
            self.peer, env.peer_seq, env.content_type
        ));
        match self.apply_redacted_applied(f, &env, payload_len).await {
            Ok(applied) => {
                if !applied {
                    self.log.info(format!(
                        "federation: inbound duplicate applied as no-op (still acking) peer={} seq={}",
                        self.peer, env.peer_seq
                    ));
                }
                Ok(Self::ack(f, env.peer_seq))
            }
            Err(e) => match self.handle_gap(&env, &e).await {
                Some(r) => r,
                None => Err(FedError::other(format!("federation: apply inbound: {e}"))),
            },
        }
    }

    /// `federation_apply_inbound` with the redacted stand-in; Ok(applied).
    async fn apply_redacted_applied(
        &self,
        f: &Frame,
        env: &MsgEnvelope,
        payload_len: usize,
    ) -> Result<bool, String> {
        let redacted = wire::encode_redacted(&env.content_type, payload_len);
        let rows = self
            .db
            .query(
                "SELECT federation_apply_inbound($1,$2,$3,$4,$5)",
                &[
                    (&self.peer, Type::TEXT),
                    (&env.peer_seq, Type::INT8),
                    (&f.stanza_id, Type::TEXT),
                    (&env.content_type, Type::TEXT),
                    (&RawJsonb(&redacted), Type::JSONB),
                ],
            )
            .await?;
        rows.first()
            .ok_or_else(|| "no rows".to_string())?
            .try_get::<_, bool>(0)
            .map_err(|e| e.to_string())
    }

    /// Consume the sequence through the stand-in and produce the ack (or the
    /// gap handling). `what` names the failure for the generic wrap.
    async fn apply_redacted(
        &self,
        f: &Frame,
        env: &MsgEnvelope,
        payload_len: usize,
        what: &str,
    ) -> Result<Frame, FedError> {
        match self.apply_redacted_applied(f, env, payload_len).await {
            Ok(_) => Ok(Self::ack(f, env.peer_seq)),
            Err(e) => match self.handle_gap(env, &e).await {
                Some(r) => r,
                None => Err(FedError::other(format!("federation: {what}: {e}"))),
            },
        }
    }

    async fn handle_chat(&self, f: &Frame, env: &MsgEnvelope) -> Result<Frame, FedError> {
        let payload_len = env.payload.as_ref().map_or(0, Vec::len);
        if !env
            .payload
            .as_deref()
            .is_none_or(spam::payload_safe_for_jsonb)
        {
            self.log.warn(format!(
                "federation: inbound chat frame carries NUL — undeliverable to the jsonb applier, poisoned and acked peer={} seq={}",
                self.peer, env.peer_seq
            ));
            return self
                .apply_redacted(f, env, payload_len, "apply chat (redacted NUL stand-in)")
                .await;
        }
        let (quarantined, reason) =
            spam::spam_scan_chat_body(&spam::decode_chat_body(env.payload.as_deref()));
        let reason_arg: Option<&str> = if reason.is_empty() {
            None
        } else {
            Some(&reason)
        };
        let payload = env.payload.as_deref().map(RawJsonb);
        let verdict = self
            .db
            .query(
                "SELECT federation_apply_chat($1,$2,$3,$4,$5,$6)",
                &[
                    (&self.peer, Type::TEXT),
                    (&env.peer_seq, Type::INT8),
                    (&f.stanza_id, Type::TEXT),
                    (&payload, Type::JSONB),
                    (&quarantined, Type::BOOL),
                    (&reason_arg, Type::TEXT),
                ],
            )
            .await;
        match verdict {
            Ok(rows) => {
                let v = self.verdict(&rows)?;
                self.log_apply_verdict(
                    "chat",
                    "federation_apply_chat",
                    &v,
                    env.peer_seq,
                    quarantined,
                    &reason,
                );
                Ok(Self::ack(f, env.peer_seq))
            }
            Err(e) => match self.handle_gap(env, &e).await {
                Some(r) => r,
                None => Err(FedError::other(format!("federation: apply chat: {e}"))),
            },
        }
    }

    async fn handle_room(&self, f: &Frame, env: &MsgEnvelope) -> Result<Frame, FedError> {
        let payload_len = env.payload.as_ref().map_or(0, Vec::len);
        if !env
            .payload
            .as_deref()
            .is_none_or(spam::payload_safe_for_jsonb)
        {
            self.log.warn(format!(
                "federation: inbound room frame carries NUL — undeliverable to the jsonb applier, poisoned and acked peer={} seq={}",
                self.peer, env.peer_seq
            ));
            return self
                .apply_redacted(f, env, payload_len, "apply room (redacted NUL stand-in)")
                .await;
        }
        let (mut quarantined, mut reason) = (false, String::new());
        if spam::decode_room_op(env.payload.as_deref()) == "message" {
            (quarantined, reason) =
                spam::spam_scan_chat_body(&spam::decode_chat_body(env.payload.as_deref()));
        }
        let reason_arg: Option<&str> = if reason.is_empty() {
            None
        } else {
            Some(&reason)
        };
        let payload = env.payload.as_deref().map(RawJsonb);
        let verdict = self
            .db
            .query(
                "SELECT federation_apply_room($1,$2,$3,$4,$5,$6,$7)",
                &[
                    (&self.peer, Type::TEXT),
                    (&env.peer_seq, Type::INT8),
                    (&f.stanza_id, Type::TEXT),
                    (&payload, Type::JSONB),
                    (&quarantined, Type::BOOL),
                    (&reason_arg, Type::TEXT),
                    (&env.content_type, Type::TEXT),
                ],
            )
            .await;
        match verdict {
            Ok(rows) => {
                let v = self.verdict(&rows)?;
                self.log_apply_verdict(
                    "room",
                    "federation_apply_room",
                    &v,
                    env.peer_seq,
                    quarantined,
                    &reason,
                );
                Ok(Self::ack(f, env.peer_seq))
            }
            Err(e) => match self.handle_gap(env, &e).await {
                Some(r) => r,
                None => Err(FedError::other(format!("federation: apply room: {e}"))),
            },
        }
    }

    fn verdict(&self, rows: &[setjoin_pg::Row]) -> Result<String, FedError> {
        rows.first()
            .ok_or_else(|| FedError::other("federation: apply: no rows"))?
            .try_get::<_, String>(0)
            .map_err(|e| FedError::other(format!("federation: apply: {e}")))
    }

    fn log_apply_verdict(
        &self,
        kind: &str,
        applier: &str,
        verdict: &str,
        seq: i64,
        quarantined: bool,
        reason: &str,
    ) {
        let peer = &self.peer;
        match verdict {
            "dup" => self.log.info(format!(
                "federation: inbound {kind} duplicate applied as no-op (still acking) peer={peer} seq={seq}"
            )),
            "poison" => self.log.warn(format!(
                "federation: inbound {kind} frame poisoned by trust validation — dropped, still acking peer={peer} seq={seq}"
            )),
            "applied" => {
                if quarantined {
                    self.log.warn(format!(
                        "federation: inbound {kind} message quarantined by spam scan — applied, flagged for review peer={peer} seq={seq} reason={reason}"
                    ));
                }
            }
            other => self.log.warn(format!(
                "federation: inbound {kind} unexpected verdict from {applier} peer={peer} seq={seq} verdict={other}"
            )),
        }
    }

    /// BZ202 (sequence gap) becomes a replay request naming the resume point;
    /// `None` when `err` is not a gap.
    async fn handle_gap(&self, env: &MsgEnvelope, err: &str) -> Option<Result<Frame, FedError>> {
        if !is_code(err, "BZ202") {
            return None;
        }
        let last = match self.last_applied_seq().await {
            Ok(l) => l,
            Err(e) => {
                return Some(Err(FedError::other(format!(
                    "federation: gap detected but failed to read last_applied_seq: {e}"
                ))))
            }
        };
        self.log.warn(format!(
            "federation: inbound sequence gap — requesting replay peer={} got_seq={} resume_from={}",
            self.peer,
            env.peer_seq,
            last + 1
        ));
        Some(Ok(Frame::new(
            KIND_REPLAY_REQ,
            "",
            Some(wire::encode_seq(last + 1)),
        )))
    }

    async fn check_ingress(&self, payload: Option<&[u8]>) -> Result<String, String> {
        let payload = payload.map(RawJsonb);
        let rows = self
            .db
            .query(
                "SELECT federation_ingress_check($1,$2)",
                &[(&self.peer, Type::TEXT), (&payload, Type::JSONB)],
            )
            .await?;
        rows.first()
            .ok_or_else(|| "no rows".to_string())?
            .try_get::<_, String>(0)
            .map_err(|e| e.to_string())
    }

    async fn last_applied_seq(&self) -> Result<i64, String> {
        let rows = self
            .db
            .query(
                "SELECT COALESCE((SELECT last_applied_seq FROM federation_inbox_cursor WHERE peer_domain = $1), 0)",
                &[(&self.peer, Type::TEXT)],
            )
            .await?;
        rows.first()
            .ok_or_else(|| "no rows".to_string())?
            .try_get::<_, i64>(0)
            .map_err(|e| e.to_string())
    }
}
