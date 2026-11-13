//! `push-intent-drain` (#408): frozen Go's `pushjobs.Worker`.
//!
//! One 3 s tick runs three drain legs in Go's order, then the reaps:
//! 1. mail push: claim one `push_intents` row (lease via `next_attempt_at`),
//!    `push_should_notify` gate, payload, device resolution, provider dispatch,
//!    then done / retry-with-backoff / failed;
//! 2. chat push: the same claim shape over `chat_push_intents`, fanned out to
//!    every notify-eligible channel member, always terminal-done after fan-out;
//! 3. guest digest: one per-guest transaction that renders pending
//!    `guest_notification_intents` into a system mail (object store plus
//!    `outbound_queue`) and stamps them, atomically.
//!
//! Both queues and `push_devices` are cross-tenant: worker credential only.
//! Device tokens are decrypted in SQL (`push_decrypt_token`) under the session
//! `app.encryption_key`, so the worker database must carry the audit keys.
//! Provider transports and capability-URL scrubbing live in `setjoin-push`.
use crate::{guest_mail, recovery_worker::ObjectStore};
use setjoin_pg::{
    workers::{WorkerConnection, WorkerDatabase},
    Row, Type,
};
use std::{future::Future, sync::Arc, time::Duration};

pub const NAME: &str = "push-intent-drain";
/// Go's `workerInterval`.
pub const INTERVAL: Duration = Duration::from_secs(3);
const MAX_ATTEMPTS: i32 = 5;
const LEASE_SECS: f64 = 120.0;
const DIGEST_SEND_TIMEOUT: Duration = Duration::from_secs(30);
/// Go's `chatReapAfter`: seven days.
const CHAT_REAP_SECS: f64 = 7.0 * 24.0 * 3600.0;
const UNREGISTERED: &str = "push: device token no longer registered";
const PUSH_INTENTS: &str = "push_intents";
const CHAT_INTENTS: &str = "chat_push_intents";

/// Non-database dependencies of the guest-digest leg (Go's `GuestDigestConfig`).
/// The object store carries the bucket; Go refuses to boot without one, so the
/// executable refuses too rather than running the leg inert.
pub struct GuestDigest {
    pub store: Arc<dyn ObjectStore>,
    pub from_addr: String,
    pub from_name: String,
    pub webmail_url: String,
}

pub struct PushIntentDrain {
    db: WorkerDatabase,
    providers: tokio::sync::Mutex<setjoin_push::Set>,
    digest: Option<GuestDigest>,
    connection: tokio::sync::Mutex<Option<WorkerConnection>>,
}

struct Device {
    id: i64,
    provider: String,
    token: String,
}

#[derive(Default)]
struct Outcome {
    any_success: bool,
    retryable: bool,
    last_err: String,
    prune: Vec<i64>,
}

fn warn(message: &str) {
    eprintln!("{message}");
}

impl PushIntentDrain {
    pub fn new(
        db: WorkerDatabase,
        providers: setjoin_push::Set,
        digest: Option<GuestDigest>,
    ) -> Self {
        Self {
            db,
            providers: tokio::sync::Mutex::new(providers),
            digest,
            connection: tokio::sync::Mutex::new(None),
        }
    }

    pub async fn run_until(self, stop: impl Future<Output = ()> + Send) {
        let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + INTERVAL, INTERVAL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(stop);
        loop {
            tokio::select! {biased; _ = &mut stop => return, _ = ticks.tick() => {}}
            tokio::select! {biased; _ = &mut stop => return, _ = self.tick() => {}}
        }
    }

    /// One tick. Any failure drops the session so the next tick reconnects.
    pub async fn tick(&self) {
        let mut slot = self.connection.lock().await;
        if slot.is_none() {
            match self.db.connect_session().await {
                Ok(connection) => *slot = Some(connection),
                Err(_) => {
                    warn("pushjobs: process failed");
                    return;
                }
            }
        }
        let conn = slot.as_ref().expect("connected above");
        let mut failed = false;
        loop {
            match self.process_one(conn).await {
                Ok(true) => {}
                Ok(false) => break,
                Err(_) => {
                    warn("pushjobs: process failed");
                    failed = true;
                    break;
                }
            }
        }
        // Chat drains after mail within one tick, as in Go.
        loop {
            match self.process_one_chat(conn).await {
                Ok(true) => {}
                Ok(false) => break,
                Err(_) => {
                    warn("pushjobs(chat): process failed");
                    failed = true;
                    break;
                }
            }
        }
        if conn
            .execute(
                "DELETE FROM chat_push_intents WHERE status IN ('done','failed') AND created_at < now() - make_interval(secs => $1)",
                &[(&CHAT_REAP_SECS, Type::FLOAT8)],
            )
            .await
            .is_err()
        {
            warn("pushjobs(chat): reap failed");
            failed = true;
        }
        loop {
            match self.drain_guest_digests(conn).await {
                Ok(true) => {}
                Ok(false) => break,
                Err(_) => {
                    warn("pushjobs(guest-digest): drain failed");
                    failed = true;
                    break;
                }
            }
        }
        if self.digest.is_some() {
            if conn
                .execute(
                    "DELETE FROM guest_notification_intents WHERE sent_at IS NOT NULL AND created_at < now()-interval '7 days'",
                    &[],
                )
                .await
                .is_err()
            {
                warn("pushjobs(guest-digest): reap sent failed");
                failed = true;
            }
            if conn
                .execute(
                    "UPDATE guest_notification_intents SET sent_at=now() WHERE sent_at IS NULL AND created_at < now()-interval '7 days'",
                    &[],
                )
                .await
                .is_err()
            {
                warn("pushjobs(guest-digest): reap stale failed");
                failed = true;
            }
        }
        if failed {
            *slot = None;
        }
    }

    // ---- shared claim / outcome statements -------------------------------

    async fn claim(
        &self,
        conn: &WorkerConnection,
        table: &'static str,
        returning: &'static str,
    ) -> Result<Option<Row>, String> {
        let sql = format!(
            "
		UPDATE {table}
		   SET attempts = attempts + 1,
		       next_attempt_at = now() + make_interval(secs => $1)
		 WHERE id = (
		   SELECT id FROM {table}
		    WHERE status = 'pending' AND next_attempt_at <= now()
		    ORDER BY next_attempt_at
		    FOR UPDATE SKIP LOCKED
		    LIMIT 1
		 )
		 RETURNING {returning}"
        );
        Ok(conn
            .query(&sql, &[(&LEASE_SECS, Type::FLOAT8)])
            .await?
            .into_iter()
            .next())
    }

    async fn mark_done(
        &self,
        conn: &WorkerConnection,
        table: &'static str,
        id: i64,
    ) -> Result<(), String> {
        conn.execute(
            &format!("UPDATE {table} SET status='done', next_attempt_at=now(), last_error=NULL WHERE id=$1"),
            &[(&id, Type::INT8)],
        )
        .await
        .map(|_| ())
    }

    /// Capped exponential backoff `min(1 min * 2^attempts, 1 h)`; failed once
    /// attempts are exhausted. `attempts` was already incremented by the claim.
    async fn retry_or_fail(
        &self,
        conn: &WorkerConnection,
        table: &'static str,
        id: i64,
        attempts: i32,
        message: &str,
    ) -> Result<(), String> {
        if attempts >= MAX_ATTEMPTS {
            return conn
                .execute(
                    &format!("UPDATE {table} SET status='failed', last_error=$2, next_attempt_at=now() WHERE id=$1"),
                    &[(&id, Type::INT8), (&message, Type::TEXT)],
                )
                .await
                .map(|_| ());
        }
        let backoff = (60u64 << attempts.clamp(1, 6)).min(3600) as f64;
        conn.execute(
            &format!("UPDATE {table} SET status='pending', next_attempt_at=now()+make_interval(secs => $2), last_error=$3 WHERE id=$1"),
            &[(&id, Type::INT8), (&backoff, Type::FLOAT8), (&message, Type::TEXT)],
        )
        .await
        .map(|_| ())
    }

    /// Go's `sharedpush.ResolveDevices`: unrevoked devices of one user, token
    /// decrypted in SQL; unreadable rows are skipped (counted, never logged
    /// with contents), empty tokens are dropped.
    async fn resolve_devices(
        &self,
        conn: &WorkerConnection,
        user: i64,
    ) -> Result<Vec<Device>, String> {
        let rows = conn
            .query(
                "
		SELECT id, push_provider, push_decrypt_token(push_token_enc)
		  FROM push_devices
		 WHERE user_id = $1 AND revoked_at IS NULL",
                &[(&user, Type::INT8)],
            )
            .await
            .map_err(|e| format!("resolve push devices: {e}"))?;
        let mut out = Vec::new();
        let mut undecryptable = 0;
        for row in rows {
            let (Ok(id), Ok(provider), Ok(token)) = (
                row.try_get::<_, i64>(0),
                row.try_get::<_, String>(1),
                row.try_get::<_, Option<String>>(2),
            ) else {
                undecryptable += 1;
                continue;
            };
            match token {
                None => undecryptable += 1,
                Some(token) if token.is_empty() => {}
                Some(token) => out.push(Device {
                    id,
                    provider,
                    token,
                }),
            }
        }
        if undecryptable > 0 {
            eprintln!("push: push_devices rows could not be decrypted; tokens skipped (user_id={user}, skipped_rows={undecryptable})");
        }
        Ok(out)
    }

    /// Dispatch to every device; a device whose provider is not configured is
    /// skipped, not an error (Go's `evalSends`).
    async fn eval_sends(&self, devices: &[Device], payload: &[u8]) -> Outcome {
        let mut outcome = Outcome::default();
        let mut providers = self.providers.lock().await;
        for device in devices {
            match providers
                .send(&device.provider, &device.token, payload)
                .await
            {
                None => {}
                Some(Ok(())) => outcome.any_success = true,
                Some(Err(error)) if error.ends_with(UNREGISTERED) => outcome.prune.push(device.id),
                Some(Err(error)) => {
                    outcome.retryable = true;
                    outcome.last_err = error;
                }
            }
        }
        outcome
    }

    // ---- mail leg --------------------------------------------------------

    async fn process_one(&self, conn: &WorkerConnection) -> Result<bool, String> {
        let Some(row) = self
            .claim(
                conn,
                PUSH_INTENTS,
                "id, mailbox_id, message_id, received_at::text, attempts",
            )
            .await?
        else {
            return Ok(false);
        };
        let id: i64 = row.get(0);
        let mailbox: i64 = row.get(1);
        let message: i64 = row.get(2);
        let received: String = row.get(3);
        let attempts: i32 = row.get(4);

        // Policy gate: a FALSE verdict is terminal-done, never a retry.
        let verdict = conn
            .query(
                "SELECT push_should_notify($1,$2,$3::timestamptz)",
                &[
                    (&mailbox, Type::INT8),
                    (&message, Type::INT8),
                    (&received, Type::TEXT),
                ],
            )
            .await;
        let notify = match verdict {
            Ok(rows) => rows.first().map(|r| r.get::<_, bool>(0)).unwrap_or(false),
            Err(error) => {
                self.retry_or_fail(conn, PUSH_INTENTS, id, attempts, &format!("gate: {error}"))
                    .await?;
                return Ok(true);
            }
        };
        if !notify {
            self.mark_done(conn, PUSH_INTENTS, id).await?;
            return Ok(true);
        }

        let (payload, user) = match self.build_payload(conn, mailbox, message, &received).await {
            Ok(Some(built)) => built,
            Ok(None) => {
                // Message/mailbox vanished: nothing to send.
                self.mark_done(conn, PUSH_INTENTS, id).await?;
                return Ok(true);
            }
            Err(error) => {
                self.retry_or_fail(
                    conn,
                    PUSH_INTENTS,
                    id,
                    attempts,
                    &format!("payload: {error}"),
                )
                .await?;
                return Ok(true);
            }
        };
        let devices = match self.resolve_devices(conn, user).await {
            Ok(devices) => devices,
            Err(error) => {
                self.retry_or_fail(
                    conn,
                    PUSH_INTENTS,
                    id,
                    attempts,
                    &format!("devices: {error}"),
                )
                .await?;
                return Ok(true);
            }
        };
        if devices.is_empty() {
            self.mark_done(conn, PUSH_INTENTS, id).await?;
            return Ok(true);
        }

        let outcome = self.eval_sends(&devices, payload.as_bytes()).await;
        for device in &outcome.prune {
            match conn
                .execute(
                    "UPDATE push_devices SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
                    &[(device, Type::INT8)],
                )
                .await
            {
                Ok(_) => eprintln!("pushjobs: pruned unregistered device (device_id={device})"),
                Err(_) => warn("pushjobs: prune failed"),
            }
        }
        if outcome.retryable {
            warn("pushjobs: send failed");
        }
        // One delivery (or an all-pruned/all-unmatched outcome) is terminal;
        // only all-failed-with-retryable-errors retries.
        if outcome.any_success || !outcome.retryable {
            self.mark_done(conn, PUSH_INTENTS, id).await?;
        } else {
            self.retry_or_fail(conn, PUSH_INTENTS, id, attempts, &outcome.last_err)
                .await?;
        }
        Ok(true)
    }

    /// The rich mail-push JSON and the recipient user; `None` when the message
    /// or mailbox no longer exists. Go marshals a map, so keys are sorted.
    async fn build_payload(
        &self,
        conn: &WorkerConnection,
        mailbox: i64,
        message: i64,
        received: &str,
    ) -> Result<Option<(String, i64)>, String> {
        let rows = conn
            .query(
                "
		SELECT COALESCE(m.from_addr,''), COALESCE(m.from_name,''), COALESCE(m.subject,''),
		       COALESCE(m.message_id,''), mb.email, mb.user_id
		  FROM messages m
		  JOIN mailboxes mb ON mb.id = m.mailbox_id
		 WHERE m.id = $1 AND m.received_at = $2::timestamptz AND m.mailbox_id = $3",
                &[
                    (&message, Type::INT8),
                    (&received, Type::TEXT),
                    (&mailbox, Type::INT8),
                ],
            )
            .await?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let (from_addr, from_name, subject, rfc_id, email) = (
            row.get::<_, String>(0),
            row.get::<_, String>(1),
            row.get::<_, String>(2),
            row.get::<_, String>(3),
            row.get::<_, String>(4),
        );
        let Some(user) = row.get::<_, Option<i64>>(5) else {
            return Ok(None);
        };
        let mut out = String::from("{\"actions\":[\"archive\",\"reply\"],\"mailbox\":");
        json_string(&mut out, &email);
        out.push_str(",\"messageId\":");
        json_string(&mut out, &rfc_id);
        out.push_str(",\"sender\":{\"email\":");
        json_string(&mut out, &from_addr);
        out.push_str(",\"name\":");
        json_string(&mut out, &from_name);
        out.push_str("},\"subject\":");
        json_string(&mut out, &subject);
        out.push_str(",\"type\":\"mail\"}");
        Ok(Some((out, user)))
    }

    // ---- chat leg --------------------------------------------------------

    async fn process_one_chat(&self, conn: &WorkerConnection) -> Result<bool, String> {
        let Some(row) = self
            .claim(
                conn,
                CHAT_INTENTS,
                "id, channel_id, message_id, sender_user_id, attempts",
            )
            .await?
        else {
            return Ok(false);
        };
        let id: i64 = row.get(0);
        let channel: i64 = row.get(1);
        let message: i64 = row.get(2);
        let sender: i64 = row.get(3);
        let attempts: i32 = row.get(4);

        let loaded = match self.load_chat_message(conn, message, channel).await {
            Ok(loaded) => loaded,
            Err(error) => {
                self.retry_or_fail(conn, CHAT_INTENTS, id, attempts, &format!("load: {error}"))
                    .await?;
                return Ok(true);
            }
        };
        let Some(mut meta) = loaded else {
            self.mark_done(conn, CHAT_INTENTS, id).await?;
            return Ok(true);
        };

        let newer = conn
            .query(
                "
		SELECT EXISTS (SELECT 1 FROM chat_push_intents WHERE channel_id=$1 AND status='pending' AND id>$2)",
                &[(&channel, Type::INT8), (&id, Type::INT8)],
            )
            .await;
        let newer_pending = match newer {
            Ok(rows) => rows.first().map(|r| r.get::<_, bool>(0)).unwrap_or(false),
            Err(error) => {
                self.retry_or_fail(
                    conn,
                    CHAT_INTENTS,
                    id,
                    attempts,
                    &format!("coalesce: {error}"),
                )
                .await?;
                return Ok(true);
            }
        };
        // An older intent is dropped when a newer one is pending for the
        // channel, unless the message was a broadcast or personally mentioned.
        if newer_pending && !meta.broadcast && meta.mentioned.is_empty() {
            self.mark_done(conn, CHAT_INTENTS, id).await?;
            return Ok(true);
        }

        let roster = match self.load_chat_roster(conn, channel).await {
            Ok(roster) => roster,
            Err(error) => {
                self.retry_or_fail(
                    conn,
                    CHAT_INTENTS,
                    id,
                    attempts,
                    &format!("roster: {error}"),
                )
                .await?;
                return Ok(true);
            }
        };
        if let Some(author) = roster.iter().find(|(user, _)| *user == sender) {
            meta.sender_name = author.1.clone();
        }

        // Fan-out starts here: from now on the intent is always terminal-done.
        let mut sends = Vec::new();
        for (user, _) in &roster {
            if *user == sender {
                continue;
            }
            let gate = conn
                .query(
                    "SELECT chat_push_should_notify($1,$2,$3)",
                    &[
                        (user, Type::INT8),
                        (&channel, Type::INT8),
                        (&message, Type::INT8),
                    ],
                )
                .await;
            match gate {
                Err(_) => {
                    warn("pushjobs(chat): gate failed");
                    continue;
                }
                Ok(rows) if !rows.first().map(|r| r.get::<_, bool>(0)).unwrap_or(false) => continue,
                Ok(_) => {}
            }
            let devices = match self.resolve_devices(conn, *user).await {
                Ok(devices) => devices,
                Err(_) => {
                    warn("pushjobs(chat): resolve devices failed");
                    continue;
                }
            };
            if devices.is_empty() {
                continue;
            }
            let mention = meta.broadcast || meta.mentioned.contains(user);
            let name = chat_channel_name(&meta, &roster, *user);
            sends.push((devices, chat_payload(&meta, &name, mention)));
        }
        for (devices, payload) in sends {
            let outcome = self.eval_sends(&devices, payload.as_bytes()).await;
            if !outcome.prune.is_empty() {
                // One batched revoke per fanout.
                if conn
                    .execute(
                        "UPDATE push_devices SET revoked_at = now()\n\t\t\t\t WHERE id = ANY($1::bigint[]) AND revoked_at IS NULL",
                        &[(&outcome.prune, Type::INT8_ARRAY)],
                    )
                    .await
                    .is_err()
                {
                    warn("pushjobs(chat): prune failed");
                }
            }
            if outcome.retryable {
                warn("pushjobs(chat): send failed");
            }
        }
        self.mark_done(conn, CHAT_INTENTS, id).await?;
        Ok(true)
    }

    async fn load_chat_message(
        &self,
        conn: &WorkerConnection,
        message: i64,
        channel: i64,
    ) -> Result<Option<ChatMeta>, String> {
        let rows = conn
            .query(
                "
		SELECT m.seq, (m.broadcast IS NOT NULL), c.kind, c.name
		  FROM chat_messages m
		  JOIN chat_channels c ON c.id = m.channel_id
		 WHERE m.id = $1 AND m.channel_id = $2",
                &[(&message, Type::INT8), (&channel, Type::INT8)],
            )
            .await?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let mut meta = ChatMeta {
            channel,
            message,
            seq: row.get(0),
            broadcast: row.get(1),
            kind: row.get(2),
            channel_name: row.get::<_, Option<String>>(3).unwrap_or_default(),
            sender_name: String::new(),
            mentioned: Vec::new(),
        };
        for row in conn
            .query(
                "SELECT mentioned_user_id FROM chat_mentions WHERE message_id = $1",
                &[(&message, Type::INT8)],
            )
            .await?
        {
            meta.mentioned.push(row.get(0));
        }
        Ok(Some(meta))
    }

    async fn load_chat_roster(
        &self,
        conn: &WorkerConnection,
        channel: i64,
    ) -> Result<Vec<(i64, String)>, String> {
        Ok(conn
            .query(
                "
		SELECT ccm.user_id, COALESCE(u.display_name, '')
		  FROM chat_channel_members ccm
		  JOIN users u ON u.id = ccm.user_id
		 WHERE ccm.channel_id = $1
		 ORDER BY ccm.user_id",
                &[(&channel, Type::INT8)],
            )
            .await?
            .into_iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect())
    }

    // ---- guest digest leg ------------------------------------------------

    /// At most one guest batch; `true` means a batch was sent or terminalized
    /// and another pass may help (active/throttled/locked guests are no
    /// progress, so they cannot spin the drain loop).
    async fn drain_guest_digests(&self, conn: &WorkerConnection) -> Result<bool, String> {
        let Some(digest) = &self.digest else {
            return Ok(false);
        };
        let window = self.digest_window(conn).await?;
        let guests = conn
            .query(
                "SELECT DISTINCT user_id FROM guest_notification_intents\n\t\t  WHERE sent_at IS NULL ORDER BY user_id",
                &[],
            )
            .await
            .map_err(|e| format!("guest-digest: list pending guests: {e}"))?;
        for guest in guests {
            let guest: i64 = guest.get(0);
            if self
                .process_guest_digest(conn, digest, guest, window)
                .await?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn digest_window(&self, conn: &WorkerConnection) -> Result<i32, String> {
        let rows = conn
            .query(
                "SELECT value #>> '{}' FROM system_config WHERE key='guest.digest_window_minutes'",
                &[],
            )
            .await
            .map_err(|e| format!("guest-digest: read digest window: {e}"))?;
        let Some(row) = rows.first() else {
            return Ok(15);
        };
        let raw: Option<String> = row.get(0);
        // Go's strconv.Atoi on the trimmed text; non-positive is refused.
        match raw.unwrap_or_default().trim().parse::<i32>() {
            Ok(minutes) if minutes > 0 => Ok(minutes),
            _ => Err("guest-digest: invalid digest window".into()),
        }
    }

    /// A transaction-scoped advisory lock covers status lookup through render,
    /// queue and stamp. The transaction deliberately spans the object-store
    /// write so the `outbound_queue` insert and the stamp commit together; the
    /// 30 s timeout bounds that network-I/O tradeoff (Go parity).
    async fn process_guest_digest(
        &self,
        conn: &WorkerConnection,
        digest: &GuestDigest,
        guest: i64,
        window: i32,
    ) -> Result<bool, String> {
        conn.batch("BEGIN")
            .await
            .map_err(|e| format!("guest-digest: begin guest transaction: {e}"))?;
        match self.guest_digest_body(conn, digest, guest, window).await {
            Ok((progress, committed)) => {
                if !committed {
                    let _ = conn.batch("ROLLBACK").await;
                }
                Ok(progress)
            }
            Err(error) => {
                let _ = conn.batch("ROLLBACK").await;
                Err(error)
            }
        }
    }

    /// `(progress, committed)`. Paths that return without a commit roll back.
    async fn guest_digest_body(
        &self,
        conn: &WorkerConnection,
        digest: &GuestDigest,
        guest: i64,
        window: i32,
    ) -> Result<(bool, bool), String> {
        let locked: bool = conn
            .query(
                "SELECT pg_try_advisory_xact_lock(hashtextextended('setjoin.pushjobs.guest_digest:' || ($1::bigint)::text, 0))",
                &[(&guest, Type::INT8)],
            )
            .await
            .map_err(|e| format!("guest-digest: acquire guest lock: {e}"))?
            .first()
            .map(|r| r.get(0))
            .unwrap_or(false);
        if !locked {
            return Ok((false, false));
        }

        let status = conn
            .query(
                "
		SELECT ga.status, ga.invited_email, u.enabled
		  FROM guest_accounts ga JOIN users u ON u.id=ga.user_id
		 WHERE ga.user_id=$1",
                &[(&guest, Type::INT8)],
            )
            .await
            .map_err(|e| format!("guest-digest: read guest status: {e}"))?;
        let (invited_email, usable) = match status.first() {
            None => (String::new(), false),
            Some(row) => (
                row.get::<_, String>(1),
                row.get::<_, String>(0) == "active" && row.get::<_, bool>(2),
            ),
        };
        if !usable {
            let progress = self.tombstone(conn, guest).await?;
            commit(conn).await?;
            return Ok((progress, true));
        }

        let active: bool = conn
            .query(
                "
		SELECT EXISTS (SELECT 1 FROM sessions
		 WHERE user_id=$1 AND last_seen_at > now()-interval '1 hour')",
                &[(&guest, Type::INT8)],
            )
            .await
            .map_err(|e| format!("guest-digest: check active session: {e}"))?
            .first()
            .map(|r| r.get(0))
            .unwrap_or(false);
        if active {
            return Ok((false, false));
        }
        let throttled: bool = conn
            .query(
                "
		SELECT EXISTS (SELECT 1 FROM guest_notification_intents
		 WHERE user_id=$1 AND sent_at > now()-make_interval(mins => $2))",
                &[(&guest, Type::INT8), (&window, Type::INT4)],
            )
            .await
            .map_err(|e| format!("guest-digest: check throttle: {e}"))?
            .first()
            .map(|r| r.get(0))
            .unwrap_or(false);
        if throttled {
            return Ok((false, false));
        }

        let batch = conn
            .query(
                "
		SELECT id,kind,ref FROM guest_notification_intents
		 WHERE user_id=$1 AND sent_at IS NULL
		 ORDER BY created_at,id LIMIT 50",
                &[(&guest, Type::INT8)],
            )
            .await
            .map_err(|e| format!("guest-digest: load batch: {e}"))?;
        if batch.is_empty() {
            return Ok((false, false));
        }
        let ids: Vec<i64> = batch.iter().map(|r| r.get(0)).collect();

        let org: String = conn
            .query(
                "
		SELECT COALESCE(NULLIF((SELECT value #>> '{}' FROM system_config WHERE key='org.name'),''),
		                'your organization')",
                &[],
            )
            .await
            .map_err(|e| format!("guest-digest: read organization name: {e}"))?
            .first()
            .map(|r| r.get(0))
            .unwrap_or_default();
        let mut lines = Vec::new();
        for row in &batch {
            let kind: String = row.get(1);
            let reference: String = row.get(2);
            let line = self.render_line(conn, guest, &kind, &reference).await?;
            if !line.is_empty() {
                lines.push(line);
            }
        }
        if lines.is_empty() {
            let progress = self.stamp(conn, guest, &ids).await?;
            commit(conn).await?;
            return Ok((progress, true));
        }

        let subject = if lines.len() > 1 {
            format!("{} new items in {org}", lines.len())
        } else {
            format!("New activity in {org}")
        };
        let body = format!(
            "{}\n\nThis message was sent because you have a guest account in {org}.\nLog in to view full content: {}\n",
            lines.join("\n"),
            digest.webmail_url
        );
        let send = async {
            // The sender error may contain message content; only this
            // sanitized result is reported and the batch stays pending.
            send_system_mail(
                conn,
                digest.store.as_ref(),
                "digest/",
                &digest.from_addr,
                &digest.from_name,
                &invited_email,
                &subject,
                &body,
            )
            .await
            .map_err(|_| "guest-digest: send failed".to_string())?;
            let progress = self.stamp(conn, guest, &ids).await?;
            commit(conn).await?;
            Ok::<_, String>((progress, true))
        };
        tokio::time::timeout(DIGEST_SEND_TIMEOUT, send)
            .await
            .map_err(|_| "guest-digest: send failed".to_string())?
    }

    async fn tombstone(&self, conn: &WorkerConnection, guest: i64) -> Result<bool, String> {
        conn.execute(
            "
		WITH batch AS (
		  SELECT id FROM guest_notification_intents
		   WHERE user_id=$1 AND sent_at IS NULL ORDER BY created_at,id LIMIT 50
		)
		UPDATE guest_notification_intents SET sent_at=now()
		 WHERE user_id=$1 AND sent_at IS NULL AND id IN (SELECT id FROM batch)",
            &[(&guest, Type::INT8)],
        )
        .await
        .map(|n| n > 0)
        .map_err(|e| format!("guest-digest: tombstone batch: {e}"))
    }

    async fn stamp(
        &self,
        conn: &WorkerConnection,
        guest: i64,
        ids: &[i64],
    ) -> Result<bool, String> {
        let ids = ids.to_vec();
        let changed = conn
            .execute(
                "
		UPDATE guest_notification_intents SET sent_at=now()
		 WHERE user_id=$1 AND sent_at IS NULL AND id=ANY($2)",
                &[(&guest, Type::INT8), (&ids, Type::INT8_ARRAY)],
            )
            .await
            .map_err(|e| format!("guest-digest: stamp batch: {e}"))?;
        if changed != ids.len() as u64 {
            return Err(format!(
                "guest-digest: stamp batch changed {changed} of {} rows",
                ids.len()
            ));
        }
        Ok(!ids.is_empty())
    }

    /// No line for malformed, deleted or foreign refs; a database error fails
    /// the batch closed.
    async fn render_line(
        &self,
        conn: &WorkerConnection,
        guest: i64,
        kind: &str,
        reference: &str,
    ) -> Result<String, String> {
        match kind {
            "mention" | "dm" => {
                let Some((channel, message)) = parse_chat_ref(reference) else {
                    return Ok(String::new());
                };
                let (sql, label) = if kind == "mention" {
                    (
                        "
			SELECT COALESCE(c.name,'conversation'),u.display_name,left(m.body,100)
			  FROM chat_messages m
			  JOIN chat_channels c ON c.id=m.channel_id
			  JOIN users u ON u.id=m.author_id
			  JOIN chat_mentions cm ON cm.message_id=m.id AND cm.mentioned_user_id=$3
			  JOIN chat_channel_members member ON member.channel_id=m.channel_id AND member.user_id=$3
			 WHERE m.id=$2 AND m.channel_id=$1 AND m.deleted_at IS NULL",
                        "mention",
                    )
                } else {
                    (
                        "
			SELECT u.display_name,left(m.body,100)
			  FROM chat_messages m
			  JOIN chat_channels c ON c.id=m.channel_id AND c.kind='dm'
			  JOIN users u ON u.id=m.author_id
			  JOIN chat_channel_members member ON member.channel_id=m.channel_id AND member.user_id=$3
			 WHERE m.id=$2 AND m.channel_id=$1 AND m.deleted_at IS NULL",
                        "dm",
                    )
                };
                let rows = conn
                    .query(
                        sql,
                        &[
                            (&channel, Type::INT8),
                            (&message, Type::INT8),
                            (&guest, Type::INT8),
                        ],
                    )
                    .await
                    .map_err(|e| format!("guest-digest: render {label}: {e}"))?;
                let Some(row) = rows.first() else {
                    return Ok(String::new());
                };
                if kind == "mention" {
                    Ok(format!(
                        "You were mentioned in #{} by {}: {}",
                        row.get::<_, String>(0),
                        row.get::<_, String>(1),
                        go_quote(&row.get::<_, String>(2))
                    ))
                } else {
                    Ok(format!(
                        "New message from {}: {}",
                        row.get::<_, String>(0),
                        go_quote(&row.get::<_, String>(1))
                    ))
                }
            }
            "meeting_invite" => {
                let Some(meeting) = go_parse_positive(reference) else {
                    return Ok(String::new());
                };
                let rows = conn
                    .query(
                        "
			SELECT m.title,COALESCE(to_char(m.scheduled_start AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI UTC'),'time not set')
			  FROM meetings m
			  JOIN chat_channel_members member ON member.channel_id=m.chat_channel_id AND member.user_id=$2
			 WHERE m.id=$1",
                        &[(&meeting, Type::INT8), (&guest, Type::INT8)],
                    )
                    .await
                    .map_err(|e| format!("guest-digest: render meeting: {e}"))?;
                let Some(row) = rows.first() else {
                    return Ok(String::new());
                };
                Ok(format!(
                    "New meeting: {} ({})",
                    row.get::<_, String>(0),
                    row.get::<_, String>(1)
                ))
            }
            _ => Ok(String::new()),
        }
    }
}

async fn commit(conn: &WorkerConnection) -> Result<(), String> {
    conn.batch("COMMIT")
        .await
        .map_err(|e| format!("guest-digest: commit guest transaction: {e}"))
}

// ---- chat helpers ----------------------------------------------------------

struct ChatMeta {
    channel: i64,
    message: i64,
    seq: i64,
    broadcast: bool,
    kind: String,
    channel_name: String,
    sender_name: String,
    mentioned: Vec<i64>,
}

/// The payload's channelName for one recipient: a channel's own name, empty
/// for a DM (the client renders "Direct message"), the other members' names
/// for a group DM.
fn chat_channel_name(meta: &ChatMeta, roster: &[(i64, String)], recipient: i64) -> String {
    match meta.kind.as_str() {
        "channel" => meta.channel_name.clone(),
        "dm" => String::new(),
        _ => roster
            .iter()
            .filter(|(user, name)| *user != recipient && !name.is_empty())
            .map(|(_, name)| name.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    }
}

/// No message body (payload privacy); `dedupeTag` is per channel. Keys sorted
/// like Go's map marshal.
fn chat_payload(meta: &ChatMeta, channel_name: &str, mention: bool) -> String {
    let mut out = format!("{{\"channelId\":{},\"channelName\":", meta.channel);
    json_string(&mut out, channel_name);
    out.push_str(&format!(
        ",\"dedupeTag\":\"chat-{}\",\"mention\":{mention},\"messageId\":{},\"sender\":",
        meta.channel, meta.message
    ));
    json_string(&mut out, &meta.sender_name);
    out.push_str(&format!(",\"seq\":{},\"type\":\"chat\"}}", meta.seq));
    out
}

/// Go's `strconv.ParseInt(s, 10, 64)` restricted to positive results.
fn go_parse_positive(value: &str) -> Option<i64> {
    let digits = value.strip_prefix('+').unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse::<i64>().ok().filter(|n| *n > 0)
}

fn parse_chat_ref(reference: &str) -> Option<(i64, i64)> {
    let (channel, message) = reference.split_once(':')?;
    Some((go_parse_positive(channel)?, go_parse_positive(message)?))
}

// ---- Go-compatible text encoders --------------------------------------------

/// `encoding/json` string encoding with HTML escaping on (the default).
fn json_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `fmt`'s `%q` (strconv.Quote). Printability follows `unicode.IsPrint`
/// closely: controls, non-ASCII spaces and common format characters escape.
fn go_quote(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            c if c == ' ' || (c.is_ascii() && !c.is_ascii_control()) => out.push(c),
            c if is_print(c) => out.push(c),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push('"');
    out
}

fn is_print(c: char) -> bool {
    !(c.is_control()
        || c.is_whitespace()
        || matches!(c as u32,
            0xad | 0x200b..=0x200f | 0x2028..=0x202e | 0x2060..=0x206f | 0xfeff | 0xfff9..=0xfffb
            | 0xe000..=0xf8ff | 0xfffe | 0xffff))
}

// ---- system mail (frozen Go `notify.SendSystemMail`) ----------------------

fn single_address(value: &str) -> bool {
    if value.contains(['\r', '\n']) {
        return false;
    }
    match mailparse::addrparse(value) {
        Ok(list) if list.len() == 1 => matches!(&list[0], mailparse::MailAddr::Single(info)
            if info.addr == value && info.display_name.is_none()),
        _ => false,
    }
}

fn message_nanos() -> Option<u64> {
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos() as u64;
    let mut previous = LAST.load(std::sync::atomic::Ordering::Relaxed);
    loop {
        let next = now.max(previous.checked_add(1)?);
        match LAST.compare_exchange_weak(
            previous,
            next,
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(_) => return Some(next),
            Err(actual) => previous = actual,
        }
    }
}

/// Render the single-part quoted-printable RFC 5322 message. Invalid input is
/// an error (Go's `validateSystemMailInput`).
fn build_system_mime(
    from_addr: &str,
    from_name: &str,
    to_addr: &str,
    subject: &str,
    body: &str,
    prefix: &str,
) -> Result<(String, String), String> {
    let normalize = |s: &str| {
        s.replace("\r\n", "\n")
            .replace('\r', "\n")
            .replace('\n', " ")
    };
    if !single_address(from_addr) || !single_address(to_addr) {
        return Err("invalid address".into());
    }
    if !matches!(prefix, "invite/" | "digest/") {
        return Err("invalid message-id prefix".into());
    }
    let from_name = normalize(from_name);
    let subject = normalize(subject);
    let from = if from_name.is_empty() {
        format!("<{from_addr}>")
    } else if from_name.is_ascii() {
        format!(
            "\"{}\" <{from_addr}>",
            from_name.replace('\\', "\\\\").replace('"', "\\\"")
        )
    } else {
        format!("{} <{from_addr}>", guest_mail::qencode(&from_name))
    };
    let domain = from_addr
        .split_once('@')
        .map(|(_, d)| d)
        .unwrap_or_default();
    let nanos = message_nanos().ok_or("clock")?;
    let message_id = format!("<{prefix}{nanos}@{domain}>");
    let crlf = body
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n");
    let raw = format!(
        "From: {from}\r\nTo: <{to_addr}>\r\nSubject: {}\r\nMessage-ID: {message_id}\r\nDate: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n{}",
        guest_mail::qencode(&subject),
        chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000"),
        guest_mail::quoted_printable(&(crlf + "\r\n")),
    );
    Ok((raw, message_id))
}

/// Store the message object, then queue it for asynchronous SMTP delivery in
/// the caller's transaction (so the queue row and the caller's stamp commit
/// together).
#[allow(clippy::too_many_arguments)]
async fn send_system_mail(
    conn: &WorkerConnection,
    store: &dyn ObjectStore,
    prefix: &str,
    from_addr: &str,
    from_name: &str,
    to_addr: &str,
    subject: &str,
    body: &str,
) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let (mime, message_id) =
        build_system_mime(from_addr, from_name, to_addr, subject, body, prefix)?;
    let key = format!("{prefix}{:x}.eml", Sha256::digest(mime.as_bytes()));
    if !guest_mail::put_retrying(store, &key, mime.as_bytes(), "message/rfc822").await {
        return Err("store blob".into());
    }
    let recipients = vec![to_addr.to_owned()];
    conn.execute(
        "INSERT INTO outbound_queue (message_id, from_addr, rcpt_addrs, raw_ref, status)\n\t\t VALUES ($1, $2, $3, $4, 'pending')",
        &[
            (&message_id, Type::TEXT),
            (&from_addr, Type::TEXT),
            (&recipients, Type::TEXT_ARRAY),
            (&key, Type::TEXT),
        ],
    )
    .await
    .map(|_| ())
    .map_err(|_| "enqueue".to_string())
}
