//! Frozen Go spam collector/flush loop. Models stay in F06; storage and DB
//! credentials come from the gateway's existing infrastructure adapters.
use crate::{mail_security_input::SpamTrain, recovery_worker::S3Store};
use setjoin_mail_security::spam_model::Model;
use setjoin_pg::{
    workers::{WorkerConnection, WorkerDatabase},
    Type,
};
use std::{collections::HashMap, future::Future, time::Duration};

pub const NAME: &str = "spam-trainer";
pub const CHANNEL: &str = "spam_train";
pub const MAX_BATCH: usize = 100;
pub const MAX_MESSAGE_BYTES: usize = 150 << 20;
pub const INTERVAL: Duration = Duration::from_secs(30);
pub const MAX_QUEUE: usize = 1000;

pub struct SpamTrainer {
    db: WorkerDatabase,
    store: Option<S3Store>,
    pending: HashMap<i64, SpamTrain>,
}

fn warn(what: &str, error: impl std::fmt::Display) {
    eprintln!("spam trainer: {what}: {error}");
}

impl SpamTrainer {
    pub fn new(db: WorkerDatabase, store: Option<S3Store>) -> Self {
        Self {
            db,
            store,
            pending: HashMap::new(),
        }
    }

    /// Go's bounded notification queue and 30-second flush loop. The listener
    /// stays live during DB/S3 waits; cancellation owns and drops both futures.
    pub async fn run_until(mut self, direct_dsn: String, stop: impl Future<Output = ()> + Send) {
        let (send, mut receive) = tokio::sync::mpsc::channel::<SpamTrain>(MAX_QUEUE);
        let listen = async move {
            let mut backoff = Duration::from_secs(1);
            loop {
                let connection = tokio::time::timeout(
                    Duration::from_secs(2),
                    setjoin_pg::workers::DirectListener::connect(&direct_dsn, CHANNEL),
                )
                .await;
                let mut listener = match connection {
                    Ok(Ok(listener)) => listener,
                    _ => {
                        warn("direct LISTEN unavailable; retrying", NAME);
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(INTERVAL);
                        continue;
                    }
                };
                backoff = Duration::from_secs(1);
                while let Some(notification) = listener.recv().await {
                    match serde_json::from_str::<SpamTrain>(notification.payload()) {
                        Ok(event) => {
                            if send.try_send(event).is_err() {
                                warn("event queue full; dropping event", NAME);
                            }
                        }
                        Err(e) => warn("invalid notification", e),
                    }
                }
                let _ = listener.close().await;
                tokio::time::sleep(backoff).await;
            }
        };
        let train = async move {
            let mut ticker =
                tokio::time::interval_at(tokio::time::Instant::now() + INTERVAL, INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    event = receive.recv() => match event {
                        Some(event) => self.collect(event),
                        None => return,
                    },
                    _ = ticker.tick() => self.tick().await,
                }
            }
        };
        tokio::pin!(stop);
        tokio::select! {
            biased;
            _ = &mut stop => {},
            _ = async { tokio::join!(listen, train); } => {},
        }
    }

    /// The production NOTIFY callback, also driven directly by the tick oracle.
    pub fn on_notification(&mut self, payload: &str) {
        match serde_json::from_str::<SpamTrain>(payload) {
            Ok(event) => self.collect(event),
            Err(error) => warn("invalid notification", error),
        }
    }

    fn collect(&mut self, event: SpamTrain) {
        if self
            .pending
            .get(&event.message_id)
            .is_some_and(|old| old.is_spam != event.is_spam)
        {
            self.pending.remove(&event.message_id);
        } else {
            self.pending.insert(event.message_id, event);
        }
    }

    /// One real collector flush. Overflow stays pending; every flushed event is
    /// dropped after a disabled/corrupt load, failed fetch or refused save, as Go.
    pub async fn tick(&mut self) {
        let ids: Vec<_> = self.pending.keys().take(MAX_BATCH).copied().collect();
        if ids.is_empty() {
            return;
        }
        let mut users: HashMap<i64, Vec<SpamTrain>> = HashMap::new();
        for id in ids {
            let event = self.pending.remove(&id).expect("pending key");
            users.entry(event.user_id).or_default().push(event);
        }
        let connection = match self.db.connect_session().await {
            Ok(c) => c,
            Err(e) => return warn("connect failed", e),
        };
        for (user, events) in users {
            let (mut model, expect) = match load(&connection, user).await {
                Ok(Some(model)) => model,
                Ok(None) => continue,
                Err(e) => {
                    warn("load failed", e);
                    continue;
                }
            };
            let mut trained = 0;
            for event in events {
                match self.fetch(&connection, user, event.message_id).await {
                    Ok(raw) => {
                        model.train(&raw, event.is_spam);
                        trained += 1;
                    }
                    Err(e) => warn("fetch failed", e),
                }
            }
            if trained == 0 {
                continue;
            }
            let bytes = model.save();
            // Each Go SaveModel transaction is exactly one statement. Snapshot
            // CAS and disabled checks are in that write, never a check-then-write.
            let saved = if expect.is_empty() {
                connection.execute(
                    "INSERT INTO user_spam_model (user_id, model_bytes, sample_count, trained_at) \
                     VALUES ($1, $2, 1, now()) \
                     ON CONFLICT (user_id) DO UPDATE SET \
                       model_bytes = EXCLUDED.model_bytes, \
                       sample_count = EXCLUDED.sample_count, trained_at = now() \
                     WHERE user_spam_model.disabled = FALSE \
                       AND octet_length(user_spam_model.model_bytes) = 0",
                    &[(&user, Type::INT8), (&bytes, Type::BYTEA)],
                ).await
            } else {
                connection
                    .execute(
                        "UPDATE user_spam_model \
                     SET model_bytes = $2, sample_count = sample_count + 1, trained_at = now() \
                     WHERE user_id = $1 AND disabled = FALSE AND model_bytes = $3",
                        &[
                            (&user, Type::INT8),
                            (&bytes, Type::BYTEA),
                            (&expect, Type::BYTEA),
                        ],
                    )
                    .await
            };
            match saved {
                Ok(0) => warn("save fenced; batch dropped", user),
                Ok(_) => eprintln!("spam trainer: model updated user_id={user} trained={trained}"),
                Err(e) => warn("persist failed", e),
            }
        }
    }

    async fn fetch(
        &self,
        c: &WorkerConnection,
        user: i64,
        message: i64,
    ) -> Result<Vec<u8>, String> {
        let rows = c
            .query(
                "SELECT m.raw_ref FROM messages m \
             JOIN mailboxes mb ON mb.id = m.mailbox_id \
             WHERE m.id = $1 AND mb.user_id = $2",
                &[(&message, Type::INT8), (&user, Type::INT8)],
            )
            .await?;
        let row = rows.first().ok_or("message not owned by training user")?;
        let raw: String = row.try_get(0).map_err(|e| e.to_string())?;
        if raw.contains(['\r', '\n']) {
            return Ok(raw.into_bytes());
        }
        let mut response = self
            .store
            .as_ref()
            .ok_or("no object store configured")?
            .blob_object(&raw)
            .await?;
        if !matches!(response.status().as_u16(), 200 | 206) {
            return Err("unexpected GetObject status".into());
        }
        let modified = response
            .headers()
            .get("last-modified")
            .and_then(|h| h.to_str().ok())
            .ok_or("missing Last-Modified")?;
        if !valid_object_date(modified) {
            return Err("invalid Last-Modified".into());
        }
        let mut bytes = Vec::with_capacity(4 << 20);
        while bytes.len() < MAX_MESSAGE_BYTES {
            let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? else {
                break;
            };
            bytes.extend_from_slice(&chunk[..chunk.len().min(MAX_MESSAGE_BYTES - bytes.len())]);
        }
        Ok(bytes)
    }
}

/// MinIO's three Go time.Parse layouts: variable/padded day, two/four digit
/// year, literal GMT. Normalize their fields into the existing Go HTTP-time
/// parser so weekday mismatches and fractional seconds keep Go's behavior.
fn valid_object_date(value: &str) -> bool {
    let parts: Vec<_> = value.split(' ').filter(|s| !s.is_empty()).collect();
    if parts.len() != 6
        || parts[5] != "GMT"
        || parts[0].len() != 4
        || !parts[0].ends_with(',')
        || !(1..=2).contains(&parts[1].len())
        || !parts[1].bytes().all(|b| b.is_ascii_digit())
        || !matches!(parts[3].len(), 2 | 4)
        || !parts[3].bytes().all(|b| b.is_ascii_digit())
    {
        return false;
    }
    let Ok(day) = parts[1].parse::<u32>() else {
        return false;
    };
    let Ok(mut year) = parts[3].parse::<u32>() else {
        return false;
    };
    if parts[3].len() == 2 {
        year += if year >= 69 { 1900 } else { 2000 };
    }
    let canonical = format!(
        "{} {day:02} {} {year:04} {} GMT",
        parts[0], parts[2], parts[4]
    );
    setjoin_mime::parse_http_time(canonical.as_bytes()).is_some()
}

async fn load(c: &WorkerConnection, user: i64) -> Result<Option<(Model, Vec<u8>)>, String> {
    let rows = c
        .query(
            "SELECT model_bytes, disabled FROM user_spam_model WHERE user_id = $1",
            &[(&user, Type::INT8)],
        )
        .await?;
    let Some(row) = rows.first() else {
        return Ok(Some((Model::new(user), Vec::new())));
    };
    let disabled: bool = row.try_get(1).map_err(|e| e.to_string())?;
    if disabled {
        return Ok(None);
    }
    let bytes: Vec<u8> = row.try_get(0).map_err(|e| e.to_string())?;
    if bytes.is_empty() {
        return Ok(Some((Model::new(user), bytes)));
    }
    Ok(Some((Model::load(user, &bytes)?, bytes)))
}
