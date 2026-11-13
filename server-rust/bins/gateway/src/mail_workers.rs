//! F05 worker adapters. Reducers own all database transitions.
use crate::webhook::{CloudEvent, Dispatcher};
use serde::Deserialize;
use setjoin_pg::{workers::WorkerDatabase, Type};
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Purge {
    purge_request_id: String,
    actor_user_id: String,
    operation_id: String,
    request_digest: String,
    attempt: i32,
    blocked: bool,
}
#[derive(Deserialize)]
struct Claim {
    id: i64,
    attempts: i32,
    consumer_kind: String,
    event_id: Option<String>,
    payload: Option<serde_json::Map<String, serde_json::Value>>,
}
pub struct MailWork {
    pub db: WorkerDatabase,
    webhooks: Option<Dispatcher>,
}

pub struct MailboxLifecycle {
    pub db: WorkerDatabase,
    id: String,
    media: Option<(String, String, String)>,
    webhooks: Option<Dispatcher>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Effect {
    effect_id: String,
    operation_id: String,
    kind: String,
    attempt: i32,
    targets: Vec<serde_json::Value>,
    event: Option<LifecycleEvent>,
}
/// `mailboxlifecycle.event`: `data` stays the reducer's exact jsonb text (Go's
/// `json.RawMessage`), so the delivered body keeps jsonb's key order.
#[derive(Deserialize)]
struct LifecycleEvent {
    #[serde(default)]
    id: String,
    #[serde(default, rename = "type")]
    kind: String,
    time: Option<String>,
    data: Option<Box<serde_json::value::RawValue>>,
}
impl LifecycleEvent {
    /// `Time.UTC().Format(time.RFC3339Nano)`; a missing time is Go's zero time.
    fn rfc3339_nano(&self) -> Option<String> {
        use chrono::{Datelike, Timelike};
        let Some(text) = &self.time else {
            return Some("0001-01-01T00:00:00Z".into());
        };
        let t = chrono::DateTime::parse_from_rfc3339(text)
            .ok()?
            .with_timezone(&chrono::Utc);
        let mut out = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            t.year(),
            t.month(),
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        );
        let nanos = format!("{:09}", t.nanosecond() % 1_000_000_000);
        let nanos = nanos.trim_end_matches('0');
        if !nanos.is_empty() {
            out.push('.');
            out.push_str(nanos);
        }
        out.push('Z');
        Some(out)
    }
}
impl MailboxLifecycle {
    pub async fn run_until(self, stop: impl std::future::Future<Output = ()>) {
        poll_until(stop, || self.tick()).await;
    }
    /// Go's `webhooks` argument: lifecycle events are enqueued durably through it.
    /// Without one every lifecycle webhook effect fails, as in Go.
    pub fn with_dispatcher(mut self, dispatcher: Dispatcher) -> Self {
        self.webhooks = Some(dispatcher);
        self
    }
    pub fn with_media(mut self, url: &str, key: &str, secret: &str) -> Self {
        if !url.is_empty() && !key.is_empty() && !secret.is_empty() {
            self.media = Some((url.into(), key.into(), secret.into()));
        }
        self
    }
    pub fn new(db: WorkerDatabase) -> Self {
        Self {
            db,
            id: format!("mailbox-lifecycle-{}", crate::admin_job_workers::new_uuid()),
            media: None,
            webhooks: None,
        }
    }
    pub async fn tick(&self) {
        let Ok(c) = self.db.connect_session().await else {
            return;
        };
        self.effects(&c).await;
        self.purges(&c).await;
    }
    async fn purges(&self, c: &setjoin_pg::workers::WorkerConnection) {
        for _ in 0..100 {
            let Ok(rows) = c
                .query(
                    "SELECT mailbox_purge_claim($1,600)::text",
                    &[(&self.id, Type::TEXT)],
                )
                .await
            else {
                return;
            };
            let Some(raw) = rows[0].get::<_, Option<String>>(0) else {
                return;
            };
            let Ok(p) = serde_json::from_str::<Purge>(&raw) else {
                return;
            };
            // Claim envelopes originate in the reducer; validate before executing,
            // including the independent blocked claim (which carries no actor).
            if !uuid(&p.purge_request_id) {
                return;
            }
            if p.blocked {
                continue;
            }
            let Ok(actor) = p.actor_user_id.parse::<i64>() else {
                return;
            };
            if actor <= 0
                || !(1..=20).contains(&p.attempt)
                || p.request_digest.len() != 64
                || !uuid(&p.operation_id)
            {
                return;
            }
            if let Err(error) = c
                .query(
                    "SELECT mailbox_purge_execute($1,$2::uuid,$3::uuid,$4)",
                    &[
                        (&actor, Type::INT8),
                        (&p.purge_request_id, Type::TEXT),
                        (&p.operation_id, Type::TEXT),
                        (&p.request_digest, Type::TEXT),
                    ],
                )
                .await
            {
                let _ = c
                    .query(
                        "SELECT mailbox_purge_fail($1,$2::uuid,$3)",
                        &[
                            (&self.id, Type::TEXT),
                            (&p.purge_request_id, Type::TEXT),
                            (&error, Type::TEXT),
                        ],
                    )
                    .await;
            }
        }
    }
    async fn effects(&self, c: &setjoin_pg::workers::WorkerConnection) {
        for _ in 0..100 {
            let Ok(rows) = c
                .query(
                    "SELECT mailbox_lifecycle_effect_claim($1,600)::text",
                    &[(&self.id, Type::TEXT)],
                )
                .await
            else {
                return;
            };
            let Some(raw) = rows[0].get::<_, Option<String>>(0) else {
                return;
            };
            let Ok(effect) = serde_json::from_str::<Effect>(&raw) else {
                return;
            };
            let Ok(id) = effect.effect_id.parse::<i64>() else {
                return;
            };
            // Go decodes the whole claim: an unparseable event time fails it.
            if effect
                .event
                .as_ref()
                .is_some_and(|e| e.rfc3339_nano().is_none())
            {
                return;
            }
            if id <= 0
                || effect.operation_id.is_empty()
                || effect.kind.is_empty()
                || !(1..=20).contains(&effect.attempt)
            {
                return;
            }
            let result = match effect.kind.as_str() {
                "revoke_sessions" | "revoke_delegates" | "notify_clients" => c
                    .query(
                        "SELECT mailbox_lifecycle_effect_apply($1,$2)",
                        &[(&self.id, Type::TEXT), (&id, Type::INT8)],
                    )
                    .await
                    .map(|_| ()),
                "evict_media" if effect.targets.is_empty() => Ok(()),
                "evict_media" => self.evict(c, id, &effect.targets).await,
                "lifecycle_webhook" => match effect.event.as_ref() {
                    Some(event) if !event.id.is_empty() && !event.kind.is_empty() => {
                        match &self.webhooks {
                            None => Err("webhook dispatcher is not configured".into()),
                            Some(dispatcher) => {
                                let time = event.rfc3339_nano().unwrap_or_default();
                                let raw = event.data.as_ref().map(|d| d.get());
                                dispatcher
                                    .enqueue_durable(&CloudEvent::with_raw_data(
                                        &event.id,
                                        "mailserver/lifecycle",
                                        &event.kind,
                                        &time,
                                        raw,
                                    ))
                                    .await
                            }
                        }
                    }
                    _ => Err("mailbox lifecycle webhook payload is missing".into()),
                },
                _ => Err(format!(
                    "unknown mailbox lifecycle effect kind {:?}",
                    effect.kind
                )),
            };
            if let Err(error) = result {
                let _ = c
                    .query(
                        "SELECT mailbox_lifecycle_effect_fail($1,$2,$3)",
                        &[
                            (&self.id, Type::TEXT),
                            (&id, Type::INT8),
                            (&error, Type::TEXT),
                        ],
                    )
                    .await;
            } else if matches!(effect.kind.as_str(), "evict_media" | "lifecycle_webhook") {
                // A lost/failed acknowledgement is not a processing failure.
                // Go leaves the lease for recovery rather than calling fail.
                if let Err(error) = c
                    .query(
                        "SELECT mailbox_lifecycle_effect_complete($1,$2)",
                        &[(&self.id, Type::TEXT), (&id, Type::INT8)],
                    )
                    .await
                {
                    eprintln!("mailbox lifecycle completion failed: {error}");
                }
            }
        }
    }
    async fn evict(
        &self,
        c: &setjoin_pg::workers::WorkerConnection,
        id: i64,
        targets: &[serde_json::Value],
    ) -> Result<(), String> {
        let Some((url, key, secret)) = &self.media else {
            return Err("LiveKit is not configured".into());
        };
        for t in targets {
            let room = t["room"].as_str().unwrap_or_default();
            let identity = t["identity"].as_str().unwrap_or_default();
            // Go continues through the committed horizon even after NotFound.
            // Nil/past horizons perform exactly one attempt.
            let until = t["evictUntil"]
                .as_str()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());
            loop {
                crate::guest_worker::remove_participant(url, key, secret, room, identity).await?;
                let Some(remaining) = until.and_then(|end| {
                    (end.with_timezone(&chrono::Utc) - chrono::Utc::now())
                        .to_std()
                        .ok()
                }) else {
                    break;
                };
                if remaining.is_zero() {
                    break;
                }
                tokio::time::sleep(remaining.min(std::time::Duration::from_secs(5))).await;
            }
            c.query(
                "SELECT mailbox_lifecycle_effect_target_complete($1,$2,$3,$4)",
                &[
                    (&self.id, Type::TEXT),
                    (&id, Type::INT8),
                    (&room, Type::TEXT),
                    (&identity, Type::TEXT),
                ],
            )
            .await?;
        }
        Ok(())
    }
}
fn uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
impl MailWork {
    /// `Worker.dispatchWebhook`: the approved event, a payload reduced to five safe
    /// keys (values as Go's `map[string]any` decode holds them), the outbox event id
    /// as the CloudEvent id, then a durable enqueue.
    async fn webhook(&self, item: &Claim) -> Result<(), String> {
        let Some(dispatcher) = &self.webhooks else {
            return Err("mail-work webhook dispatcher unavailable".into());
        };
        let payload = item.payload.as_ref();
        let get = |key: &str| {
            payload
                .and_then(|p| p.get(key))
                .map_or(serde_json::Value::Null, as_go_decoded)
        };
        let event_type = payload
            .and_then(|p| p.get("eventType"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let mapped = match event_type {
            "claimed" => "mailwork.claimed",
            "assigned" | "reassigned" => "mailwork.assigned",
            "handed_off" => "mailwork.handed_off",
            "completed" => "mailwork.completed",
            "sla_breached" => "mailwork.sla_breached",
            _ => return Err("mail-work webhook event is not approved".into()),
        };
        let event_id = item.event_id.clone().unwrap_or_default();
        let mut event = CloudEvent::new(
            "urn:setjoin:mailwork",
            mapped,
            serde_json::json!({
                "mailboxId": get("mailboxId"), "threadId": get("threadId"),
                "eventId": event_id, "eventType": event_type, "generation": get("generation"),
            }),
        );
        event.id = event_id;
        dispatcher.enqueue_durable(&event).await
    }
    pub async fn run_until(self, stop: impl std::future::Future<Output = ()>) {
        poll_until(stop, || self.tick()).await;
    }
    /// Go's `webhooks` argument: mail-work events are enqueued durably through it.
    pub fn with_dispatcher(mut self, dispatcher: Dispatcher) -> Self {
        self.webhooks = Some(dispatcher);
        self
    }
    pub fn new(db: WorkerDatabase) -> Self {
        Self { db, webhooks: None }
    }
    pub async fn tick(&self) {
        let Ok(c) = self.db.connect_session().await else {
            return;
        };
        // Go isolates the two maintenance failures and still attempts the claim.
        for sql in [
            "SELECT mail_work_sla_scan(100)",
            "SELECT mail_work_digest_dispatch(100)",
        ] {
            if let Err(error) = c.query(sql, &[]).await {
                eprintln!("mail-work: {error}");
            }
        }
        let kinds = vec![
            "push", "digest", "metric", "webhook", "task", "chat", "drive",
        ];
        let Ok(rows) = c
            .query(
                "SELECT mail_work_outbox_claim($1,100)::text",
                &[(&kinds, Type::TEXT_ARRAY)],
            )
            .await
        else {
            return;
        };
        let Ok(claims) = serde_json::from_str::<Vec<Claim>>(&rows[0].get::<_, String>(0)) else {
            return;
        };
        for item in claims {
            if item.id <= 0 || !(1..=100).contains(&item.attempts) {
                continue;
            }
            if item.consumer_kind == "webhook" {
                let result = self.webhook(&item).await;
                match result {
                    Ok(()) => {
                        let receipt=serde_json::json!({"outboxId":item.id,"eventId":item.event_id.unwrap_or_default(),"outcome":"enqueued"}).to_string();
                        let _ = c
                            .query(
                                "SELECT mail_work_outbox_finish($1,true,$2::jsonb,NULL)",
                                &[(&item.id, Type::INT8), (&receipt, Type::TEXT)],
                            )
                            .await;
                    }
                    Err(error) => {
                        let _ = c
                            .query(
                                "SELECT mail_work_outbox_finish($1,false,NULL,$2)",
                                &[(&item.id, Type::INT8), (&error, Type::TEXT)],
                            )
                            .await;
                    }
                }
                continue;
            }
            let sql = if matches!(item.consumer_kind.as_str(), "task" | "chat" | "drive") {
                "SELECT mail_work_outbox_dispatch_internal($1)::text"
            } else {
                "SELECT mail_work_outbox_dispatch_local($1)::text"
            };
            let result = c.query(sql, &[(&item.id, Type::INT8)]).await;
            match result {
                Ok(rows) => {
                    let receipt: String = rows[0].get(0);
                    let _ = c
                        .query(
                            "SELECT mail_work_outbox_finish($1,true,$2::jsonb,NULL)",
                            &[(&item.id, Type::INT8), (&receipt, Type::TEXT)],
                        )
                        .await;
                }
                Err(error) => {
                    let _ = c
                        .query(
                            "SELECT mail_work_outbox_finish($1,false,NULL,$2)",
                            &[(&item.id, Type::INT8), (&error, Type::TEXT)],
                        )
                        .await;
                }
            }
        }
    }
}

// Both Go workers drain immediately, then create a five-second ticker. A
// shutdown cancels in-flight DB/peripheral work, including horizon sleeps.
async fn poll_until<F, Fut>(stop: impl std::future::Future<Output = ()>, mut tick: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    tokio::pin!(stop);
    tokio::select! {biased; _=&mut stop=>return,_=tick()=>{}}
    let interval = std::time::Duration::from_secs(5);
    let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {biased; _=&mut stop=>return,_=ticks.tick()=>{}}
        tokio::select! {biased; _=&mut stop=>return,_=tick()=>{}}
    }
}

/// A JSON value as Go's `map[string]any` decode holds it: every number is a float64.
fn as_go_decoded(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Number(n) => n
            .as_f64()
            .and_then(serde_json::Number::from_f64)
            .map_or_else(|| value.clone(), serde_json::Value::Number),
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(as_go_decoded).collect())
        }
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), as_go_decoded(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}
