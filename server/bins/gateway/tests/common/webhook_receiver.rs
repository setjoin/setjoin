//! #457: a fake webhook receiver and the seed/observe helpers the producer oracles share.
//! Frozen Go and the Rust dispatcher both deliver to it; the receiver records the path,
//! method, content type, whether the signature verifies under the seeded secret and the
//! body, with the two fields that are fresh per event (`time`, an `evt_` id) masked.
#![allow(dead_code)]
use super::{fake_upstream, full, BoxError};
use serde_json::{json, Value};
use setjoin_config_secret::{seal_column, CryptoProfile};
use setjoin_gateway::webhook::Dispatcher;
use setjoin_pg::workers::WorkerDatabase;
use setjoin_platform::webhook_secret::SecretCodec;
use std::sync::{Arc, Mutex};

pub const MASTER: &str = "gofree-webhook-oracle-master";
pub const SIGNING_SECRET: &str = "1111111111111111111111111111111111111111111111111111111111111111";
pub type Seen = Arc<Mutex<Vec<Value>>>;

/// The Rust dispatcher with the loopback-capable client (the receiver is on loopback).
pub fn unguarded(dsn: &str) -> Result<Dispatcher, BoxError> {
    Ok(Dispatcher::unguarded_for_tests(
        WorkerDatabase::new(dsn)?,
        Some(SecretCodec::new(MASTER.as_bytes(), CryptoProfile::Standard)),
    ))
}

fn signature_label(header: &str, body: &str) -> &'static str {
    use hmac::{Hmac, Mac};
    let Some(rest) = header.strip_prefix("v1,t=") else {
        return "<missing-or-malformed>";
    };
    let Some((t, sig)) = rest.split_once(",sig=") else {
        return "<malformed>";
    };
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(SIGNING_SECRET.as_bytes()).unwrap();
    mac.update(format!("{t}.{body}").as_bytes());
    let expected: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if expected == sig {
        "<valid>"
    } else {
        "<invalid>"
    }
}

/// Replaces the string value of `"key":` (compact or PG-spaced) with `mask` when
/// `applies` accepts the current value.
fn mask_field(body: &str, key: &str, mask: &str, applies: impl Fn(&str) -> bool) -> String {
    let needle = format!("\"{key}\":");
    let Some(start) = body.find(&needle) else {
        return body.to_owned();
    };
    let after = start + needle.len();
    let Some(open) = body[after..].find('"').map(|i| after + i + 1) else {
        return body.to_owned();
    };
    let Some(close) = body[open..].find('"').map(|i| open + i) else {
        return body.to_owned();
    };
    if !applies(&body[open..close]) {
        return body.to_owned();
    }
    format!("{}{mask}{}", &body[..open], &body[close..])
}

/// Event time and `evt_` ids are minted per event (Go: `NewCloudEvent`). Lifecycle events
/// carry their outbox row's own time and an operation id, which stay exact.
pub fn mask_volatile(body: &str) -> String {
    let body = mask_field(body, "id", "<id>", |v| v.starts_with("evt_"));
    if body.contains("\"source\":\"mailserver/lifecycle\"")
        || body.contains("\"source\": \"mailserver/lifecycle\"")
    {
        return body;
    }
    mask_field(&body, "time", "<time>", |_| true)
}

pub async fn receiver(seen: Seen) -> std::net::SocketAddr {
    use http_body_util::BodyExt;
    fake_upstream(move |request| {
        let seen = seen.clone();
        async move {
            let path = request.uri().path().to_owned();
            let method = request.method().to_string();
            let header = |name: &str| {
                request
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned()
            };
            let (content_type, signature) = (header("content-type"), header("x-webhook-signature"));
            let body = String::from_utf8(
                request
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .to_vec(),
            )
            .unwrap();
            seen.lock().unwrap().push(json!({
                "path": path, "method": method, "content_type": content_type,
                "signature": signature_label(&signature, &body), "body": mask_volatile(&body),
            }));
            hyper::Response::builder()
                .status(200)
                .body(full("ok"))
                .unwrap()
        }
    })
    .await
}

/// One subscription delivering to `http://<hook><path>` under the shared signing secret.
pub async fn subscribe(
    owner: &tokio_postgres::Client,
    user: i64,
    hook: std::net::SocketAddr,
    path: &str,
    types: &str,
    scope: &str,
    active: bool,
) -> Result<(), BoxError> {
    let sealed = seal_column(
        SIGNING_SECRET.as_bytes(),
        MASTER.as_bytes(),
        CryptoProfile::Standard,
    )?;
    let url = format!("http://{hook}{path}");
    owner
        .execute(
            "INSERT INTO webhook_subscriptions(user_id,url,secret_enc,secret_key_id,event_types,scope,is_active) \
             VALUES($1,$2,$3,'v1',$4::text::jsonb,$5,$6)",
            &[&user, &url, &sealed, &types, &scope, &active],
        )
        .await?;
    Ok(())
}

pub async fn clear(owner: &tokio_postgres::Client) -> Result<(), BoxError> {
    owner
        .batch_execute("DELETE FROM webhook_deliveries; DELETE FROM webhook_subscriptions")
        .await?;
    Ok(())
}

/// Requests the receiver saw, in a run-independent order.
pub fn requests(seen: &Seen) -> Value {
    let mut all: Vec<Value> = seen.lock().unwrap().clone();
    all.sort_by_key(|r| {
        (
            r["path"].as_str().unwrap().to_owned(),
            r["body"].as_str().unwrap().to_owned(),
        )
    });
    json!(all)
}

/// Delivery rows with the subscription's receiver path, masked and sorted.
pub async fn deliveries(owner: &tokio_postgres::Client) -> Result<Value, BoxError> {
    let mut rows = Vec::new();
    for row in owner
        .query(
            "SELECT split_part(s.url,'/',4),d.event_type,d.request_body::text,d.status,d.attempt,d.response_code,d.error_message,d.event_id \
             FROM webhook_deliveries d JOIN webhook_subscriptions s ON s.id=d.subscription_id",
            &[],
        )
        .await?
    {
        let event_id: String = row.get(7);
        rows.push(json!([
            format!("/{}", row.get::<_, String>(0)), row.get::<_, String>(1), mask_volatile(&row.get::<_, String>(2)),
            row.get::<_, String>(3), row.get::<_, i32>(4), row.get::<_, Option<i32>>(5), row.get::<_, Option<String>>(6),
            if event_id.starts_with("evt_") { "<id>".to_owned() } else { event_id },
        ]));
    }
    rows.sort_by_key(Value::to_string);
    Ok(json!(rows))
}
