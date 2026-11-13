//! Public telemetry ingest: frozen handler order and per-device admission.
use crate::{Body, RequestContext};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use serde::Deserialize;
use setjoin_authz::device::{DeviceRequest, DeviceResolver};
use setjoin_pg::{workers::WorkerDatabase, ScopedExecutor};
use setjoin_static::telemetry::Report;
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

fn reply(status: u16, detail: Option<&str>, c: &RequestContext, id: String) -> Response<Body> {
    let mut response = crate::jmap::reply::response(String::new(), c.identity.proto, id);
    *response.status_mut() = StatusCode::from_u16(status).expect("telemetry status");
    if let Some(detail) = detail {
        response
            .headers_mut()
            .insert("content-type", "application/problem+json".parse().unwrap());
        *response.body_mut() = Full::new(Bytes::from(
            crate::problem::Problem::new(status, detail).body(),
        ))
        .map_err(|n| match n {})
        .boxed();
    } else {
        response.headers_mut().remove("content-type");
    }
    response
}

async fn body(r: &mut Request<Body>) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        let frame = frame.ok()?;
        if let Some(data) = frame.data_ref() {
            if bytes.len() + data.len() > 64 * 1024 {
                return None;
            }
            bytes.extend_from_slice(data);
        }
    }
    Some(bytes)
}

fn decode(bytes: &[u8]) -> Result<(i64, Report), ()> {
    let text = crate::chat::go_json_text(bytes);
    // Go decodes the first JSON value and leaves any trailing value unread.
    let fields = crate::chat::Fields::deserialize(&mut serde_json::Deserializer::from_str(&text))
        .map_err(|_| ())?;
    let mut usage = BTreeMap::new();
    for (key, raw) in &fields.0 {
        if crate::chat_channels::fold(key) != "FEATURE_USAGE" {
            continue;
        }
        if raw.get() == "null" {
            usage.clear();
            continue;
        }
        let values: BTreeMap<String, Option<i64>> =
            serde_json::from_str(raw.get()).map_err(|_| ())?;
        usage.extend(values.into_iter().map(|(k, v)| (k, v.unwrap_or(0))));
    }
    Ok((
        crate::chat_channels::number_field(&fields, "DEVICE_ID")?,
        Report {
            app_version: crate::chat_channels::text_field(&fields, "APP_VERSION")?,
            os_version: crate::chat_channels::text_field(&fields, "OS_VERSION")?,
            crash_count: crate::chat_channels::number_field(&fields, "CRASH_COUNT")?,
            uptime_hours: crate::chat_channels::number_field(&fields, "UPTIME_HOURS")?,
            feature_usage: usage,
        },
    ))
}

fn admitted(device: i64) -> bool {
    static CAPS: OnceLock<Mutex<HashMap<i64, (Instant, u8)>>> = OnceLock::new();
    let mut caps = CAPS
        .get_or_init(Default::default)
        .lock()
        .expect("device caps");
    let now = Instant::now();
    caps.retain(|_, (until, _)| *until >= now);
    let (until, count) = caps
        .entry(device)
        .or_insert((now + Duration::from_secs(3600), 0));
    let _ = until;
    if *count >= 10 {
        return false;
    }
    *count += 1;
    true
}

pub async fn serve(
    exec: &ScopedExecutor,
    mut r: Request<Body>,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    if crate::assist::feature_on(exec, "device_telemetry").await != Some(true) {
        return reply(204, None, c, id);
    }
    let Some(bytes) = body(&mut r).await else {
        return reply(400, Some("invalid JSON"), c, id);
    };
    let Ok((claimed, report)) = decode(&bytes) else {
        return reply(400, Some("invalid JSON"), c, id);
    };
    if claimed <= 0 {
        return reply(400, Some("device_id is required"), c, id);
    }
    let resolver = DeviceResolver::new(
        exec.clone(),
        std::env::var("JWT_SECRET").unwrap_or_default().into_bytes(),
        setjoin_config_secret::CryptoProfile::parse(
            &std::env::var("CRYPTO_ALGORITHM_PROFILE").unwrap_or_default(),
        ),
    );
    let target = r.uri().path_and_query().map_or("/", |p| p.as_str());
    let inner = target.strip_prefix("/api").unwrap_or(target);
    let Some(device) = resolver
        .verify_request(
            claimed,
            DeviceRequest {
                headers: r.headers(),
                method: r.method().as_str(),
                uri: inner,
                body: &bytes,
            },
        )
        .await
    else {
        return reply(401, Some("device authentication failed"), c, id);
    };
    if !admitted(device.id()) {
        return reply(429, Some("rate limit exceeded"), c, id);
    }
    let request = std::env::var("DB_DSN").unwrap_or_default();
    let worker = std::env::var("DB_WORKER_DSN").ok();
    let inserted = async {
        let db = WorkerDatabase::from_dsns(&request, worker.as_deref()).ok()?;
        setjoin_static::telemetry::insert(&db, &device, &report)
            .await
            .ok()
    }
    .await;
    if inserted.is_none() {
        return reply(500, Some("internal server error"), c, id);
    }
    reply(204, None, c, id)
}
