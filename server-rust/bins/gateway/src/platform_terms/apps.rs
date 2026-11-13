//! Group `apps`: the curated-application console of Go's `OfficeHandler`
//! (`/admin/apps*`). Reads need `apps.view|apps.manage`, operations `apps.manage` plus the
//! required-reason policy of the `apps` area. Each route is one reducer call; refusals
//! decided by a reducer use the Office admin problem mapping.
use super::{Action, Env};
use crate::{Body, Response};
use hyper::Request;
use serde::de::{MapAccess, Visitor};
use serde_json::value::RawValue;
use setjoin_platform::apps;

/// The fields of Go's `officeAppOperationBody`/`officeAppRecoverBody` (decoded with
/// `DisallowUnknownFields`): `null` leaves a field unset except for the raw `request`.
#[derive(Default)]
struct Fields {
    kind: Option<String>,
    provider: Option<String>,
    generation: Option<i64>,
    key: Option<String>,
    request: Option<Box<RawValue>>,
}
struct Strict(Fields);
/// `officeAppRecoverBody`: only `expectedGeneration`.
struct Recover(i64);
impl<'de> serde::Deserialize<'de> for Recover {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Recover;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Recover, E> {
                Ok(Recover(0))
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Recover, M::Error> {
                let mut generation = 0;
                while let Some(key) = map.next_key::<String>()? {
                    if crate::guests_input::fold(&key) != "expectedgeneration" {
                        return Err(serde::de::Error::custom("unknown field"));
                    }
                    if let Some(n) = map.next_value::<Option<serde_json::Number>>()? {
                        generation = n
                            .as_i64()
                            .ok_or_else(|| serde::de::Error::custom("not an integer"))?;
                    }
                }
                Ok(Recover(generation))
            }
        }
        decoder.deserialize_any(V)
    }
}
impl<'de> serde::Deserialize<'de> for Strict {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Fields::default()))
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Strict, M::Error> {
                let mut fields = Fields::default();
                while let Some(key) = map.next_key::<String>()? {
                    match crate::guests_input::fold(&key).as_str() {
                        "kind" => {
                            fields.kind = map.next_value::<Option<String>>()?.or(fields.kind);
                        }
                        "providerid" => {
                            fields.provider =
                                map.next_value::<Option<String>>()?.or(fields.provider);
                        }
                        "expectedprovidergeneration" => {
                            if let Some(n) = map.next_value::<Option<serde_json::Number>>()? {
                                fields.generation =
                                    Some(n.as_i64().ok_or_else(|| {
                                        serde::de::Error::custom("not an integer")
                                    })?);
                            }
                        }
                        "idempotencykey" => {
                            fields.key = map.next_value::<Option<String>>()?.or(fields.key);
                        }
                        "request" => {
                            fields.request = Some(map.next_value::<Box<RawValue>>()?);
                        }
                        _ => return Err(serde::de::Error::custom("unknown field")),
                    }
                }
                Ok(Strict(fields))
            }
        }
        decoder.deserialize_any(V)
    }
}

/// Go's `decodeOfficeBody`: a 64 KiB `MaxBytesReader`, strict fields, then exactly one
/// value. `Err` carries Go's detail.
async fn decode<T: serde::de::DeserializeOwned>(r: &mut Request<Body>) -> Result<T, &'static str> {
    use http_body_util::BodyExt;
    const CAP: usize = 64 << 10;
    let mut bytes = Vec::new();
    let mut over = false;
    while let Some(frame) = r.body_mut().frame().await {
        let Ok(frame) = frame else {
            return Err("invalid JSON body");
        };
        if let Ok(data) = frame.into_data() {
            let room = (CAP + 1).saturating_sub(bytes.len());
            bytes.extend_from_slice(&data[..data.len().min(room)]);
            if bytes.len() > CAP {
                over = true;
                break;
            }
        }
    }
    let visible = &bytes[..bytes.len().min(CAP)];
    let fixed = crate::guests_input::go_json_bytes(visible);
    let mut stream = serde_json::Deserializer::from_slice(&fixed).into_iter::<T>();
    let Some(Ok(first)) = stream.next() else {
        return Err("invalid JSON body");
    };
    let used = stream.byte_offset();
    let rest = &fixed[used.min(fixed.len())..];
    if over
        || rest
            .iter()
            .any(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
    {
        return Err("exactly one JSON value is required");
    }
    Ok(first)
}

pub(super) async fn run(what: Action, mut r: Request<Body>, e: &Env<'_>) -> Response<Body> {
    let reason = r
        .headers()
        .get("x-audit-reason")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let mut segments = r.uri().path().split('/');
    let app =
        crate::guests_input::go_utf8(&crate::inventory::unescape(segments.nth(4).unwrap_or("")));
    let operation_id = crate::guests_input::go_utf8(&crate::inventory::unescape(
        r.uri().path().split('/').nth(6).unwrap_or(""),
    ));
    let finish = |outcome| match crate::office::command_result(outcome, &e.raw_path, e.c, e.id) {
        Ok(body) => {
            let mut response = e.reply(body, 202);
            response.headers_mut().insert(
                "content-type",
                hyper::header::HeaderValue::from_static("application/json"),
            );
            response
        }
        Err(reply) => reply,
    };
    if what == Action::AppList {
        return match apps::list(e.exec, e.actor).await {
            Ok(body) => e.reply(body, 200),
            Err(f) => crate::office::reducer_problem(&f, &e.raw_path, true, e.c, e.id.to_owned()),
        };
    }
    // The required-reason middleware runs before the handler.
    if reason.is_empty() && apps::reason_required(e.exec).await {
        let _ = apps::reason_missing(
            e.exec,
            e.actor,
            &e.c.identity.client_ip.to_string(),
            e.operation,
        )
        .await;
        return e.bare(400, "reason_required");
    }
    if app != "collabora-code" {
        return e.bare(404, "unknown curated application");
    }
    if what == Action::AppRequest {
        let fields = match decode::<Strict>(&mut r).await {
            Ok(f) => f.0,
            Err(detail) => return e.bare(400, detail),
        };
        let key = fields.key.clone().unwrap_or_default();
        let canonical = apps::uuid(&key).filter(|u| *u == key);
        let header = r
            .headers()
            .get("idempotency-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if canonical.is_none() || header != key {
            return e.bare(
                400,
                "one canonical Idempotency-Key must match body idempotencyKey",
            );
        }
        let Some(request) = fields.request else {
            return e.bare(400, "request is required");
        };
        return finish(
            apps::request(
                e.exec,
                e.actor,
                fields.kind.as_deref().unwrap_or(""),
                fields.provider.as_deref().unwrap_or(""),
                fields.generation.unwrap_or(0),
                &key,
                request.get(),
                &reason,
                e.operation,
            )
            .await,
        );
    }
    let Some(operation_uuid) = apps::uuid(&operation_id) else {
        return e.bare(400, "operationId must be a UUID");
    };
    let generation = match decode::<Recover>(&mut r).await {
        Ok(g) => g.0,
        Err(detail) => return e.bare(400, detail),
    };
    finish(
        apps::recover(
            e.exec,
            e.actor,
            &operation_uuid,
            generation,
            &reason,
            e.operation,
        )
        .await,
    )
}
