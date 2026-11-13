//! Group `domains`: Go's `DomainsHandler` (`/admin/domains*`). Gates are
//! `requireMailPerm` (reads) and `requireDomainsWrite`; the handler then applies the
//! principal's domain scope. Bodies decode like `json.Decoder.Decode` into a struct:
//! case-folded keys, `null` leaves a field unset, unknown keys are ignored and a wrongly
//! typed field (including a non-integer number) fails the decode.
use super::{path_id, Action, Env};
use crate::{Body, Response};
use hyper::Request;
use serde::de::{MapAccess, Visitor};
use setjoin_pg::CommandOutcome;
use setjoin_platform::domains::{self, Created, New, Patch};

#[derive(Default)]
struct Raw {
    name: Option<String>,
    is_local: Option<bool>,
    is_primary: Option<bool>,
    catch_all: Option<i64>,
    dmarc: Option<String>,
    mta_sts: Option<String>,
    max_bytes: Option<i64>,
    quota: Option<i64>,
}
impl<'de> serde::Deserialize<'de> for Raw {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        fn integer<E: serde::de::Error>(n: serde_json::Number) -> Result<i64, E> {
            n.as_i64().ok_or_else(|| E::custom("not an integer"))
        }
        impl<'de> Visitor<'de> for Fields {
            type Value = Raw;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Raw, E> {
                Ok(Raw::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Raw, M::Error> {
                let mut raw = Raw::default();
                while let Some(key) = map.next_key::<String>()? {
                    match crate::guests_input::fold(&key).as_str() {
                        "name" => raw.name = map.next_value::<Option<String>>()?.or(raw.name),
                        "islocal" => {
                            raw.is_local = map.next_value::<Option<bool>>()?.or(raw.is_local)
                        }
                        "isprimary" => {
                            raw.is_primary = map.next_value::<Option<bool>>()?.or(raw.is_primary)
                        }
                        "catchallmailboxid" => {
                            if let Some(n) = map.next_value::<Option<serde_json::Number>>()? {
                                raw.catch_all = Some(integer(n)?);
                            }
                        }
                        "dmarcpolicy" => {
                            raw.dmarc = map.next_value::<Option<String>>()?.or(raw.dmarc)
                        }
                        "mtastspolicy" => {
                            raw.mta_sts = map.next_value::<Option<String>>()?.or(raw.mta_sts)
                        }
                        "maxmessagebytes" => {
                            if let Some(n) = map.next_value::<Option<serde_json::Number>>()? {
                                raw.max_bytes = Some(integer(n)?);
                            }
                        }
                        "quotabytes" => {
                            if let Some(n) = map.next_value::<Option<serde_json::Number>>()? {
                                raw.quota = Some(integer(n)?);
                            }
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                Ok(raw)
            }
        }
        decoder.deserialize_any(Fields)
    }
}

/// `strings.ToLower(strings.TrimSpace(..))` then Go's `validate.ValidateDomain`.
fn canonical(name: &str) -> Result<String, &'static str> {
    let name = crate::guests_input::lower(name.trim());
    crate::guests_input::domain(name.trim())?;
    Ok(name)
}

pub(super) async fn run(what: Action, mut r: Request<Body>, e: &Env<'_>) -> Response<Body> {
    let scope = e.authority.domain_scope();
    let target = |r: &Request<Body>| path_id(r.uri().path(), 4);
    match what {
        Action::DomainList => match domains::list(e.exec, scope).await {
            Ok(body) => e.reply(body, 200),
            Err(_) => e.database(),
        },
        Action::DomainGet => {
            let Some(id) = target(&r) else {
                return e.problem(400, "invalid domain id");
            };
            if scope > 0 && id != scope {
                return e.problem(403, "access denied: domain not in scope");
            }
            match domains::get(e.exec, id).await {
                Ok(Some(body)) => e.reply(body, 200),
                Ok(None) => e.problem(404, "domain not found"),
                Err(_) => e.database(),
            }
        }
        Action::DomainCreate => {
            if scope > 0 {
                return e.problem(403, "scoped admins cannot create domains");
            }
            let Ok(body) = super::json_body::<Raw>(&mut r, 1 << 20).await else {
                return e.problem(400, "invalid JSON");
            };
            let name = body.name.unwrap_or_default();
            if name.is_empty() {
                return e.problem(400, "domain name is required");
            }
            let name = match canonical(&name) {
                Ok(n) => n,
                Err(reason) => return e.problem(400, reason),
            };
            let fill = |v: Option<String>, d: &str| match v {
                Some(v) if !v.is_empty() => v,
                _ => d.to_owned(),
            };
            let new = New {
                name,
                is_local: body.is_local.unwrap_or_default(),
                is_primary: body.is_primary.unwrap_or_default(),
                dmarc_policy: fill(body.dmarc, "none"),
                mta_sts_policy: fill(body.mta_sts, "none"),
                max_message_bytes: match body.max_bytes {
                    Some(n) if n > 0 => n,
                    _ => 52_428_800,
                },
                quota_bytes: body.quota,
            };
            match domains::create(e.exec, e.actor, &new, e.operation).await {
                CommandOutcome::Committed(Created::Id(id)) => {
                    e.reply(setjoin_platform::done(format!("{{\"id\":{id}}}")), 201)
                }
                CommandOutcome::Committed(Created::Conflict) => {
                    e.problem(409, "domain already exists")
                }
                CommandOutcome::RolledBack(_) => e.problem(500, "database error"),
                CommandOutcome::Unknown { operation } => e.unknown(operation),
            }
        }
        Action::DomainUpdate => {
            let Some(id) = target(&r) else {
                return e.problem(400, "invalid domain id");
            };
            if scope > 0 && id != scope {
                return e.problem(403, "access denied: domain not in scope");
            }
            let Ok(body) = super::json_body::<Raw>(&mut r, 1 << 20).await else {
                return e.problem(400, "invalid JSON");
            };
            let name = match body.name.as_deref().map(canonical) {
                None => None,
                Some(Ok(n)) => Some(n),
                Some(Err(reason)) => return e.problem(400, reason),
            };
            let patch = Patch {
                name,
                is_local: body.is_local,
                is_primary: body.is_primary,
                catch_all_mailbox_id: body.catch_all,
                dmarc_policy: body.dmarc,
                mta_sts_policy: body.mta_sts,
                max_message_bytes: body.max_bytes,
                quota_bytes: body.quota,
            };
            if patch.is_empty() {
                return e.problem(400, "no fields to update");
            }
            match domains::update(e.exec, e.actor, id, scope, &patch, e.operation).await {
                CommandOutcome::Committed(true) => e.no_content(),
                CommandOutcome::Committed(false) => e.problem(404, "domain not found"),
                CommandOutcome::RolledBack(_) => e.database(),
                CommandOutcome::Unknown { operation } => e.unknown(operation),
            }
        }
        _ => {
            let Some(id) = target(&r) else {
                return e.problem(400, "invalid domain id");
            };
            if scope > 0 && id != scope {
                return e.problem(403, "access denied: domain not in scope");
            }
            match domains::delete(e.exec, e.actor, id, scope, e.operation).await {
                CommandOutcome::Committed(()) => e.no_content(),
                CommandOutcome::RolledBack(_) => e.database(),
                CommandOutcome::Unknown { operation } => e.unknown(operation),
            }
        }
    }
}
