//! F08 `updates-deploy` group `upgrades`: Go's `UpgradeHandler` console routes
//! (`/admin/system/upgrades/*`). The handler validates and decodes, then calls one
//! `upgrade_*` reducer with the verified actor and writes its JSONB verbatim (no trailing
//! newline, no content-length games: `w.Write(raw)`). Reducer refusals with an updater code
//! (BZ242-BZ251) are `reducererr.WriteClassified` problems; anything else is Go's fixed 500.
use crate::mailboxes::{bare, language, render, unknown_outcome};
use crate::problem::Problem;
use crate::{Body, RequestContext};
use hyper::{Method, Request, Response};
use serde_json::{Map, Value};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, Param, ScopedExecutor, StatementFailure, Type};
use setjoin_platform::upgrades as db;
use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Kind {
    Console,
    Preview,
    ChallengeIssue,
    ChallengeComplete,
    IntentRequest,
    IntentRead,
    Diagnostics,
    IntentCancel,
    RecoveryContext,
    RecoverySet,
    RestoreProof,
}

/// `(method, pattern, kind)`; the method column is `GET` or `POST`.
pub(crate) const TABLE: [(&str, &str, Kind); 11] = [
    ("GET", "/api/admin/system/upgrades", Kind::Console),
    ("POST", "/api/admin/system/upgrades/preview", Kind::Preview),
    ("POST", "/api/admin/system/upgrades/challenges", Kind::ChallengeIssue),
    ("POST", "/api/admin/system/upgrades/challenges/complete", Kind::ChallengeComplete),
    ("POST", "/api/admin/system/upgrades/intents", Kind::IntentRequest),
    ("GET", "/api/admin/system/upgrades/intents/{id}", Kind::IntentRead),
    ("GET", "/api/admin/system/upgrades/intents/{id}/diagnostics", Kind::Diagnostics),
    ("POST", "/api/admin/system/upgrades/intents/{id}/cancel", Kind::IntentCancel),
    ("GET", "/api/admin/system/upgrades/recovery-context", Kind::RecoveryContext),
    ("POST", "/api/admin/system/upgrades/recovery-sets", Kind::RecoverySet),
    ("POST", "/api/admin/system/upgrades/restore-proofs", Kind::RestoreProof),
];

/// Routes Go wraps in `requireReason(system.upgrade)`.
pub(crate) fn reason_wrapped(kind: Kind) -> bool {
    !matches!(
        kind,
        Kind::Console
            | Kind::ChallengeComplete
            | Kind::IntentRead
            | Kind::Diagnostics
            | Kind::RecoveryContext
    )
}

const FAILED: &str = "upgrade control operation failed";

fn refused(failure: &StatementFailure, path: &str, r: &Request<Body>, c: &RequestContext, id: &str) -> Response<Body> {
    match db::classify(failure) {
        Some(refusal) => render(
            Problem::new(refusal.status, refusal.detail)
                .kind(&format!(
                    "https://setjoin.com/problems/reducer/{}",
                    refusal.code.to_ascii_lowercase()
                ))
                .code(&refusal.code)
                .retryable(false)
                .remediation(&refusal.remediation)
                .instance(path),
            Some(&language(r)),
            c,
            id,
        ),
        None => bare(500, FAILED, c, id),
    }
}

/// Go's `writeUpgradeRaw`: the status and the reducer's bytes, nothing appended.
fn raw(body: db::Raw, status: u16, c: &RequestContext, id: &str) -> Response<Body> {
    let mut response = crate::jmap::reply::response(body.unwrap_or_default(), c.identity.proto, id.to_owned());
    *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
    response
}

const BODY_CAP: usize = 64 << 10;

/// Go's `decodeUpgradeJSON`: one object, strict fields, 64 KiB. `Ok(None)` is a JSON `null`
/// (a no-op decode that leaves the zero request).
async fn decode(r: &mut Request<Body>) -> Result<Option<Map<String, Value>>, &'static str> {
    use http_body_util::BodyExt;
    let mut bytes = Vec::new();
    while bytes.len() <= BODY_CAP {
        let Some(frame) = r.body_mut().frame().await else {
            break;
        };
        match frame {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    bytes.extend_from_slice(&data[..data.len().min(BODY_CAP + 1 - bytes.len())]);
                }
            }
            Err(_) => return Err("invalid upgrade request"),
        }
    }
    let over = bytes.len() > BODY_CAP;
    bytes.truncate(BODY_CAP);
    let fixed = crate::guests_input::go_json_bytes(&bytes);
    let mut stream = serde_json::Deserializer::from_slice(&fixed).into_iter::<Value>();
    let first = match stream.next() {
        Some(Ok(value)) => value,
        _ => return Err("invalid upgrade request"),
    };
    let object = match first {
        Value::Object(map) => Some(map),
        Value::Null => None,
        _ => return Err("invalid upgrade request"),
    };
    if over || stream.next().is_some() {
        return Err("upgrade request must contain one JSON object");
    }
    Ok(object)
}

/// Case-folded, strict member lookup (`DisallowUnknownFields`): a member naming no known
/// field fails the decode; a repeated member is last-wins.
fn members<'a>(map: &'a Map<String, Value>, known: &[&'static str]) -> Result<BTreeMap<&'static str, &'a Value>, ()> {
    let mut found = BTreeMap::new();
    for (key, value) in map {
        let folded = crate::guests_input::fold(key);
        let Some(name) = known.iter().find(|k| crate::guests_input::fold(k) == folded) else {
            return Err(());
        };
        found.insert(*name, value);
    }
    Ok(found)
}

fn string(v: Option<&&Value>) -> Result<String, ()> {
    match v.copied() {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(()),
    }
}

/// Microseconds since the Unix epoch for a Go `time.Time` JSON string (RFC 3339).
fn micros(text: &str) -> Result<i64, ()> {
    let b = text.as_bytes();
    // Go's parser is stricter than chrono's on the separator, the zone letter and leap seconds.
    if b.len() < 20 || b[10] != b'T' || text.contains(' ') {
        return Err(());
    }
    let zone_ok = text.ends_with('Z') || text.get(19..).is_some_and(|t| t.contains(['+', '-']));
    if !zone_ok || text.get(17..19) == Some("60") {
        return Err(());
    }
    let parsed = chrono::DateTime::parse_from_rfc3339(text).map_err(|_| ())?;
    Ok(parsed.timestamp_micros())
}
/// `time.Time` zero value (`0001-01-01T00:00:00Z`) in microseconds.
const ZERO_TIME: i64 = -62_135_596_800_000_000;

fn time_ptr(v: Option<&&Value>) -> Result<Option<i64>, ()> {
    match v.copied() {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => micros(s).map(Some),
        Some(_) => Err(()),
    }
}
fn time(v: Option<&&Value>) -> Result<i64, ()> {
    Ok(time_ptr(v)?.unwrap_or(ZERO_TIME))
}

fn int(v: Option<&&Value>) -> Result<i64, ()> {
    match v.copied() {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Number(n)) => n.as_i64().ok_or(()),
        Some(_) => Err(()),
    }
}

/// `map[string]bool` re-marshalled by Go: `null` for a missing map, else sorted members.
fn checks(v: Option<&&Value>) -> Result<String, ()> {
    match v.copied() {
        None | Some(Value::Null) => Ok("null".into()),
        Some(Value::Object(map)) => {
            let mut out = BTreeMap::new();
            for (k, v) in map {
                match v {
                    Value::Bool(b) => out.insert(k.clone(), *b),
                    Value::Null => out.insert(k.clone(), false),
                    _ => return Err(()),
                };
            }
            serde_json::to_string(&out).map_err(|_| ())
        }
        Some(_) => Err(()),
    }
}

fn uuid(text: &str) -> Option<String> {
    setjoin_admin_identity::idv2::parse_uuid(text)
        .filter(|u| u != "00000000-0000-0000-0000-000000000000")
}

fn header(r: &Request<Body>, name: &str) -> String {
    r.headers()
        .get(name)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .unwrap_or_default()
}

/// Go's `validateUpgradeReason`.
fn reason_ok(r: &Request<Body>, reason: &str) -> bool {
    let reason = reason.trim();
    reason.len() >= 8
        && reason.len() <= 1024
        && !reason.contains(['\r', '\n', '\0'])
        && header(r, "x-audit-reason").trim() == reason
}

const BAD_REASON: &str = "body reason must exactly match X-Audit-Reason and contain 8-1024 safe characters";

/// Go's `validateUpgradeIdempotency`: the key must equal the header and parse as a UUID.
fn idempotency(r: &Request<Body>, key: &str) -> Result<String, &'static str> {
    if key.is_empty() || header(r, "idempotency-key").trim() != key {
        return Err("body idempotencyKey must exactly match Idempotency-Key");
    }
    uuid(key).ok_or("invalid Idempotency-Key")
}

/// Go's `VerifyFreshAAL2` with `CurrentFreshAAL2Policy` (5 min age, 30 s future skew, 16
/// distinct AMR values) and `upgradeStepUpBindings`: the session and factor digests the
/// challenge reducer binds, plus the sorted distinct AMR list.
pub(crate) fn step_up(auth: &setjoin_authz::Authorized, challenge: &str) -> Option<(Vec<u8>, Vec<u8>, Vec<String>)> {
    use sha2::{Digest, Sha256};
    let user = auth.context().user_id();
    let issued = auth.issued_at();
    if user <= 0 || auth.token_id().is_empty() || issued <= 0 || auth.acr() != "aal2" {
        return None;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos() as i128;
    let issued_ns = i128::from(issued) * 1_000_000_000;
    if now < issued_ns - 30_000_000_000 || now - issued_ns > 300_000_000_000 {
        return None;
    }
    let mut seen = std::collections::BTreeSet::new();
    let (mut factors, mut multi) = (0, false);
    for method in auth.amr().iter().filter(|m| !m.is_empty()) {
        if !seen.insert(method.clone()) {
            continue;
        }
        if seen.len() > 16 {
            return None;
        }
        multi |= method == "mfa";
        factors += usize::from(matches!(method.as_str(), "pwd" | "otp" | "hwk" | "swk"));
    }
    if !multi || factors < 2 {
        return None;
    }
    let amr: Vec<String> = seen.into_iter().collect();
    let at = chrono::DateTime::from_timestamp(issued, 0)?
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let jti = auth.token_id();
    let session = Sha256::digest(format!("setjoin-upgrade-session-v1\n{user}\n{jti}\n{at}").as_bytes());
    let factor = Sha256::digest(
        format!(
            "setjoin-upgrade-factor-v1\n{user}\n{challenge}\n{}\n{}\n{jti}",
            auth.acr(),
            amr.join(",")
        )
        .as_bytes(),
    );
    Some((session.to_vec(), factor.to_vec(), amr))
}

fn digest_ok(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `strconv.ParseInt(.., 10, 64)` that must also round-trip (`id > 0`, canonical form).
fn canonical_positive(text: &str) -> Option<i64> {
    let n: i64 = text.parse().ok()?;
    (n > 0 && n.to_string() == text).then_some(n)
}

fn segment(path: &str, index: usize) -> String {
    crate::guests_input::go_utf8(&crate::inventory::unescape(path.split('/').nth(index).unwrap_or("")))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    kind: Kind,
    mut r: Request<Body>,
    c: &RequestContext,
    exec: &ScopedExecutor,
    auth: &setjoin_authz::Authorized,
    operation: [u8; 16],
    id: &str,
    path: &str,
) -> Response<Body> {
    let actor = auth.context();
    debug_assert!(matches!(*r.method(), Method::GET | Method::HEAD | Method::POST));
    let user = actor.user_id();
    let problem = |detail: &str| bare(400, detail, c, id);
    macro_rules! decoded {
        ($object:ident, $found:ident, $known:expr) => {
            let $object = match decode(&mut r).await {
                Ok(object) => object.unwrap_or_default(),
                Err(detail) => return problem(detail),
            };
            let $found = match members(&$object, $known) {
                Ok(found) => found,
                Err(()) => return problem("invalid upgrade request"),
            };
        };
    }
    macro_rules! field {
        ($e:expr) => {
            match $e {
                Ok(v) => v,
                Err(()) => return problem("invalid upgrade request"),
            }
        };
    }
    // Reads and writes both finish here: the reducer's JSON, its refusal, or Go's 500.
    macro_rules! finish_read {
        ($result:expr, $status:expr) => {
            match $result.await {
                Ok(body) => raw(body, $status, c, id),
                Err(failure) => refused(&failure, path, &r, c, id),
            }
        };
    }
    macro_rules! finish_write {
        ($outcome:expr, $status:expr) => {
            match $outcome.await {
                CommandOutcome::Committed(body) => raw(body, $status, c, id),
                CommandOutcome::RolledBack(rejection) => match rejection {
                    setjoin_pg::Rejection::Statement(failure) | setjoin_pg::Rejection::Body(failure) => {
                        refused(&failure, path, &r, c, id)
                    }
                    _ => bare(500, FAILED, c, id),
                },
                CommandOutcome::Unknown { operation } => unknown_outcome(operation, c, id),
            }
        };
    }
    match kind {
        Kind::Console => finish_read!(
            db::read(exec, "SELECT upgrade_console_read($1::bigint)::text", &[(&user, Type::INT8)]),
            200
        ),
        Kind::RecoveryContext => finish_read!(
            db::read(exec, "SELECT upgrade_recovery_context_read($1::bigint)::text", &[(&user, Type::INT8)]),
            200
        ),
        Kind::IntentRead | Kind::Diagnostics => {
            let Some(intent) = canonical_positive(&segment(r.uri().path(), 6)) else {
                return problem("invalid upgrade intent id");
            };
            if kind == Kind::IntentRead {
                finish_read!(
                    db::read(exec, "SELECT upgrade_intent_read($1::bigint)::text", &[(&intent, Type::INT8)]),
                    200
                )
            } else {
                finish_read!(
                    db::read(
                        exec,
                        "SELECT upgrade_intent_diagnostics($1::bigint,$2::bigint)::text",
                        &[(&user, Type::INT8), (&intent, Type::INT8)]
                    ),
                    200
                )
            }
        }
        Kind::ChallengeComplete => {
            decoded!(object, m, &["challengeId"]);
            let challenge = field!(string(m.get("challengeId")));
            let Some(challenge) = uuid(&challenge) else {
                return problem("invalid upgrade challenge id");
            };
            let Some((session, factor, amr)) = step_up(auth, &challenge) else {
                return bare(
                    403,
                    "fresh AAL2 step-up with two verified factors is required",
                    c,
                    id,
                );
            };
            let acr = "aal2";
            let params: Vec<Param<'_>> = vec![
                (&user, Type::INT8),
                (&challenge, Type::TEXT),
                (&session, Type::BYTEA),
                (&factor, Type::BYTEA),
                (&amr, Type::TEXT_ARRAY),
                (&acr, Type::TEXT),
            ];
            finish_write!(
                db::write(
                    exec,
                    actor,
                    "upgrade_challenge_complete",
                    "SELECT upgrade_challenge_complete($4::bigint,$5::text::uuid,$6::bytea,$7::bytea,$8::text[],$9::text)::text WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
                    &params,
                    operation
                ),
                200
            )
        }
        Kind::Preview => {
            decoded!(object, m, &["releaseId", "reason", "scheduleAt"]);
            let release = field!(string(m.get("releaseId")));
            let reason = field!(string(m.get("reason")));
            let schedule = field!(time_ptr(m.get("scheduleAt")));
            if !reason_ok(&r, &reason) {
                return problem(BAD_REASON);
            }
            let params: Vec<Param<'_>> = vec![
                (&user, Type::INT8),
                (&release, Type::TEXT),
                (&reason, Type::TEXT),
                (&schedule, Type::INT8),
            ];
            finish_read!(
                db::read(
                    exec,
                    "SELECT upgrade_intent_preview($1::bigint,$2::text,$3::text,CASE WHEN $4::bigint IS NULL THEN NULL ELSE 'epoch'::timestamptz+$4::bigint*interval '1 microsecond' END)::text",
                    &params
                ),
                200
            )
        }
        Kind::ChallengeIssue | Kind::IntentRequest => {
            let issue = kind == Kind::ChallengeIssue;
            let known: &[&'static str] = if issue {
                &["releaseId", "reason", "scheduleAt", "previewDigest", "idempotencyKey"]
            } else {
                &["releaseId", "reason", "scheduleAt", "previewDigest", "elevationId", "idempotencyKey"]
            };
            decoded!(object, m, known);
            let release = field!(string(m.get("releaseId")));
            let reason = field!(string(m.get("reason")));
            let schedule = field!(time_ptr(m.get("scheduleAt")));
            let digest = field!(string(m.get("previewDigest")));
            let elevation = field!(string(m.get("elevationId")));
            let key = field!(string(m.get("idempotencyKey")));
            if !reason_ok(&r, &reason) {
                return problem(BAD_REASON);
            }
            if !digest_ok(&digest) {
                return problem("invalid upgrade preview digest");
            }
            let elevation = if issue {
                String::new()
            } else {
                match uuid(&elevation) {
                    Some(u) => u,
                    None => return problem("invalid upgrade elevation id"),
                }
            };
            let key = match idempotency(&r, &key) {
                Ok(k) => k,
                Err(detail) => return problem(detail),
            };
            if issue {
                let params: Vec<Param<'_>> = vec![
                    (&user, Type::INT8),
                    (&release, Type::TEXT),
                    (&reason, Type::TEXT),
                    (&schedule, Type::INT8),
                    (&digest, Type::TEXT),
                    (&key, Type::TEXT),
                ];
                finish_write!(
                    db::write(
                        exec,
                        actor,
                        "upgrade_challenge_issue",
                        "SELECT upgrade_challenge_issue($4::bigint,$5::text,$6::text,CASE WHEN $7::bigint IS NULL THEN NULL ELSE 'epoch'::timestamptz+$7::bigint*interval '1 microsecond' END,$8::text,$9::text::uuid)::text WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
                        &params,
                        operation
                    ),
                    200
                )
            } else {
                let params: Vec<Param<'_>> = vec![
                    (&user, Type::INT8),
                    (&release, Type::TEXT),
                    (&reason, Type::TEXT),
                    (&schedule, Type::INT8),
                    (&digest, Type::TEXT),
                    (&elevation, Type::TEXT),
                    (&key, Type::TEXT),
                ];
                finish_write!(
                    db::write(
                        exec,
                        actor,
                        "upgrade_intent_request",
                        "SELECT upgrade_intent_request($4::bigint,$5::text,$6::text,CASE WHEN $7::bigint IS NULL THEN NULL ELSE 'epoch'::timestamptz+$7::bigint*interval '1 microsecond' END,$8::text,$9::text::uuid,$10::text::uuid)::text WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
                        &params,
                        operation
                    ),
                    202
                )
            }
        }
        Kind::IntentCancel => {
            let Some(intent) = canonical_positive(&segment(r.uri().path(), 6)) else {
                return problem("invalid upgrade intent id");
            };
            decoded!(object, m, &["expectedGeneration", "reason"]);
            let generation = field!(string(m.get("expectedGeneration")));
            let reason = field!(string(m.get("reason")));
            if !reason_ok(&r, &reason) {
                return problem(BAD_REASON);
            }
            let Some(generation) = canonical_positive(&generation) else {
                return problem("invalid upgrade state generation");
            };
            let params: Vec<Param<'_>> = vec![
                (&user, Type::INT8),
                (&intent, Type::INT8),
                (&generation, Type::INT8),
                (&reason, Type::TEXT),
            ];
            finish_write!(
                db::write(
                    exec,
                    actor,
                    "upgrade_intent_cancel",
                    "SELECT upgrade_intent_cancel($4::bigint,$5::bigint,$6::bigint,$7::text)::text WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
                    &params,
                    operation
                ),
                200
            )
        }
        Kind::RecoverySet => {
            decoded!(object, m, &[
                "recoverySetId",
                "timelineId",
                "sourceReleaseId",
                "schemaVersion",
                "manifestDigest",
                "checks",
                "createdAt",
                "expiresAt",
                "reason"
            ]);
            let set = field!(string(m.get("recoverySetId")));
            let timeline = field!(string(m.get("timelineId")));
            let source = field!(string(m.get("sourceReleaseId")));
            let schema = field!(int(m.get("schemaVersion")));
            let manifest = field!(string(m.get("manifestDigest")));
            let checks = field!(checks(m.get("checks")));
            let created = field!(time(m.get("createdAt")));
            let expires = field!(time(m.get("expiresAt")));
            let reason = field!(string(m.get("reason")));
            if !reason_ok(&r, &reason) {
                return problem(BAD_REASON);
            }
            if !digest_ok(&manifest) {
                return problem("invalid recovery-set manifest digest");
            }
            let (Some(set), Some(timeline)) = (uuid(&set), uuid(&timeline)) else {
                return problem("invalid recovery-set identity");
            };
            // pgx cannot encode a Go int outside int32 into an INTEGER parameter.
            let Ok(schema) = i32::try_from(schema) else {
                return bare(500, FAILED, c, id);
            };
            let params: Vec<Param<'_>> = vec![
                (&user, Type::INT8),
                (&set, Type::TEXT),
                (&timeline, Type::TEXT),
                (&source, Type::TEXT),
                (&schema, Type::INT4),
                (&manifest, Type::TEXT),
                (&checks, Type::TEXT),
                (&created, Type::INT8),
                (&expires, Type::INT8),
            ];
            finish_write!(
                db::write(
                    exec,
                    actor,
                    "upgrade_recovery_set_record",
                    "SELECT upgrade_recovery_set_record($4::bigint,$5::text::uuid,$6::text::uuid,$7::text,$8::int,$9::text,$10::text::jsonb,'epoch'::timestamptz+$11::bigint*interval '1 microsecond','epoch'::timestamptz+$12::bigint*interval '1 microsecond')::text WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
                    &params,
                    operation
                ),
                201
            )
        }
        Kind::RestoreProof => {
            decoded!(object, m, &["proofId", "recoverySetId", "targetId", "checks", "provedAt", "reason"]);
            let proof = field!(string(m.get("proofId")));
            let set = field!(string(m.get("recoverySetId")));
            let target = field!(string(m.get("targetId")));
            let checks = field!(checks(m.get("checks")));
            let proved = field!(time(m.get("provedAt")));
            let reason = field!(string(m.get("reason")));
            if !reason_ok(&r, &reason) {
                return problem(BAD_REASON);
            }
            let (Some(proof), Some(set)) = (uuid(&proof), uuid(&set)) else {
                return problem("invalid restore-proof identity");
            };
            let params: Vec<Param<'_>> = vec![
                (&user, Type::INT8),
                (&proof, Type::TEXT),
                (&set, Type::TEXT),
                (&target, Type::TEXT),
                (&checks, Type::TEXT),
                (&proved, Type::INT8),
            ];
            finish_write!(
                db::write(
                    exec,
                    actor,
                    "upgrade_restore_proof_record",
                    "SELECT upgrade_restore_proof_record($4::bigint,$5::text::uuid,$6::text::uuid,$7::text,$8::text::jsonb,'epoch'::timestamptz+$9::bigint*interval '1 microsecond')::text WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
                    &params,
                    operation
                ),
                201
            )
        }
    }
}
