//! F01 slice `idv2-transitions`: identity v2 transition reads, preview, step-up
//! challenge and commands. The parent adapter has already run Go's route guards (live
//! permission, audited bare 403, reason policy); each handler here keeps Go's own order of
//! checks (path id, strict body, reason, preview/generation fence, idempotency key, reach)
//! and answers Go's bare problems or `writeIdentityRawJSON` documents.
#![allow(clippy::result_large_err)]
use super::{
    bare, body_refusal, header_text, mutation_key, raw_json, raw_json_as, read_body,
    reason_matches, refusal, rejection, segment, unknown_outcome,
};
use crate::{Body, RequestContext};
use hyper::{Request, Response};
use setjoin_admin_identity::idv2 as db;
use setjoin_admin_identity::idv2_ops as ops;
use setjoin_admin_identity::idv2_transitions as tr;
use setjoin_admin_identity::idv2_writes as wr;
use setjoin_authz::{AuthContext, Authorized};
use setjoin_pg::{CommandOutcome, ScopedExecutor, Type};

pub(super) use tr::Op;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    List,
    Read,
    Report,
    Preview,
    Command(Op),
}

pub(super) struct Call<'a> {
    pub worker: &'a ScopedExecutor,
    pub auth: &'a Authorized,
    pub actor: &'a AuthContext,
    pub scope: i64,
    pub operation: [u8; 16],
    pub path: &'a str,
    pub go_path: &'a str,
    pub query: &'a str,
    pub now: i64,
    pub id: &'a str,
    pub c: &'a RequestContext,
}

const NIL: &str = "00000000-0000-0000-0000-000000000000";

fn uuid(text: &str) -> Option<String> {
    db::parse_uuid(text).filter(|u| u != NIL)
}

pub(super) async fn serve(kind: Kind, mut r: Request<Body>, call: &Call<'_>) -> Response<Body> {
    match kind {
        Kind::List => list(r, call).await,
        Kind::Read => read(&r, call).await,
        Kind::Report => report(&r, call).await,
        Kind::Preview => preview(&mut r, call).await,
        Kind::Command(op) => command(op, &mut r, call).await,
    }
}

async fn list(r: Request<Body>, call: &Call<'_>) -> Response<Body> {
    let Call { c, id, .. } = call;
    let opts = match db::parse_list(
        call.query,
        &db::TRANSITIONS,
        call.actor.user_id(),
        call.scope,
        call.now,
    ) {
        Ok(opts) => opts,
        Err(e) => return refusal(e, call.go_path, c, id),
    };
    match db::transitions(call.worker, call.actor.user_id(), &opts, call.now).await {
        Ok(body) => raw_json(
            setjoin_admin_identity::go_escape(&body),
            r.headers().get("if-none-match"),
            c,
            id,
        ),
        Err(e) => refusal(e, call.go_path, c, id),
    }
}

/// `{"transitionGeneration": "<n>"}` as Go decodes it from the reducer's jsonb.
fn generation_of(raw: &str) -> Result<String, &'static str> {
    const INVALID: &str = "identity transition returned an invalid response";
    let value: serde_json::Value = serde_json::from_str(raw).map_err(|_| INVALID)?;
    let generation = match &value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::Object(object) => {
            let member = object.get("transitionGeneration").or_else(|| {
                object
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("transitionGeneration"))
                    .map(|(_, v)| v)
            });
            match member {
                None | Some(serde_json::Value::Null) => String::new(),
                Some(serde_json::Value::String(g)) => g.clone(),
                Some(_) => return Err(INVALID),
            }
        }
        _ => return Err(INVALID),
    };
    match generation.parse::<i64>() {
        Ok(n) if n > 0 => Ok(generation),
        _ => Err("identity transition returned an invalid generation"),
    }
}

fn read_failure(
    f: setjoin_pg::StatementFailure,
    fallback: &str,
    call: &Call<'_>,
) -> Response<Body> {
    match ops::classify(&f) {
        Some(e) => refusal(e, call.go_path, call.c, call.id),
        None => bare(500, fallback, call.c, call.id),
    }
}

async fn read(r: &Request<Body>, call: &Call<'_>) -> Response<Body> {
    let Call { c, id, .. } = call;
    let Some(transition) = uuid(&segment(call.path, 6)) else {
        return bare(400, "invalid transition id", c, id);
    };
    match tr::reachable(call.worker, call.actor.user_id(), &transition).await {
        Err(e) => return bare(500, &e.detail, c, id),
        Ok(false) => return bare(404, "identity transition not found", c, id),
        Ok(true) => {}
    }
    let raw = match tr::read(call.worker, call.actor.user_id(), &transition).await {
        Ok(raw) => raw,
        Err(f) => return read_failure(f, "identity transition read failed", call),
    };
    let generation = match generation_of(raw.as_deref().unwrap_or("")) {
        Ok(g) => g,
        Err(detail) => return bare(500, detail, c, id),
    };
    raw_json_as(
        raw.unwrap_or_default(),
        200,
        Some(generation),
        r.headers().get("if-none-match"),
        c,
        id,
    )
}

async fn report(r: &Request<Body>, call: &Call<'_>) -> Response<Body> {
    let Call { c, id, .. } = call;
    // `uuid.Parse` only: the nil id is looked up and is simply not found.
    let Some(transition) = db::parse_uuid(&segment(call.path, 6)) else {
        return bare(400, "invalid transition id", c, id);
    };
    let raw = match tr::report(call.worker, call.actor.user_id(), &transition).await {
        Ok(Some(raw)) => raw,
        Ok(None) => return bare(404, "identity transition not found", c, id),
        Err(e) => return bare(500, &e.detail, c, id),
    };
    let mut response = raw_json(raw, r.headers().get("if-none-match"), c, id);
    response.headers_mut().insert(
        "content-disposition",
        format!("attachment; filename=\"identity-transition-{transition}.json\"")
            .parse()
            .expect("header"),
    );
    response
}

type Members = std::collections::BTreeMap<&'static str, Box<serde_json::value::RawValue>>;

/// Go's `decodeIdentityJSON`: strict body, 64 KiB; any failure is the route's 400.
async fn decode(
    r: &mut Request<Body>,
    names: &[&'static str],
    detail: &str,
    call: &Call<'_>,
) -> Result<Members, Response<Body>> {
    let Some(bytes) = read_body(r).await else {
        return Err(bare(400, detail, call.c, call.id));
    };
    wr::strict_object(&bytes, names).map_err(|e| body_refusal(e, detail, call.c, call.id))
}

fn text(
    members: &Members,
    name: &str,
    detail: &str,
    call: &Call<'_>,
) -> Result<String, Response<Body>> {
    wr::text(members, name).map_err(|_| bare(400, detail, call.c, call.id))
}

fn fail(status: u16, detail: &str, call: &Call<'_>) -> Response<Body> {
    bare(status, detail, call.c, call.id)
}

/// `identityTransitionDigestFence`.
fn digest_fence(r: &Request<Body>, digest: &str, call: &Call<'_>) -> Result<(), Response<Body>> {
    if !tr::valid_digest(digest) {
        return Err(fail(400, "invalid transition preview digest", call));
    }
    if header_text(r, "if-match").trim() != format!("\"{digest}\"") {
        return Err(fail(
            412,
            "If-Match must be the strong transition preview digest ETag",
            call,
        ));
    }
    Ok(())
}

fn key_of(r: &Request<Body>, body: &str, call: &Call<'_>) -> Result<String, Response<Body>> {
    mutation_key(r, body).map_err(|(status, detail)| fail(status, detail, call))
}

fn reason_of(r: &Request<Body>, body: &str, call: &Call<'_>) -> Result<(), Response<Body>> {
    reason_matches(r, body).map_err(|(status, detail)| fail(status, detail, call))
}

/// `identityTransitionApprovalID`: digits only, no leading zero, positive `int64`.
fn approval_id(raw: Option<&str>) -> Option<Option<i64>> {
    let Some(raw) = raw else { return Some(None) };
    let first = *raw.as_bytes().first()?;
    if !(b'1'..=b'9').contains(&first) || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse::<i64>().ok().filter(|n| *n > 0).map(Some)
}

async fn command(op: Op, r: &mut Request<Body>, call: &Call<'_>) -> Response<Body> {
    let Some(transition) = uuid(&segment(call.path, 6)) else {
        return fail(400, "invalid transition id", call);
    };
    match op {
        Op::ChallengeIssue => issue(r, &transition, call).await,
        Op::ChallengeComplete => complete(r, &transition, call).await,
        Op::Cancel | Op::RollbackPreview | Op::Retry => generation(op, r, &transition, call).await,
        _ => authorized(op, r, &transition, call).await,
    }
}

fn outcome(
    op_detail: &str,
    done: CommandOutcome<wr::Verdict, setjoin_pg::StatementFailure>,
    status: u16,
    digest_etag: Option<String>,
    r: &Request<Body>,
    call: &Call<'_>,
) -> Response<Body> {
    let Call { c, id, .. } = call;
    match done {
        CommandOutcome::Committed(v) if v.status == 404 => {
            bare(404, "identity transition not found", c, id)
        }
        CommandOutcome::Committed(v) => {
            let raw = v.body.unwrap_or_default();
            let version = match digest_etag {
                Some(digest) => digest,
                None => match generation_of(&raw) {
                    Ok(g) => g,
                    Err(detail) => return bare(500, detail, c, id),
                },
            };
            raw_json_as(
                raw,
                status,
                Some(version),
                r.headers().get("if-none-match"),
                c,
                id,
            )
        }
        CommandOutcome::RolledBack(e) => rejection(&e, op_detail, call.go_path, c, id),
        CommandOutcome::Unknown { operation } => unknown_outcome(operation, c, id),
    }
}

async fn authorized(
    op: Op,
    r: &mut Request<Body>,
    transition: &str,
    call: &Call<'_>,
) -> Response<Body> {
    const BAD: &str = "invalid identity transition command";
    let members = match decode(
        r,
        &[
            "previewDigest",
            "elevationId",
            "approvalRequestId",
            "reason",
            "idempotencyKey",
        ],
        BAD,
        call,
    )
    .await
    {
        Ok(m) => m,
        Err(e) => return e,
    };
    let (Ok(digest), Ok(elevation), Ok(reason), Ok(key_text)) = (
        wr::text(&members, "previewDigest"),
        wr::text(&members, "elevationId"),
        wr::text(&members, "reason"),
        wr::text(&members, "idempotencyKey"),
    ) else {
        return fail(400, BAD, call);
    };
    // `approvalRequestId` is a `*string`: absent and null are nil, any other type fails.
    let approval_text = match members.get("approvalRequestId") {
        None => None,
        Some(raw) => match serde_json::from_str::<Option<String>>(raw.get()) {
            Ok(value) => value,
            Err(_) => return fail(400, BAD, call),
        },
    };
    if let Err(e) = reason_of(r, &reason, call) {
        return e;
    }
    if let Err(e) = digest_fence(r, &digest, call) {
        return e;
    }
    let elevation = uuid(&elevation);
    let approval = approval_id(approval_text.as_deref());
    let (Some(elevation), Some(approval)) = (elevation, approval) else {
        return fail(400, "invalid identity transition authorization", call);
    };
    if op == Op::Rollback && approval.is_none() {
        return fail(400, "rollback requires an approvalRequestId", call);
    }
    let key = match key_of(r, &key_text, call) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let word = match op {
        Op::Request => "request",
        Op::Approve => "approve",
        Op::Deny => "deny",
        Op::Execute => "execute",
        _ => "rollback",
    };
    let payload = format!("{digest}:{elevation}:{approval:?}:{key}:{reason}");
    let done = if matches!(op, Op::Execute | Op::Rollback) {
        tr::run(
            call.worker,
            call.actor,
            op,
            transition,
            &[
                (&digest, Type::TEXT),
                (&elevation, Type::TEXT),
                (&approval, Type::INT8),
                (&reason, Type::TEXT),
                (&key, Type::TEXT),
            ],
            &payload,
            call.operation,
        )
        .await
    } else {
        tr::run(
            call.worker,
            call.actor,
            op,
            transition,
            &[
                (&digest, Type::TEXT),
                (&elevation, Type::TEXT),
                (&reason, Type::TEXT),
                (&key, Type::TEXT),
            ],
            &payload,
            call.operation,
        )
        .await
    };
    let status = if matches!(op, Op::Request | Op::Execute | Op::Rollback) {
        202
    } else {
        200
    };
    outcome(
        &format!("identity transition {word} failed"),
        done,
        status,
        None,
        r,
        call,
    )
}

async fn generation(
    op: Op,
    r: &mut Request<Body>,
    transition: &str,
    call: &Call<'_>,
) -> Response<Body> {
    // Retry names the effect in the path before anything else is read.
    let effect = if op == Op::Retry {
        match uuid(&segment(call.path, 8)) {
            Some(effect) => Some(effect),
            None => return fail(400, "invalid identity transition effect id", call),
        }
    } else {
        None
    };
    let bad = if op == Op::Retry {
        "invalid identity transition retry"
    } else {
        "invalid identity transition command"
    };
    let members = match decode(
        r,
        &["expectedGeneration", "reason", "idempotencyKey"],
        bad,
        call,
    )
    .await
    {
        Ok(m) => m,
        Err(e) => return e,
    };
    let (Ok(expected_text), Ok(reason), Ok(key_text)) = (
        wr::text(&members, "expectedGeneration"),
        wr::text(&members, "reason"),
        wr::text(&members, "idempotencyKey"),
    ) else {
        return fail(400, bad, call);
    };
    if let Err(e) = reason_of(r, &reason, call) {
        return e;
    }
    // `identityTransitionGenerationFence`.
    let Some(expected) = expected_text.parse::<i64>().ok().filter(|n| *n > 0) else {
        return fail(400, "invalid expected transition generation", call);
    };
    if header_text(r, "if-match").trim() != format!("\"{expected_text}\"") {
        return fail(
            412,
            "If-Match must be the strong transition generation ETag",
            call,
        );
    }
    let key = match key_of(r, &key_text, call) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let (word, status) = match op {
        Op::Cancel => ("cancel", 200),
        Op::RollbackPreview => ("rollback-preview", 200),
        _ => ("retry", 202),
    };
    let payload = format!("{expected}:{effect:?}:{key}:{reason}");
    let done = match &effect {
        Some(effect) => {
            tr::run(
                call.worker,
                call.actor,
                op,
                transition,
                &[
                    (&expected, Type::INT8),
                    (effect, Type::TEXT),
                    (&reason, Type::TEXT),
                    (&key, Type::TEXT),
                ],
                &payload,
                call.operation,
            )
            .await
        }
        None => {
            tr::run(
                call.worker,
                call.actor,
                op,
                transition,
                &[
                    (&expected, Type::INT8),
                    (&reason, Type::TEXT),
                    (&key, Type::TEXT),
                ],
                &payload,
                call.operation,
            )
            .await
        }
    };
    outcome(
        &format!("identity transition {word} failed"),
        done,
        status,
        None,
        r,
        call,
    )
}

async fn issue(r: &mut Request<Body>, transition: &str, call: &Call<'_>) -> Response<Body> {
    const BAD: &str = "invalid transition challenge request";
    let members = match decode(r, &["previewDigest", "idempotencyKey"], BAD, call).await {
        Ok(m) => m,
        Err(e) => return e,
    };
    let (Ok(digest), Ok(key_text)) = (
        text(&members, "previewDigest", BAD, call),
        text(&members, "idempotencyKey", BAD, call),
    ) else {
        return fail(400, BAD, call);
    };
    if let Err(e) = digest_fence(r, &digest, call) {
        return e;
    }
    let key = match key_of(r, &key_text, call) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let done = tr::run(
        call.worker,
        call.actor,
        Op::ChallengeIssue,
        transition,
        &[(&digest, Type::TEXT), (&key, Type::TEXT)],
        &format!("{digest}:{key}"),
        call.operation,
    )
    .await;
    outcome(
        "identity transition challenge failed",
        done,
        200,
        Some(digest),
        r,
        call,
    )
}

async fn complete(r: &mut Request<Body>, transition: &str, call: &Call<'_>) -> Response<Body> {
    const BAD: &str = "invalid transition challenge completion";
    let members = match decode(
        r,
        &["challengeId", "previewDigest", "idempotencyKey"],
        BAD,
        call,
    )
    .await
    {
        Ok(m) => m,
        Err(e) => return e,
    };
    let (Ok(challenge), Ok(digest), Ok(key_text)) = (
        text(&members, "challengeId", BAD, call),
        text(&members, "previewDigest", BAD, call),
        text(&members, "idempotencyKey", BAD, call),
    ) else {
        return fail(400, BAD, call);
    };
    if let Err(e) = digest_fence(r, &digest, call) {
        return e;
    }
    let Some(challenge) = uuid(&challenge) else {
        return fail(400, "invalid transition challenge id", call);
    };
    let key = match key_of(r, &key_text, call) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let Some((session, factor, amr)) = tr::step_up_bindings(
        call.actor.user_id(),
        call.auth.token_id(),
        call.auth.issued_at(),
        call.auth.acr(),
        call.auth.amr(),
        transition,
        &challenge,
        &digest,
        now,
    ) else {
        return fail(
            403,
            "fresh AAL2 step-up with two verified factors is required",
            call,
        );
    };
    let acr = call.auth.acr().to_owned();
    let done = tr::run(
        call.worker,
        call.actor,
        Op::ChallengeComplete,
        transition,
        &[
            (&challenge, Type::TEXT),
            (&digest, Type::TEXT),
            (&session, Type::BYTEA),
            (&factor, Type::BYTEA),
            (&amr, Type::TEXT_ARRAY),
            (&acr, Type::TEXT),
            (&key, Type::TEXT),
        ],
        &format!("{challenge}:{digest}:{key}"),
        call.operation,
    )
    .await;
    outcome(
        "identity transition challenge completion failed",
        done,
        200,
        Some(digest),
        r,
        call,
    )
}

async fn preview(r: &mut Request<Body>, call: &Call<'_>) -> Response<Body> {
    const BAD: &str = "invalid transition preview";
    let members = match decode(
        r,
        &["userId", "reason", "idempotencyKey", "targetLinkId"],
        BAD,
        call,
    )
    .await
    {
        Ok(m) => m,
        Err(e) => return e,
    };
    let (Ok(user_text), Ok(reason), Ok(mut key_text), Ok(target_text)) = (
        text(&members, "userId", BAD, call),
        text(&members, "reason", BAD, call),
        text(&members, "idempotencyKey", BAD, call),
        text(&members, "targetLinkId", BAD, call),
    ) else {
        return fail(400, BAD, call);
    };
    if let Err(e) = reason_of(r, &reason, call) {
        return e;
    }
    let header = header_text(r, "idempotency-key");
    let header = header.trim();
    if !header.is_empty() && !key_text.is_empty() && header != key_text {
        return fail(400, "Idempotency-Key must match body idempotencyKey", call);
    }
    if !header.is_empty() {
        key_text = header.to_owned();
    }
    let user = user_text.parse::<i64>().ok().filter(|n| *n > 0);
    let key = db::parse_uuid(&key_text);
    let (Some(user), Some(key)) = (user, key) else {
        return fail(400, BAD, call);
    };
    let target = if target_text.is_empty() {
        None
    } else {
        match target_text.parse::<i64>().ok().filter(|n| *n > 0) {
            Some(n) => Some(n),
            None => {
                // Go checks reach (404) before it parses the target link.
                return match tr::person_reachable(call.worker, call.actor.user_id(), user).await {
                    Err(e) => fail(500, &e.detail, call),
                    Ok(false) => fail(404, "identity user not found", call),
                    Ok(true) => fail(400, "invalid targetLinkId", call),
                };
            }
        }
    };
    let done = tr::preview(
        call.worker,
        call.actor,
        user,
        target,
        &reason,
        &key,
        call.operation,
    )
    .await;
    match done {
        CommandOutcome::Committed(v) if v.status == 404 => {
            fail(404, "identity user not found", call)
        }
        CommandOutcome::Committed(v) => {
            let raw = v.body.unwrap_or_default();
            let digest = serde_json::from_str::<serde_json::Value>(&raw)
                .ok()
                .and_then(|value| {
                    let object = value.as_object()?;
                    let member = object.get("previewDigest").or_else(|| {
                        object
                            .iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case("previewDigest"))
                            .map(|(_, v)| v)
                    })?;
                    member.as_str().map(str::to_owned)
                });
            let Some(digest) = digest.filter(|d| tr::valid_digest(d)) else {
                return fail(500, "transition preview returned an invalid response", call);
            };
            raw_json_as(
                raw,
                200,
                Some(digest),
                r.headers().get("if-none-match"),
                call.c,
                call.id,
            )
        }
        CommandOutcome::RolledBack(e) => rejection(
            &e,
            "transition preview failed",
            call.go_path,
            call.c,
            call.id,
        ),
        CommandOutcome::Unknown { operation } => unknown_outcome(operation, call.c, call.id),
    }
}
