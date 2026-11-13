//! F06 slice `spam`: HTTP side of the spam dashboard and model switches, the sender
//! lists, trusted senders, external-sender warning, sender-control center and the user
//! report. Business reads and writes live in `setjoin_mail_security::spam`; this file
//! only decodes requests the way Go's handlers do and renders Go's exact answers.
use crate::admin_identity_input::{query, rfc3339, timestamptz};
use crate::mail_security::{segment, segment_path};
use crate::mail_security_input as input;
use crate::mailboxes::{bare, language, parse_uuid, render, unknown_outcome};
use crate::problem::Problem;
use crate::{Body, RequestContext};
use hyper::{Request, Response};
use setjoin_authz::AuthContext;
use setjoin_mail_security::spam as db;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure};
use sha2::{Digest, Sha256};

/// How Go's handler wrote the answer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// `httputil.WriteJSON`: `application/json`.
    Json,
    /// `WriteHeader` before `Encode`: nothing sets a type, so net/http sniffs it.
    Plain,
    /// A reducer's jsonb written verbatim: JSON type, no trailing newline.
    Raw,
}

struct Out<'a> {
    c: &'a RequestContext,
    id: &'a str,
    head: bool,
}
impl Out<'_> {
    fn send(&self, body: String, status: u16, kind: Kind, etag: Option<&str>) -> Response<Body> {
        // net/http buffers 2 KiB of a handler's output; a larger single write is
        // flushed before the handler returns and sent chunked.
        let chunked = body.len() > 2048 && !self.head;
        let mut response =
            crate::jmap::reply::response(body, self.c.identity.proto, self.id.to_owned());
        *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
        if kind == Kind::Plain {
            response.headers_mut().insert(
                "content-type",
                hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
            );
        }
        if let Some(tag) = etag {
            if let Ok(v) = format!("\"{tag}\"").parse() {
                response.headers_mut().insert("etag", v);
            }
        }
        if chunked {
            response.headers_mut().insert(
                "transfer-encoding",
                hyper::header::HeaderValue::from_static("chunked"),
            );
        }
        response
    }
    fn json(&self, body: String, status: u16) -> Response<Body> {
        self.send(body, status, Kind::Json, None)
    }
    fn no_content(&self) -> Response<Body> {
        let mut response = self.send(String::new(), 204, Kind::Json, None);
        response.headers_mut().remove("content-type");
        response
    }
    fn bare(&self, status: u16, detail: &str) -> Response<Body> {
        bare(status, detail, self.c, self.id)
    }
}

fn state(rejection: &setjoin_pg::Rejection<StatementFailure>) -> &str {
    match rejection {
        setjoin_pg::Rejection::Statement(f) | setjoin_pg::Rejection::Body(f) => {
            f.sqlstate.as_deref().unwrap_or("")
        }
        _ => "",
    }
}

/// Go's `reducererr.WriteClassified` for the codes the sender reducers raise; any other
/// failure is the handler's own 500.
fn classified(code: &str, fallback: &str, path: &str, lang: &str, out: &Out<'_>) -> Response<Body> {
    let (status, detail, remediation) = match code {
        "BZ300" | "BZ302" => (
            404,
            "notFound",
            "Refresh the target identifier and retry only if the resource still exists.",
        ),
        "BZ006" => (
            404,
            "accountId does not match an existing account",
            "Refresh the target identifier and retry only if the resource still exists.",
        ),
        "BZ301" => (
            400,
            "invalidArguments",
            "Correct the request fields and retry.",
        ),
        "BZ303" | "BZ304" => (
            409,
            "stateMismatch",
            "Refresh current state, resolve the conflict, and retry.",
        ),
        _ => return out.bare(500, fallback),
    };
    let kind = format!(
        "https://setjoin.com/problems/reducer/{}",
        code.to_ascii_lowercase()
    );
    render(
        Problem::new(status, detail)
            .kind(&kind)
            .instance(path)
            .remediation(remediation)
            .code(code)
            .retryable(false),
        Some(lang),
        out.c,
        out.id,
    )
}

fn header<'a>(r: &'a Request<Body>, name: &str) -> String {
    r.headers()
        .get(name)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .unwrap_or_default()
}

fn sha_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `strconv.ParseInt(text, 10, 64)`.
fn int(text: &str) -> Option<i64> {
    text.parse::<i64>().ok()
}

/// Go's `parseSenderControlTarget`: `(mailbox, message, receivedAt)` or the 400 detail.
fn target(
    mailbox: &str,
    message: &str,
    received: &str,
) -> Result<(i64, i64, String), &'static str> {
    let mailbox = int(mailbox).filter(|n| *n > 0).ok_or("invalid mailboxId")?;
    let message = int(message).filter(|n| *n > 0).ok_or("invalid messageId")?;
    let at = rfc3339(received).ok_or("invalid receivedAt")?;
    Ok((mailbox, message, timestamptz(at)))
}

/// `uuid.Parse` that also refuses the nil UUID.
fn real_uuid(text: &str) -> Option<String> {
    parse_uuid(text).filter(|u| u != "00000000-0000-0000-0000-000000000000")
}

pub(crate) async fn handle(
    what: crate::mail_security::Action,
    mut r: Request<Body>,
    c: &RequestContext,
    id: &str,
    operation: [u8; 16],
    actor: &AuthContext,
    worker: &ScopedExecutor,
) -> Response<Body> {
    use crate::mail_security::Action as A;
    let out = Out {
        c,
        id,
        head: r.method() == hyper::Method::HEAD,
    };
    let user = actor.user_id();
    let path = r.uri().path().to_owned();
    let stripped = segment_path(&path);
    let lang = language(&r);
    // `WriteProblem`: instance is the stripped path, language from the request.
    let problem = |status: u16, detail: &str| {
        render(
            Problem::new(status, detail).instance(&stripped),
            Some(&lang),
            c,
            id,
        )
    };
    let unknown = |op| unknown_outcome(op, c, id);
    match what {
        A::SpamDashboard => out.json(db::dashboard_with_stats(worker, setjoin_spam::process_stats().snapshot()).await, 200),
        A::SpamReset | A::SpamDisable | A::SpamEnable => {
            let switch = match what {
                A::SpamReset => db::Switch::Reset,
                A::SpamDisable => db::Switch::Disable,
                _ => db::Switch::Enable,
            };
            let Some(target) = int(&segment(&path, 5)).filter(|n| *n > 0) else {
                return problem(400, "invalid userId");
            };
            match db::switch_model(worker, actor, target, switch, operation).await {
                CommandOutcome::Committed(true) => out.json(
                    setjoin_mail_security::done(format!(
                        "{{\"status\":{}}}",
                        setjoin_mail_security::s(match switch {
                            db::Switch::Reset => "reset",
                            db::Switch::Disable => "disabled",
                            db::Switch::Enable => "enabled",
                        })
                    )),
                    200,
                ),
                CommandOutcome::Committed(false) => {
                    problem(403, "target user not within your administrative scope")
                }
                CommandOutcome::RolledBack(_) => problem(500, "database error"),
                CommandOutcome::Unknown { operation } => unknown(operation),
            }
        }
        A::SendersGet => {
            let Ok(on) = db::sender_control_on(worker).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            if on {
                match db::sender_list_read(worker, user).await {
                    Ok(raw) => out.send(raw.body, 200, Kind::Raw, Some(&raw.generation)),
                    Err(e) => classified(
                        e.sqlstate.as_deref().unwrap_or(""),
                        "sender list read failed",
                        &stripped,
                        &lang,
                        &out,
                    ),
                }
            } else {
                match db::senders_legacy(worker, user).await {
                    Ok(body) => out.json(body, 200),
                    Err(_) => out.bare(500, "database error"),
                }
            }
        }
        A::SendersPut => {
            let Ok(on) = db::sender_control_on(worker).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let Ok(body) = input::lenient::<input::SenderList>(&mut r).await else {
                return out.bare(400, "invalid json");
            };
            if !on {
                let (safe, blocked) = (
                    body.safe.clone().unwrap_or_default(),
                    body.blocked.clone().unwrap_or_default(),
                );
                return match db::sender_list_replace_legacy(
                    worker, actor, &safe, &blocked, operation,
                )
                .await
                {
                    CommandOutcome::Committed(_) => {
                        out.send("{\"status\":\"ok\"}\n".into(), 200, Kind::Plain, None)
                    }
                    CommandOutcome::RolledBack(_) => out.bare(500, "database error"),
                    CommandOutcome::Unknown { operation } => unknown(operation),
                };
            }
            let operation_id = real_uuid(&body.operation_id);
            let generation = int(&body.expected_generation);
            if operation_id.is_none()
                || generation.is_none_or(|g| g <= 0)
                || header(&r, "idempotency-key").trim() != body.operation_id
                || header(&r, "if-match") != format!("\"{}\"", body.expected_generation)
            {
                return out.bare(
                    428,
                    "operationId/Idempotency-Key and expectedGeneration/If-Match are required",
                );
            }
            // json.Marshal(req): struct order, omitempty on the two trailing strings.
            let mut encoded = format!(
                "{{\"safe\":{},\"blocked\":{}",
                input::go_strings(&body.safe),
                input::go_strings(&body.blocked)
            );
            if !body.expected_generation.is_empty() {
                encoded += &format!(
                    ",\"expectedGeneration\":{}",
                    input::go_string(&body.expected_generation)
                );
            }
            if !body.operation_id.is_empty() {
                encoded += &format!(",\"operationId\":{}", input::go_string(&body.operation_id));
            }
            encoded.push('}');
            match db::sender_list_replace(
                worker,
                actor,
                &operation_id.expect("checked"),
                generation.expect("checked"),
                &sha_hex(&encoded),
                &body.safe,
                &body.blocked,
                operation,
            )
            .await
            {
                CommandOutcome::Committed(raw) => {
                    out.send(raw.body, 200, Kind::Raw, Some(&raw.generation))
                }
                CommandOutcome::RolledBack(e) => classified(
                    state(&e),
                    "sender list replacement failed",
                    &stripped,
                    &lang,
                    &out,
                ),
                CommandOutcome::Unknown { operation } => unknown(operation),
            }
        }
        A::SendersNeverBlock => {
            let Ok(on) = db::sender_control_on(worker).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            if on {
                return out.bare(409, "use the message-bound sender control action");
            }
            let Ok(body) = input::lenient::<input::Sender>(&mut r).await else {
                return out.bare(400, "invalid json");
            };
            if body.sender.is_empty() {
                return out.bare(400, "sender is required");
            }
            match db::never_block(worker, actor, &body.sender, operation).await {
                CommandOutcome::Committed(_) => out.send(
                    format!(
                        "{{\"list\":\"safe\",\"sender\":{},\"status\":\"ok\"}}\n",
                        setjoin_mail_security::s(&body.sender)
                    ),
                    200,
                    Kind::Plain,
                    None,
                ),
                CommandOutcome::RolledBack(_) => out.bare(500, "database error"),
                CommandOutcome::Unknown { operation } => unknown(operation),
            }
        }
        A::ControlGet => {
            let value = |name: &str| query(r.uri(), name).unwrap_or_default();
            let (mailbox, message, at) = match target(
                &value("mailboxId"),
                &value("messageId"),
                &value("receivedAt"),
            ) {
                Ok(t) => t,
                Err(detail) => return out.bare(400, detail),
            };
            match db::sender_control_read(worker, user, mailbox, message, &at).await {
                Ok(raw) => control_write(&out, raw),
                Err(e) => classified(
                    e.sqlstate.as_deref().unwrap_or(""),
                    "sender control read failed",
                    &stripped,
                    &lang,
                    &out,
                ),
            }
        }
        A::ControlAction => {
            let body = match input::strict_one::<input::ControlAction>(&mut r).await {
                Ok(b) => b,
                Err(true) => return out.bare(400, "invalid sender control request"),
                Err(false) => {
                    return out.bare(400, "sender control request must contain one JSON object")
                }
            };
            let (mailbox, message, at) =
                match target(&body.mailbox_id, &body.message_id, &body.received_at) {
                    Ok(t) => t,
                    Err(detail) => return out.bare(400, detail),
                };
            let operation_id = real_uuid(&body.operation_id);
            if operation_id.is_none() || header(&r, "idempotency-key").trim() != body.operation_id {
                return out.bare(400, "operationId must exactly match Idempotency-Key");
            }
            let generation = int(&body.expected_generation).filter(|g| *g > 0);
            if generation.is_none()
                || header(&r, "if-match") != format!("\"{}\"", body.expected_generation)
            {
                return out.bare(428, "expectedGeneration must exactly match If-Match");
            }
            let target_operation = if body.target_operation_id.is_empty() {
                None
            } else {
                match real_uuid(&body.target_operation_id) {
                    Some(u) => Some(u),
                    None => return out.bare(400, "invalid targetOperationId"),
                }
            };
            let encoded = format!(
                "{{\"MailboxID\":{},\"MessageID\":{},\"ReceivedAt\":{},\"OperationID\":{},\"Action\":{},\"ExpectedGeneration\":{},\"TargetOperationID\":{}}}",
                input::go_string(&body.mailbox_id),
                input::go_string(&body.message_id),
                input::go_string(&body.received_at),
                input::go_string(&body.operation_id),
                input::go_string(&body.action),
                input::go_string(&body.expected_generation),
                input::go_string(&body.target_operation_id),
            );
            let digest = sha_hex(&encoded);
            let action = db::ControlAction {
                mailbox,
                message,
                received_at: &at,
                operation_id: operation_id.as_deref().expect("checked"),
                action: &body.action,
                generation: generation.expect("checked"),
                digest: &digest,
                target_operation: target_operation.as_deref(),
            };
            match db::sender_control_action(worker, actor, &action, operation).await {
                CommandOutcome::Committed(raw) => control_write(&out, raw),
                CommandOutcome::RolledBack(e) => classified(
                    state(&e),
                    "sender control action failed",
                    &stripped,
                    &lang,
                    &out,
                ),
                CommandOutcome::Unknown { operation } => unknown(operation),
            }
        }
        A::TrustedList => match db::trusted_list(worker, user).await {
            Ok(body) => out.json(body, 200),
            Err(_) => out.bare(500, "database error"),
        },
        A::TrustedAdd | A::TrustedRemove => {
            let add = what == A::TrustedAdd;
            let raw = if add {
                let Ok(body) = input::lenient::<input::Sender>(&mut r).await else {
                    return out.bare(400, "invalid request body");
                };
                body.sender
            } else {
                segment(&path, 4)
            };
            let sender = input::normalize_sender(&raw);
            if sender.is_empty() {
                return out.bare(400, "invalid sender address");
            }
            match db::trusted_write(worker, actor, &sender, add, operation).await {
                CommandOutcome::Committed(_) if add => out.json(
                    setjoin_mail_security::done(format!(
                        "{{\"sender\":{}}}",
                        setjoin_mail_security::s(&sender)
                    )),
                    200,
                ),
                CommandOutcome::Committed(_) => out.no_content(),
                CommandOutcome::RolledBack(_) => out.bare(500, "database error"),
                CommandOutcome::Unknown { operation } => unknown(operation),
            }
        }
        A::ExternalGet => out.json(db::external_get(worker, user).await, 200),
        A::ExternalPut => {
            let Ok(body) = input::lenient::<input::External>(&mut r).await else {
                return out.bare(400, "invalid json");
            };
            let Some(enabled) = body.enabled else {
                return out.bare(400, "enabled is required");
            };
            match db::external_put(worker, actor, enabled, operation).await {
                CommandOutcome::Committed(_) => {
                    out.send("{\"status\":\"ok\"}\n".into(), 200, Kind::Plain, None)
                }
                CommandOutcome::RolledBack(_) => out.bare(500, "database error"),
                CommandOutcome::Unknown { operation } => unknown(operation),
            }
        }
        A::Report => {
            let Ok(on) = db::sender_control_on(worker).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            if on {
                return out.bare(409, "use the message-bound sender control report action");
            }
            let Ok(body) = input::lenient::<input::Report>(&mut r).await else {
                return out.bare(400, "invalid JSON");
            };
            if body.email_id.is_empty() {
                return out.bare(400, "emailId is required");
            }
            if !matches!(body.kind.as_str(), "spam" | "phishing" | "concern") {
                return out.json(
                    setjoin_mail_security::done(
                        "{\"error\":\"invalid type; must be spam, phishing, or concern\"}".into(),
                    ),
                    400,
                );
            }
            let Some(message) = int(&body.email_id) else {
                return out.bare(400, "invalid emailId");
            };
            let note = if body.note.is_empty() {
                format!("User-reported {}", body.kind)
            } else {
                body.note.clone()
            };
            match db::report(worker, actor, message, &body.kind, &note, operation).await {
                CommandOutcome::Committed(true) => out.json(
                    setjoin_mail_security::done(format!(
                        "{{\"status\":\"reported\",\"type\":{}}}",
                        setjoin_mail_security::s(&body.kind)
                    )),
                    201,
                ),
                CommandOutcome::Committed(false) => out.bare(404, "message not found"),
                CommandOutcome::RolledBack(_) => out.bare(500, "database error"),
                CommandOutcome::Unknown { operation } => unknown(operation),
            }
        }
        _ => unreachable!("not a spam action"),
    }
}

/// `senderControlWrite`: ETag only when the reducer gave a generation, always 200.
fn control_write(out: &Out<'_>, raw: db::Raw) -> Response<Body> {
    let tag = (!raw.generation.is_empty()).then_some(raw.generation.as_str());
    out.send(raw.body, 200, Kind::Raw, tag)
}
