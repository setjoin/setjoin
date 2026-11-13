//! F06 slice `dlp`: HTTP side of the DLP pattern list/replace, anti-phishing configuration and
//! link-protect audit list routes. Database work lives in `setjoin_mail_security::dlp`; this file
//! decodes the requests as Go's handlers do and renders Go's exact answers.
use crate::mail_security::Action;
use crate::mail_security_input as input;
use crate::mailboxes::{bare, unknown_outcome};
use crate::{Body, RequestContext};
use hyper::{Request, Response};
use setjoin_authz::AuthContext;
use setjoin_mail_security::dlp as db;
use setjoin_pg::{CommandOutcome, ScopedExecutor};

/// Go's `time.Time.Format(time.RFC3339)` in the process's local zone.
fn local_rfc3339(epoch: i64) -> String {
    use chrono::{Local, SecondsFormat, TimeZone};
    Local
        .timestamp_opt(epoch, 0)
        .single()
        .map(|t| t.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle(
    what: Action,
    mut r: Request<Body>,
    c: &RequestContext,
    id: &str,
    operation: [u8; 16],
    actor: &AuthContext,
    worker: &ScopedExecutor,
    domain_scope: i64,
) -> Response<Body> {
    let head = r.method() == hyper::Method::HEAD;
    let reply = |body: String, status: u16| {
        let chunked = body.len() > 2048 && !head;
        let mut response = crate::jmap::reply::response(body, c.identity.proto, id.to_owned());
        *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
        if chunked {
            response.headers_mut().insert(
                "transfer-encoding",
                hyper::header::HeaderValue::from_static("chunked"),
            );
        }
        response
    };
    let empty = |status: u16| {
        let mut response =
            crate::jmap::reply::response(String::new(), c.identity.proto, id.to_owned());
        *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
        response.headers_mut().remove("content-type");
        response
    };
    match what {
        Action::DlpGet => match db::patterns_get(worker, domain_scope).await {
            Ok(body) => reply(body, 200),
            Err(_) => bare(500, "failed to load patterns", c, id),
        },
        Action::DlpPut => {
            if domain_scope > 0 {
                return bare(
                    403,
                    "scoped admins cannot modify global DLP patterns",
                    c,
                    id,
                );
            }
            let Ok(rows) = crate::admin_identity_input::first::<Option<Vec<input::DlpPattern>>>(
                &mut r,
                1 << 20,
            )
            .await
            else {
                return bare(400, "invalid JSON", c, id);
            };
            let patterns: Vec<db::Pattern> = rows
                .unwrap_or_default()
                .into_iter()
                .map(|p| db::Pattern {
                    name: p.name,
                    regex: p.regex,
                    severity: p.severity,
                    enabled: p.enabled,
                })
                .collect();
            match db::patterns_put(worker, actor, &patterns, operation).await {
                Ok(()) => empty(200),
                Err(db::ReplaceError::Clear) => bare(500, "failed to clear patterns", c, id),
                Err(db::ReplaceError::Save) => bare(500, "failed to save patterns", c, id),
                Err(db::ReplaceError::Unknown(operation)) => {
                    unknown_outcome(setjoin_contracts::ids::OperationId(operation), c, id)
                }
            }
        }
        Action::AntiPhishGet => match db::antiphish_get(worker).await {
            Ok(body) => reply(body, 200),
            Err(_) => bare(500, "database error", c, id),
        },
        Action::AntiPhishPut => {
            let Ok(body) = input::lenient::<input::AntiPhishBody>(&mut r).await else {
                return bare(400, "invalid JSON", c, id);
            };
            let body = db::AntiPhish {
                display_name: body.display_name,
                lookalike: body.lookalike,
                contact_graph: body.contact_graph,
                strict_mode: body.strict_mode,
                domains: body.domains,
                users: body.users,
            };
            match db::antiphish_put(worker, actor, &body, operation).await {
                CommandOutcome::Committed(()) => empty(204),
                CommandOutcome::RolledBack(_) => bare(500, "database error", c, id),
                CommandOutcome::Unknown { operation } => unknown_outcome(operation, c, id),
            }
        }
        Action::LinkAudit => {
            let get =
                |name: &str| crate::admin_identity_input::query(r.uri(), name).unwrap_or_default();
            let mut limit = crate::admin_identity_input::atoi(&get("limit"));
            if limit <= 0 || limit > 100 {
                limit = 50;
            }
            let since_text = get("since");
            let mut since = None;
            if !since_text.is_empty() {
                let Ok(parsed) = crate::go_time::parse_rfc3339(&since_text) else {
                    return reply(
                        setjoin_mail_security::done(
                            "{\"error\":\"invalid since format, use RFC 3339\"}".into(),
                        ),
                        400,
                    );
                };
                let utc = parsed.with_timezone(&chrono::Utc);
                // A zero `time.Time` (0001-01-01T00:00:00Z) adds no filter.
                if utc.timestamp() != -62_135_596_800 || utc.timestamp_subsec_nanos() != 0 {
                    since = Some(format!(
                        "{}.{:06}Z",
                        utc.format("%Y-%m-%dT%H:%M:%S"),
                        utc.timestamp_subsec_micros()
                    ));
                }
            }
            let rows = match db::audit_list(worker, since.as_deref(), &get("url_hash"), limit).await
            {
                Ok(rows) => rows,
                Err(_) => return bare(500, "database error", c, id),
            };
            let s = setjoin_mail_security::s;
            let items = rows
                .iter()
                .map(|i| {
                    format!(
                        "{{\"id\":{},\"url_hash\":{},\"verdict\":{},\"scanner\":{},\"message_id\":{},\"mailbox_id\":{},\"client_ip\":{},\"created_at\":{}}}",
                        i.id,
                        s(&i.url_hash),
                        s(&i.verdict),
                        s(&i.scanner),
                        i.message_id.unwrap_or_default(),
                        i.mailbox_id,
                        s(i.client_ip.as_deref().unwrap_or_default()),
                        s(&local_rfc3339(i.epoch)),
                    )
                })
                .collect::<Vec<_>>();
            let list = if items.is_empty() {
                "null".to_owned()
            } else {
                format!("[{}]", items.join(","))
            };
            reply(
                setjoin_mail_security::done(format!(
                    "{{\"count\":{},\"items\":{list}}}",
                    items.len()
                )),
                200,
            )
        }
        _ => unreachable!("only dlp actions are dispatched here"),
    }
}
