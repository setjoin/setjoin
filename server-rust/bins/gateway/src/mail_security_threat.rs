//! F06 slice `threat`: HTTP side of the four threat views and the IP-rule routes. Reads and
//! writes live in `setjoin_mail_security::threat`; this file decodes the requests as Go's
//! handlers do and renders Go's exact answers (`httputil.WriteProblem` bodies, the CSV
//! download, the JSON envelopes).
use crate::admin_identity_input::query;
use crate::mail_security::{segment, segment_path, Action};
use crate::mail_security_input as input;
use crate::mailboxes::{language, render, unknown_outcome};
use crate::problem::Problem;
use crate::{Body, RequestContext};
use hyper::{Request, Response};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_mail_security::sql as mailsec_sql;
use setjoin_mail_security::threat as db;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure};

const NOT_FOUND: &str = "https://setjoin.com/errors/not-found";
const INTERNAL: &str = "https://setjoin.com/errors/internal-error";

/// Execute the worker-only `lockout_count` / `lockout_list` accessors (`auth_lockouts`
/// is deny-all FORCE RLS and the accessors are `REVOKE ALL FROM setjoin_app`).
async fn worker_lockouts(
    worker: &ScopedExecutor,
    query: &db::Query<'_>,
) -> Result<(Vec<db::Item>, i64), StatementFailure> {
    let bad = || StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid lockout result".into(),
    };
    let limit = i32::try_from(query.limit).map_err(|_| bad())?;
    let offset = i32::try_from(query.offset).map_err(|_| bad())?;
    let (column, dir) = db::lockout_sort(query);
    let pool = worker.try_worker_pool().ok_or_else(bad)?;
    let mut tx = pool.begin_repeatable_read_only().await?;
    let total = tx
        .query_contract(&mailsec_sql::THREAT_LOCKOUT_COUNT, &[&query.q])
        .await?
        .first()
        .and_then(|r| r.try_get::<_, i64>(0).ok())
        .ok_or_else(bad)?;
    let rows = tx
        .query_contract(
            &mailsec_sql::THREAT_LOCKOUT_LIST,
            &[&query.q, &limit, &offset, &column, &dir],
        )
        .await?;
    tx.commit().await?;
    Ok((
        rows.iter()
            .filter_map(|r| db::lockout_item(r).ok())
            .collect(),
        total,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle(
    what: Action,
    mut r: Request<Body>,
    c: &RequestContext,
    id: &str,
    operation: [u8; 16],
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    worker: &ScopedExecutor,
) -> Response<Body> {
    let head = r.method() == hyper::Method::HEAD;
    let path = r.uri().path().to_owned();
    let lang = language(&r);
    // Go's `WriteProblem`: instance is the stripped path, language from the request.
    let problem = |p: Problem<'_>| render(p.instance(&segment_path(&path)), Some(&lang), c, id);
    let simple = |status: u16, detail: &str| problem(Problem::new(status, detail));
    let internal = || {
        problem(
            Problem::new(500, db::INTERNAL_DETAIL)
                .kind(INTERNAL)
                .title("Internal Server Error"),
        )
    };
    let reply = |body: String, status: u16| {
        // net/http buffers 2 KiB of a handler's output; a larger single write is flushed
        // before the handler returns and sent chunked.
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
    let get = |name: &str| query(r.uri(), name).unwrap_or_default();
    match what {
        Action::ThreatView => {
            let name = segment(&path, 4);
            let Some(view) = db::View::named(&name) else {
                return problem(
                    Problem::new(404, &db::unknown_view_detail(&name))
                        .kind(NOT_FOUND)
                        .title("Not Found"),
                );
            };
            // PostgreSQL refuses a parameter that is not valid UTF-8: Go's query fails.
            let bad_text = |name: &str| {
                crate::compliance_export::query_bytes(r.uri(), name)
                    .is_some_and(|v| std::str::from_utf8(&v).is_err())
            };
            let (limit, offset) = db::page(&get("limit"), &get("offset"));
            let (since, q, sort, dir) = (get("since"), get("q"), get("sort"), get("dir"));
            if bad_text("q") || (view == db::View::Attempts && bad_text("since")) {
                return internal();
            }
            let spec = db::Query {
                limit,
                offset,
                since: &since,
                q: &q,
                sort: &sort,
                dir: &dir,
            };
            let fetched = if view == db::View::Lockouts {
                worker_lockouts(worker, &spec).await
            } else {
                db::rows(factory, admin, view, &spec).await
            };
            let Ok((items, total)) = fetched else {
                return internal();
            };
            if get("format") == "csv" {
                let mut response = reply(db::view_csv(view, &items), 200);
                let headers = response.headers_mut();
                headers.insert(
                    "content-type",
                    hyper::header::HeaderValue::from_static("text/csv"),
                );
                let day = chrono::Local::now().format("%Y%m%d");
                headers.insert(
                    "content-disposition",
                    format!("attachment; filename=threat-{name}-{day}.csv")
                        .parse()
                        .expect("header"),
                );
                return response;
            }
            reply(db::view_json(&items, total, limit, offset), 200)
        }
        Action::IpRulesList => {
            let (limit, offset) = db::page(&get("limit"), &get("offset"));
            match db::ip_rules_list(factory, admin, limit, offset).await {
                Ok(body) => reply(body, 200),
                Err(_) => internal(),
            }
        }
        Action::IpRuleCreate => {
            let Ok(body) = input::lenient::<input::IpRule>(&mut r).await else {
                return simple(
                    400,
                    "request body must be JSON with cidr, action, and description fields",
                );
            };
            if let Err(error) = db::parse_prefix(&body.cidr) {
                return simple(
                    400,
                    &format!(
                        "invalid CIDR {}: {error}",
                        setjoin_contracts::go_quote::quote(body.cidr.as_bytes())
                    ),
                );
            }
            if body.action != "allow" && body.action != "block" {
                return simple(
                    400,
                    &format!(
                        "action must be 'allow' or 'block', got {}",
                        setjoin_contracts::go_quote::quote(body.action.as_bytes())
                    ),
                );
            }
            if body.description.is_empty() {
                return simple(400, "description is required");
            }
            let ip = c.identity.client_ip.to_string();
            match db::ip_rule_create(
                factory,
                admin,
                &ip,
                &body.cidr,
                &body.action,
                &body.description,
                body.expires.as_deref(),
                operation,
            )
            .await
            {
                CommandOutcome::Committed(new) => reply(db::created_body(new), 201),
                CommandOutcome::RolledBack(_) => internal(),
                CommandOutcome::Unknown { operation } => unknown_outcome(operation, c, id),
            }
        }
        Action::IpRuleDelete => {
            let Some(target) = segment(&path, 5).parse::<i64>().ok().filter(|n| *n > 0) else {
                return simple(400, "id must be a positive integer");
            };
            let ip = c.identity.client_ip.to_string();
            match db::ip_rule_delete(factory, admin, &ip, target, operation).await {
                CommandOutcome::Committed(true) => {
                    let mut response = crate::jmap::reply::response(
                        String::new(),
                        c.identity.proto,
                        id.to_owned(),
                    );
                    *response.status_mut() = hyper::StatusCode::NO_CONTENT;
                    response.headers_mut().remove("content-type");
                    response
                }
                CommandOutcome::Committed(false) => problem(
                    Problem::new(404, &format!("ip_rule {target} not found"))
                        .kind(NOT_FOUND)
                        .title("Not Found"),
                ),
                CommandOutcome::RolledBack(_) => internal(),
                CommandOutcome::Unknown { operation } => unknown_outcome(operation, c, id),
            }
        }
        _ => unreachable!("only threat actions are dispatched here"),
    }
}
