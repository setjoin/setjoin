//! F04 chat-compliance adapter, shared by executable and recorded HTTP replay.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;
pub struct ChatComplianceRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub worker: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    pub database: setjoin_pg::workers::WorkerDatabase,
    pub store: Option<Arc<crate::recovery_worker::S3Store>>,
}
impl<K: KeySource + 'static> Intercept for ChatComplianceRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        let method = if r.method() == hyper::Method::HEAD {
            "GET"
        } else {
            r.method().as_str()
        };
        [
            ("GET", "/admin/chat-retention-policies"),
            ("POST", "/admin/chat-retention-policies"),
            ("PUT", "/admin/chat-retention-policies/{id}"),
            ("DELETE", "/admin/chat-retention-policies/{id}"),
            ("GET", "/admin/chat-ediscovery/cases"),
            ("GET", "/admin/chat-ediscovery/export"),
            ("GET", "/admin/chat-ediscovery/holds"),
            ("POST", "/admin/chat-ediscovery/holds"),
            ("POST", "/admin/chat-ediscovery/holds/{id}/release"),
            ("POST", "/admin/chat-ediscovery/search"),
            ("GET", "/admin/chat-ediscovery/channels/{id}/messages"),
            ("GET", "/admin/chat-purge/preview"),
            ("GET", "/admin/chat-compliance/overview"),
        ]
        .iter()
        .any(|(m, p)| {
            method == *m
                && crate::inventory::path_score(&format!("/api{p}"), r.uri().path()).is_some()
        })
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_request(&exec, &keys, &issuer, &h, s)
                .await
                .is_some()
        })
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        let worker = self.worker.clone();
        let database = self.database.clone();
        let store = self.store.clone();
        Box::pin(async move {
            let mut nonce = [0; 16];
            if getrandom::getrandom(&mut nonce).is_err() {
                return c.upstream.forward(r, &c.identity).await;
            }
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), nonce);
            let mount = r.uri().path().split('/').nth(1).unwrap_or("");
            if mount != "api" && crate::inventory::unescape(mount) == b"api" {
                let mut reply = crate::jmap::reply::response(
                    "404 page not found\n".into(),
                    c.identity.proto,
                    id,
                );
                *reply.status_mut() = hyper::StatusCode::NOT_FOUND;
                reply.headers_mut().insert(
                    "content-type",
                    "text/plain; charset=utf-8".parse().expect("header"),
                );
                return reply;
            }
            let decoded = crate::chat::go_utf8(&crate::inventory::unescape(r.uri().path()));
            let path = decoded.strip_prefix("/api").unwrap_or(&decoded).to_owned();
            let Some(auth) = setjoin_authz::authorize_request(
                &exec,
                &keys,
                &issuer,
                r.headers(),
                c.identity.proto,
            )
            .await
            else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let authority = match setjoin_compliance::authority(&exec, auth.context()).await {
                Ok(v) => v,
                Err(_) => return c.upstream.forward(r, &c.identity).await,
            };
            let write = !matches!(r.method().as_str(), "GET" | "HEAD");
            let required: &[&str] = if path == "/admin/chat-ediscovery/export"
                || path == "/admin/chat-ediscovery/search"
                || path.starts_with("/admin/chat-ediscovery/channels/")
            {
                &["chat.ediscovery"]
            } else if write {
                &["chat.compliance_manage"]
            } else {
                &["chat.compliance_view", "chat.compliance_manage"]
            };
            if !authority.allows_any(required) {
                let _ = setjoin_compliance::console_denied(
                    &exec,
                    auth.context(),
                    &path,
                    &required.join("|"),
                    nonce,
                )
                .await;
                let mut reply = crate::chat::problem(403, "Forbidden", "", &c, id);
                reply.headers_mut().remove("content-language");
                return reply;
            }
            match exec.read("SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.chat_compliance'),false)",&[]).await{Ok(v)if v[0].get::<_,bool>(0)=>{},Ok(_)=>{let mut reply=crate::chat::problem(404,"not found","",&c,id);reply.headers_mut().remove("content-language");return reply;},Err(_)=>return c.upstream.forward(r,&c.identity).await}
            let language = crate::chat_channels::problem_language(r.headers());
            let mut response=async {
            if path == "/admin/chat-ediscovery/export" {
                let raw=crate::chat::query(&r,"caseId").unwrap_or_default();
                if raw.is_empty(){return crate::chat::problem(400,"caseId is required",&path,&c,id);}
                let Ok(case)=raw.parse::<i64>() else{return crate::chat::problem(400,"invalid caseId",&path,&c,id);};
                let mut channels=Vec::new();
                let raw=crate::compliance_export::query_bytes(r.uri(),"channels").unwrap_or_default();
                for part in raw.split(|b|*b==b',') {
                    let decoded=crate::chat::go_utf8(part);
                    let leading=decoded.len()-decoded.trim_start().len();let trailing=decoded.len()-decoded.trim_end().len();
                    if leading==part.len(){continue;}
                    let part=&part[leading..part.len()-trailing];if part.is_empty(){continue;}
                    let n=match std::str::from_utf8(part).ok().and_then(|s|s.parse::<i64>().ok()){Some(n)=>n,None=>{let reason=channel_parse_error(part);let quoted=setjoin_contracts::go_quote::quote(part);return crate::chat::problem(400,&format!("invalid channel id {quoted}: strconv.ParseInt: parsing {quoted}: {reason}"),&path,&c,id);}};channels.push(n);
                }
                if channels.is_empty(){return crate::chat::problem(400,"channels is required",&path,&c,id);}
                let query=serde_json::json!({"channels":channels,"includeAttachments":crate::chat::query(&r,"includeAttachments").as_deref()==Some("1")});
                let result=setjoin_compliance::chat::command(&worker,auth.context(),"export",&serde_json::json!({"caseId":case,"query":query}),&c.identity.client_ip.to_string(),nonce).await;
                if let setjoin_pg::CommandOutcome::Committed(v)=&result {
                    if v["status"]==200 {
                        if let Some(begin)=v["raw"].as_str().and_then(|s|serde_json::from_str(s).ok()) {
                            return crate::chat_compliance_export::response(database,store,r.method()==hyper::Method::HEAD,case,auth.context().user_id(),query,begin,&c,id).await;
                        }
                        return crate::chat::problem(500,"database error",&path,&c,id);
                    }
                }
                return command(result,&path,&c,id);
            }
            if path.starts_with("/admin/chat-ediscovery/channels/") {
                let Some(channel) = path
                    .strip_prefix("/admin/chat-ediscovery/channels/")
                    .and_then(|s| s.strip_suffix("/messages"))
                    .and_then(|s| s.parse::<i64>().ok())
                else {
                    return crate::chat::problem(400, "invalid channel id", &path, &c, id);
                };
                let case = crate::chat::query(&r, "caseId").unwrap_or_default();
                if case.is_empty() {
                    return crate::chat::problem(400, "caseId is required", &path, &c, id);
                }
                let Ok(case) = case.parse::<i64>() else {
                    return crate::chat::problem(400, "invalid caseId", &path, &c, id);
                };
                let before = match optional_query(&r, "beforeId") {
                    Ok(v) => v,
                    Err(_) => return crate::chat::problem(400, "invalid beforeId", &path, &c, id),
                };
                let limit = match optional_query(&r, "limit") {
                    Ok(v) => v.unwrap_or(100),
                    Err(_) => return crate::chat::problem(400, "invalid limit", &path, &c, id),
                };
                let data = serde_json::json!({"caseId":case,"channelId":channel,"beforeId":before,"limit":limit});
                return command(
                    setjoin_compliance::chat::command(
                        &worker,
                        auth.context(),
                        "read",
                        &data,
                        &c.identity.client_ip.to_string(),
                        nonce,
                    )
                    .await,
                    &path,
                    &c,
                    id,
                );
            }
            if path == "/admin/chat-ediscovery/search" {
                let bytes = match crate::chat_channels::read_body(&mut r).await {
                    Ok(v) => v,
                    Err(_) => return crate::chat::problem(400, "invalid JSON", &path, &c, id),
                };
                let fields = match crate::chat_channels::decode_fields(&bytes) {
                    Ok(v) => v,
                    Err(_) => return crate::chat::problem(400, "invalid JSON", &path, &c, id),
                };
                let data = match search_input(&fields) {
                    Ok(v) => v,
                    Err(detail) => return crate::chat::problem(400, detail, &path, &c, id),
                };
                return command(
                    setjoin_compliance::chat::command(
                        &worker,
                        auth.context(),
                        "search",
                        &data,
                        &c.identity.client_ip.to_string(),
                        nonce,
                    )
                    .await,
                    &path,
                    &c,
                    id,
                );
            }
            if r.method() == hyper::Method::POST && path == "/admin/chat-ediscovery/holds" {
                let data=async {let bytes=crate::chat_channels::read_body(&mut r).await.map_err(|_|())?;let f=crate::chat_channels::decode_fields(&bytes)?;Ok::<_,()>(serde_json::json!({"caseId":crate::chat_channels::number_field(&f,"CASEID")?,"custodianUserId":crate::chat_channels::optional_field::<i64>(&f,"CUSTODIANUSERID")?,"channelId":crate::chat_channels::optional_field::<i64>(&f,"CHANNELID")?,"reason":crate::chat_channels::text_field(&f,"REASON")?}))}.await;
                let data = match data {
                    Ok(v) => v,
                    Err(_) => return crate::chat::problem(400, "invalid JSON", &path, &c, id),
                };
                return command(
                    setjoin_compliance::chat::command(
                        &exec,
                        auth.context(),
                        "hold",
                        &data,
                        &c.identity.client_ip.to_string(),
                        nonce,
                    )
                    .await,
                    &path,
                    &c,
                    id,
                );
            }
            if r.method() == hyper::Method::POST
                && path.starts_with("/admin/chat-ediscovery/holds/")
                && path.ends_with("/release")
            {
                let Some(hold) = path
                    .strip_prefix("/admin/chat-ediscovery/holds/")
                    .and_then(|s| s.strip_suffix("/release"))
                    .and_then(|s| s.parse::<i64>().ok())
                else {
                    return crate::chat::problem(400, "invalid hold id", &path, &c, id);
                };
                let data=async{let bytes=crate::chat_channels::read_body(&mut r).await.map_err(|_|())?;let f=crate::chat_channels::decode_fields(&bytes)?;Ok::<_,()>(serde_json::json!({"holdId":hold,"reason":crate::chat_channels::text_field(&f,"REASON")?}))}.await;
                let data = match data {
                    Ok(v) => v,
                    Err(_) => return crate::chat::problem(400, "invalid JSON", &path, &c, id),
                };
                return command(
                    setjoin_compliance::chat::command(
                        &exec,
                        auth.context(),
                        "release",
                        &data,
                        &c.identity.client_ip.to_string(),
                        nonce,
                    )
                    .await,
                    &path,
                    &c,
                    id,
                );
            }
            if write {
                let action = match r.method().as_str() {
                    "PUT" => "update",
                    "DELETE" => "delete",
                    _ => "create",
                };
                let target = if action != "create" {
                    match path
                        .strip_prefix("/admin/chat-retention-policies/")
                        .and_then(|s| s.parse::<i64>().ok())
                    {
                        Some(n) => n,
                        None => {
                            return crate::chat::problem(400, "invalid policy id", &path, &c, id)
                        }
                    }
                } else {
                    0
                };
                if action == "delete" {
                    let confirm = crate::chat::query(&r, "confirm").unwrap_or_default();
                    let result = setjoin_compliance::chat::policy(
                        &exec,
                        auth.context(),
                        action,
                        target,
                        &serde_json::json!({}),
                        &confirm,
                        &c.identity.client_ip.to_string(),
                        nonce,
                    )
                    .await;
                    return command(result, &path, &c, id);
                }
                let bytes = match crate::chat_channels::read_body(&mut r).await {
                    Ok(v) => v,
                    Err(_) => return crate::chat::problem(400, "invalid JSON", &path, &c, id),
                };
                let fields = match crate::chat_channels::decode_fields(&bytes) {
                    Ok(v) => v,
                    Err(_) => return crate::chat::problem(400, "invalid JSON", &path, &c, id),
                };
                let parsed = (|| {
                    Ok::<_, ()>(
                        serde_json::json!({"name":crate::chat_channels::text_field(&fields,"NAME")?,"appliesTo":crate::chat_channels::text_field(&fields,"APPLIESTO")?,"durationDays":crate::chat_channels::number_field(&fields,"DURATIONDAYS")?,"enabled":crate::chat_channels::bool_field(&fields,"ENABLED")?}),
                    )
                })();
                let data = match parsed {
                    Ok(v) => v,
                    Err(_) => return crate::chat::problem(400, "invalid JSON", &path, &c, id),
                };
                if !matches!(
                    data["appliesTo"].as_str(),
                    Some("channel" | "dm" | "group_dm" | "all")
                ) {
                    return crate::chat::problem(
                        422,
                        "appliesTo must be one of channel, dm, group_dm, all",
                        &path,
                        &c,
                        id,
                    );
                }
                if data["durationDays"].as_i64().unwrap_or(0) <= 0 {
                    return crate::chat::problem(
                        422,
                        "durationDays must be a positive integer",
                        &path,
                        &c,
                        id,
                    );
                }
                if action == "create" && data["name"] == "" {
                    return crate::chat::problem(422, "name is required", &path, &c, id);
                }
                let result = setjoin_compliance::chat::policy(
                    &exec,
                    auth.context(),
                    action,
                    target,
                    &data,
                    "",
                    &c.identity.client_ip.to_string(),
                    nonce,
                )
                .await;
                return command(result, &path, &c, id);
            }
            if path == "/admin/chat-ediscovery/holds" {
                let value = crate::chat::query(&r, "caseId").unwrap_or_default();
                if value.is_empty() {
                    return crate::chat::problem(400, "caseId is required", &path, &c, id);
                }
                let Ok(case) = value.parse::<i64>() else {
                    return crate::chat::problem(400, "invalid caseId", &path, &c, id);
                };
                let body = match setjoin_compliance::chat::holds(&worker, case).await {
                    Ok(v) => v,
                    Err(_) => return crate::chat::problem(500, "database error", &path, &c, id),
                };
                let mut op = [0; 16];
                if getrandom::getrandom(&mut op).is_ok() {
                    setjoin_compliance::chat::audit(
                        &exec,
                        auth.context(),
                        "chat_case_hold_list",
                        "ediscovery_case",
                        case,
                        &c.identity.client_ip.to_string(),
                        op,
                    )
                    .await;
                }
                return crate::compliance::json_response(200, body, &c, id);
            }
            if path == "/admin/chat-compliance/overview" {
                let now = chrono::Local::now();
                // Go time.Date chooses its offset by looking up the naive UTC instant,
                // then looking up the candidate UTC instant if it crosses a transition.
                let naive = now
                    .date_naive()
                    .and_hms_opt(2, 50, 0)
                    .expect("valid clock")
                    .and_utc()
                    .timestamp();
                let local_at = |unix| {
                    chrono::DateTime::from_timestamp(unix, 0)
                        .expect("current date")
                        .with_timezone(&chrono::Local)
                };
                let first = local_at(naive).offset().local_minus_utc();
                let offset = local_at(naive - i64::from(first))
                    .offset()
                    .local_minus_utc();
                let mut next = local_at(naive - i64::from(offset));
                if next <= now {
                    next += chrono::Duration::hours(24);
                }
                let result = setjoin_compliance::chat::overview(
                    &worker,
                    &next.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                )
                .await;
                return match result {
                    Ok(raw) => match crate::jmap::reply::go_compact(&raw) {
                        Some(raw) => crate::compliance::json_response(200, raw + "\n", &c, id),
                        None => crate::chat::problem(500, "database error", &path, &c, id),
                    },
                    Err(_) => crate::chat::problem(500, "database error", &path, &c, id),
                };
            }
            let result = if path == "/admin/chat-purge/preview" {
                setjoin_compliance::chat::preview(&worker).await
            } else if path == "/admin/chat-ediscovery/cases" {
                setjoin_compliance::chat::cases(&exec).await
            } else {
                setjoin_compliance::chat::policies(&exec).await
            };
            match result {
                Ok(body) => crate::compliance::json_response(200, body, &c, id),
                Err(_) => crate::chat::problem(500, "database error", &path, &c, id),
            }
            }.await;
            if response.headers().contains_key("content-language") {
                response.headers_mut().insert(
                    "content-language",
                    language.parse().expect("sanitized language tag"),
                );
            }
            response
        })
    }
}

fn command(
    result: setjoin_pg::CommandOutcome<serde_json::Value, setjoin_pg::StatementFailure>,
    path: &str,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    match result {
        setjoin_pg::CommandOutcome::Committed(v) => {
            let status = v["status"].as_u64().unwrap_or(500) as u16;
            if let Some(error) = v["error"].as_str() {
                return crate::chat::problem(status, error, path, c, id);
            }
            if status == 403 {
                let mut r = crate::chat::problem(403, "Forbidden", "", c, id);
                r.headers_mut().remove("content-language");
                return r;
            }
            if let Some(raw) = v["raw"].as_str() {
                return match crate::jmap::reply::go_compact(raw) {
                    Some(raw) => crate::compliance::json_response(
                        status,
                        setjoin_compliance::finish(raw),
                        c,
                        id,
                    ),
                    None => crate::chat::problem(500, "database error", path, c, id),
                };
            }
            if status == 204 {
                let mut r = crate::compliance::json_response(204, String::new(), c, id);
                r.headers_mut().remove("content-type");
                return r;
            }
            crate::compliance::json_response(
                status,
                setjoin_compliance::finish(v["body"].to_string()),
                c,
                id,
            )
        }
        setjoin_pg::CommandOutcome::Unknown { operation, .. } => {
            crate::compliance::unknown(operation.0, c, &id)
        }
        setjoin_pg::CommandOutcome::RolledBack(error) => rejected(&error, path, c, id),
    }
}

fn rejected(
    error: &setjoin_pg::Rejection<setjoin_pg::StatementFailure>,
    path: &str,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let code = match error {
        setjoin_pg::Rejection::Statement(e) | setjoin_pg::Rejection::Body(e) => {
            e.sqlstate.as_deref()
        }
        _ => None,
    };
    let (status, detail, remediation) = match code {
        Some("BZ191" | "BZ195" | "BZ197" | "BZ210") => (
            422,
            "unprocessable",
            "Correct the requested operation using the documented runbook and retry.",
        ),
        Some("BZ192" | "BZ193" | "BZ198") => (
            409,
            "conflict",
            "Refresh current state, resolve the conflict, and retry.",
        ),
        Some("BZ194") => (
            403,
            "forbidden",
            "Complete the required authorization, approval, or recovery step before retrying.",
        ),
        _ => return crate::chat::problem(500, "database error", path, c, id),
    };
    let code = code.expect("classified error");
    let kind = format!(
        "https://setjoin.com/problems/reducer/{}",
        code.to_ascii_lowercase()
    );
    let body = crate::problem::Problem::new(status, detail)
        .kind(&kind)
        .instance(path)
        .remediation(remediation)
        .code(code)
        .retryable(false)
        .body();
    let mut response = crate::chat::problem(status, detail, path, c, id);
    crate::problem::set_body(&mut response, body);
    response
}

fn search_input(f: &crate::chat::Fields) -> Result<serde_json::Value, &'static str> {
    use crate::chat_channels::{fold, number_field, optional_field, text_field};
    let decoded = (|| {
        let mut ids = Vec::new();
        for (k, v) in &f.0 {
            if fold(k) == "CHANNELIDS" {
                ids = serde_json::from_str::<Option<Vec<Option<i64>>>>(v.get())
                    .map_err(|_| ())?
                    .unwrap_or_default()
                    .into_iter()
                    .map(|n| n.unwrap_or(0))
                    .collect();
            }
        }
        Ok::<_, ()>((
            number_field(f, "CASEID")?,
            text_field(f, "TERMS")?,
            ids,
            optional_field::<i64>(f, "AUTHORID")?,
            optional_field::<String>(f, "DATEFROM")?,
            optional_field::<String>(f, "DATETO")?,
            optional_field::<i64>(f, "BEFOREID")?,
            optional_field::<i64>(f, "LIMIT")?,
        ))
    })();
    let (case, terms, ids, author, from, to, before, limit) =
        decoded.map_err(|_| "invalid JSON")?;
    if terms.trim().is_empty() {
        return Err("terms is required");
    }
    let mut query = serde_json::json!({"terms":terms});
    if !ids.is_empty() {
        query["channelIds"] = serde_json::json!(ids);
    }
    if let Some(author) = author {
        query["authorId"] = serde_json::json!(author);
    }
    for (key, value, detail) in [
        (
            "dateFrom",
            from,
            "invalid dateFrom (want RFC3339 or YYYY-MM-DD)",
        ),
        ("dateTo", to, "invalid dateTo (want RFC3339 or YYYY-MM-DD)"),
    ] {
        if let Some(value) = value {
            let bare = value.len() == 10
                && value.as_bytes().get(4) == Some(&b'-')
                && value.as_bytes().get(7) == Some(&b'-')
                && chrono::NaiveDate::parse_from_str(&value, "%Y-%m-%d").is_ok();
            if !valid_go_rfc3339(&value) && !bare {
                return Err(detail);
            }
            query[key] = serde_json::json!(value);
        }
    }
    Ok(
        serde_json::json!({"caseId":case,"query":query,"beforeId":before,"limit":limit.unwrap_or(50),"han":terms.chars().any(setjoin_contracts::han::contains)}),
    )
}

// `time.Parse` accepts hour24/minute60 offsets. Chrono's FixedOffset cannot
// represent >=24h, but this seam only validates: PostgreSQL still decides
// whether the original, unchanged date is a valid search bound.
fn valid_go_rfc3339(value: &str) -> bool {
    if crate::go_time::parse_rfc3339(value).is_ok() {
        return true;
    }
    let bytes = value.as_bytes();
    if bytes.len() < 6 {
        return false;
    }
    let at = bytes.len() - 6;
    let zone = &bytes[at..];
    if !matches!(zone[0], b'+' | b'-')
        || zone[3] != b':'
        || ![zone[1], zone[2], zone[4], zone[5]]
            .iter()
            .all(u8::is_ascii_digit)
    {
        return false;
    }
    let hour = (zone[1] - b'0') * 10 + zone[2] - b'0';
    let minute = (zone[4] - b'0') * 10 + zone[5] - b'0';
    hour <= 24
        && minute <= 60
        && crate::go_time::parse_rfc3339(&format!("{}+00:00", &value[..at])).is_ok()
}

fn optional_query(r: &Request<Body>, key: &str) -> Result<Option<i64>, ()> {
    crate::chat::query(r, key)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<i64>().map_err(|_| ()))
        .transpose()
}

// strconv.ParseInt first parses an unsigned 64-bit magnitude; a syntax error
// before unsigned overflow wins over signed overflow (e.g. maxInt64+1 + "x").
fn channel_parse_error(value: &[u8]) -> &'static str {
    let unsigned = if matches!(value.first(), Some(b'+' | b'-')) {
        &value[1..]
    } else {
        value
    };
    if unsigned.is_empty() {
        return "invalid syntax";
    }
    let mut magnitude = 0u64;
    for &digit in unsigned {
        if !digit.is_ascii_digit() {
            return "invalid syntax";
        }
        let Some(next) = magnitude
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(digit - b'0')))
        else {
            return "value out of range";
        };
        magnitude = next;
    }
    "value out of range"
}
