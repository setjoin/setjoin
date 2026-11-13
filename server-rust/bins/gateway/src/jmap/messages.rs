//! The four `/api/messages/{id}/*` REST routes (#469): focus, raw `.eml`
//! download, attachments zip and one-click unsubscribe. Same admission chain as
//! the mounted undo/recall actions; identity and ownership come only from the
//! verified token (R1-R3). Whatever this module cannot admit forwards whole.
use super::{reply, JmapCommands};
use crate::{Body, RequestContext};
use bytes::Bytes;
use http_body_util::BodyExt as _;
use hyper::{Method, Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_contracts::{
    command::CommandEnvelope,
    ids::{ActorId, Digest, MailboxId, OperationId},
};
use setjoin_pg::{CommandOutcome, MailboxAuthContext, Rejection};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Route {
    Focus,
    Download,
    Zip,
    Unsubscribe,
}

/// `(route, unescaped {id})` for `/api/messages/{id}/<tail>` with the route's
/// own method (Go's `GET` patterns also answer `HEAD`).
pub(super) fn target(method: &Method, path: &str) -> Option<(Route, String)> {
    let tail = path.strip_prefix("/api/messages/")?;
    let (id, leaf) = tail.split_once('/')?;
    let route = match (leaf, method) {
        ("focus", &Method::POST) => Route::Focus,
        ("unsubscribe", &Method::POST) => Route::Unsubscribe,
        ("download", &Method::GET | &Method::HEAD) => Route::Download,
        ("attachments.zip", &Method::GET | &Method::HEAD) => Route::Zip,
        _ => return None,
    };
    if id.is_empty() {
        return None;
    }
    Some((
        route,
        String::from_utf8_lossy(&crate::inventory::unescape(id)).into_owned(),
    ))
}

/// Go's `strings.Map` filename sanitiser: ASCII letters, digits, `-_.` stay,
/// every other rune becomes `_`; at most 100 bytes; empty becomes `message`.
pub(super) fn sanitize_filename(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    out.truncate(100);
    if out.is_empty() {
        out = "message".into();
    }
    out
}

/// Go's `strconv.ParseInt(s, 10, 64)` followed by the handlers' `> 0` rule.
fn positive_id(raw: &str) -> Option<i64> {
    raw.parse::<i64>().ok().filter(|id| *id > 0)
}

/// What Go's `json.NewDecoder(body).Decode(&struct{Focused bool})` accepts:
/// the first JSON value only (trailing bytes are never read), `null` or an
/// object, keys matched case-insensitively (ASCII and the long s), unknown
/// fields skipped without conversion, `null` leaving the field alone and any
/// non-boolean `focused` an error.
pub(super) fn decode_focus(body: &[u8]) -> Result<bool, ()> {
    use serde::de::{Deserialize, Deserializer, IgnoredAny, MapAccess, Visitor};
    struct Value(Option<bool>);
    impl<'de> Deserialize<'de> for Value {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Option<bool>;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("a boolean or null")
                }
                fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
                    Ok(Some(v))
                }
                fn visit_unit<E>(self) -> Result<Self::Value, E> {
                    Ok(None)
                }
            }
            d.deserialize_any(V).map(Value)
        }
    }
    struct Doc(bool);
    impl<'de> Deserialize<'de> for Doc {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = bool;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("an object or null")
                }
                fn visit_unit<E>(self) -> Result<bool, E> {
                    Ok(false)
                }
                fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
                    let mut focused = false;
                    while let Some(key) = map.next_key::<String>()? {
                        let folded: String = key
                            .chars()
                            .map(|c| match c {
                                '\u{17f}' => 's',
                                c => c.to_ascii_lowercase(),
                            })
                            .collect();
                        if folded == "focused" {
                            if let Some(v) = map.next_value::<Value>()?.0 {
                                focused = v;
                            }
                        } else {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                    Ok(focused)
                }
            }
            d.deserialize_any(V).map(Doc)
        }
    }
    // Go replaces invalid UTF-8 inside strings; outside strings it is a syntax
    // error either way, which the replacement character also is.
    let text = String::from_utf8_lossy(body);
    let mut de = serde_json::Deserializer::from_str(&text);
    Doc::deserialize(&mut de).map(|d| d.0).map_err(|_| ())
}

/// `extractUnsubscribeURL`: the first `<http(s)://...>` entry, else the first
/// `<mailto:...>`, else empty.
pub(super) fn extract_unsubscribe_url(header: &str) -> &str {
    fn entry(part: &str) -> Option<&str> {
        let part = part.trim();
        (part.len() > 2 && part.starts_with('<') && part.ends_with('>'))
            .then(|| &part[1..part.len() - 1])
    }
    for part in header.split(',') {
        if let Some(uri) = entry(part) {
            if uri.starts_with("https://") || uri.starts_with("http://") {
                return uri;
            }
        }
    }
    for part in header.split(',') {
        if let Some(uri) = entry(part) {
            if uri.starts_with("mailto:") {
                return uri;
            }
        }
    }
    ""
}

/// Go's `ssrf.ValidateURL` on `net/url` semantics.
pub(super) fn go_validate_url(raw: &str) -> bool {
    let Ok(parsed) = setjoin_authz::go_url::go_url_parse(raw) else {
        return false;
    };
    if parsed.scheme != "http" && parsed.scheme != "https" {
        return false;
    }
    let Ok(host) = setjoin_authz::go_url::parse_url_host(raw) else {
        return false;
    };
    host.parse::<std::net::IpAddr>()
        .map_or(true, |ip| !crate::ssrf::blocked(ip))
}

/// The URL the one-click POST may use. The client's resolver admits public
/// addresses only, but a literal address never reaches a resolver (and the URL
/// standard reads `2130706433` or `0x7f.1` as one), so a literal that is not
/// public is refused here. Any failure is the caller's to log and ignore.
pub(crate) fn one_click_target(raw: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(raw).map_err(|e| e.to_string())?;
    let refused = || "URL is not allowed (must be http/https to a public host)".to_owned();
    match url.host() {
        Some(url::Host::Ipv4(ip)) if crate::ssrf::blocked(std::net::IpAddr::V4(ip)) => {
            Err(refused())
        }
        Some(url::Host::Ipv6(ip)) if crate::ssrf::blocked(std::net::IpAddr::V6(ip)) => {
            Err(refused())
        }
        None => Err("no host".into()),
        _ => Ok(url),
    }
}

/// RFC 8058 one-click POST on the SSRF-safe client (no redirects, no proxy).
pub(crate) async fn post_one_click(client: &reqwest::Client, raw: &str) -> Result<(), String> {
    send_one_click(client, one_click_target(raw)?).await
}

async fn send_one_click(client: &reqwest::Client, url: reqwest::Url) -> Result<(), String> {
    client
        .post(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .body("List-Unsubscribe=One-Click")
        .send()
        .await
        .map(drop)
        .map_err(|e| e.to_string())
}

struct Admitted {
    user: i64,
    mailbox: i64,
    auth: MailboxAuthContext,
    request_id: String,
}

impl<K: KeySource> JmapCommands<K> {
    pub(super) async fn serve_message(
        &self,
        route: Route,
        raw_id: String,
        req: Request<Body>,
        ctx: RequestContext,
    ) -> Response<Body> {
        let (parts, body) = req.into_parts();
        let body = if route == Route::Focus {
            match super::buffer(body).await {
                super::Buffered::Whole(bytes) => Ok(bytes),
                super::Buffered::Forward(rest) => Err(rest),
            }
        } else {
            Ok(Bytes::new())
        };
        let bytes = match body {
            Ok(bytes) => bytes,
            Err(rest) => {
                return ctx
                    .upstream
                    .forward(Request::from_parts(parts, rest), &ctx.identity)
                    .await
            }
        };
        match self.try_message(route, &raw_id, &parts, &bytes, &ctx).await {
            Ok(response) => response,
            Err(_) => {
                let body = http_body_util::BodyExt::boxed(http_body_util::Full::new(bytes).map_err(|n| match n {}));
                ctx.upstream
                    .forward(Request::from_parts(parts, body), &ctx.identity)
                    .await
            }
        }
    }

    async fn admit(
        &self,
        parts: &hyper::http::request::Parts,
        ctx: &RequestContext,
    ) -> Result<Admitted, &'static str> {
        let authorized = setjoin_authz::authorize_request(
            &self.exec,
            &self.keys,
            &self.issuer,
            &parts.headers,
            ctx.identity.proto,
        )
        .await
        .ok_or("unported identity admission (#331)")?;
        let identity = authorized.context();
        if let Some(denylist) = &self.denylist {
            let issued =
                chrono::DateTime::from_timestamp(authorized.issued_at(), 0).ok_or("token iat")?;
            if !denylist.loaded()
                || denylist.is_revoked(
                    identity.user_id(),
                    authorized.token_id(),
                    authorized.token_family(),
                    issued,
                )
            {
                return Err("unported identity admission (#331)");
            }
        }
        let request_id = reply::request_id(
            parts.headers.get("x-request-id"),
            super::random().ok_or("rng unavailable")?,
        );
        Ok(Admitted {
            user: identity.user_id(),
            mailbox: identity.mailbox_id(),
            auth: MailboxAuthContext::from_authenticated_session(
                ActorId::new(identity.user_id()).map_err(|_| "actor")?,
                MailboxId::new(identity.mailbox_id()).map_err(|_| "mailbox")?,
                super::REQUEST_AUTHORITY_GENERATION,
            ),
            request_id,
        })
    }

    fn envelope(
        &self,
        auth: &MailboxAuthContext,
        digest_of: &[u8],
    ) -> Result<CommandEnvelope<()>, &'static str> {
        Ok(CommandEnvelope {
            operation: OperationId(super::random().ok_or("rng unavailable")?),
            authority: auth.authority(),
            binding: setjoin_db::lifecycle::accepted_contract(),
            payload_digest: Digest(Sha256::digest(digest_of).into()),
            command: (),
        })
    }

    async fn try_message(
        &self,
        route: Route,
        raw_id: &str,
        parts: &hyper::http::request::Parts,
        body: &Bytes,
        ctx: &RequestContext,
    ) -> Result<Response<Body>, &'static str> {
        let a = self.admit(parts, ctx).await?;
        let rid = a.request_id.as_str();
        let worker = self.worker.as_ref().unwrap_or(&self.exec);
        Ok(match route {
            Route::Focus => {
                let Some(id) = positive_id(raw_id) else {
                    return Ok(crate::mailboxes::bare(400, "invalid message id", ctx, rid));
                };
                let Ok(focused) = decode_focus(body) else {
                    return Ok(crate::mailboxes::bare(400, "invalid request body", ctx, rid));
                };
                let owned = match setjoin_jmap::messages::owned_message(worker, a.user, id).await {
                    Ok(Some(owned)) => owned,
                    _ => return Ok(crate::mailboxes::bare(404, "message not found", ctx, rid)),
                };
                let scope = MailboxAuthContext::from_authenticated_session(
                    a.auth.actor(),
                    MailboxId::new(owned.mailbox).map_err(|_| "mailbox")?,
                    super::REQUEST_AUTHORITY_GENERATION,
                );
                let envelope = self.envelope(&scope, parts.uri.to_string().as_bytes())?;
                match setjoin_jmap::messages::set_focus(
                    worker,
                    &scope,
                    &envelope,
                    std::time::Instant::now() + super::COMMAND_DEADLINE,
                    id,
                    focused,
                )
                .await
                {
                    CommandOutcome::Committed(()) => reply::response(
                        format!("{{\"focused\":{focused}}}\n"),
                        ctx.identity.proto,
                        a.request_id.clone(),
                    ),
                    CommandOutcome::Unknown { operation } => {
                        crate::mailboxes::unknown_outcome(operation, ctx, rid)
                    }
                    CommandOutcome::RolledBack(Rejection::Statement(failure)) => {
                        crate::mailboxes::bare(
                            super::submission_actions::reducer_status(failure.sqlstate.as_deref()),
                            "focus update failed",
                            ctx,
                            rid,
                        )
                    }
                    CommandOutcome::RolledBack(_) => {
                        crate::mailboxes::bare(500, "focus update failed", ctx, rid)
                    }
                }
            }
            Route::Download => self.raw_download(raw_id, parts, ctx, &a).await?,
            Route::Zip => {
                let Some(id) = positive_id(raw_id) else {
                    return Ok(crate::mailboxes::bare(400, "invalid message id", ctx, rid));
                };
                let source = match setjoin_jmap::messages::zip_source(worker, a.user, id).await {
                    Ok(source) => source,
                    Err(_) => return Ok(crate::mailboxes::bare(500, "database error", ctx, rid)),
                };
                if source.entries.is_empty() {
                    return Ok(crate::mailboxes::bare(404, "no attachments", ctx, rid));
                }
                if !super::messages_zip::entries_allowed(source.entries.len()) {
                    return Ok(crate::mailboxes::bare(413, "too many attachments", ctx, rid));
                }
                let store = self.services.as_ref().and_then(|s| s.store.clone());
                super::messages_zip::response(
                    parts.method == Method::HEAD,
                    source,
                    store,
                    ctx,
                    a.request_id.clone(),
                )
                .await
            }
            Route::Unsubscribe => self.unsubscribe(raw_id, worker, ctx, &a).await?,
        })
    }

    async fn raw_download(
        &self,
        raw_id: &str,
        parts: &hyper::http::request::Parts,
        ctx: &RequestContext,
        a: &Admitted,
    ) -> Result<Response<Body>, &'static str> {
        let rid = a.request_id.as_str();
        if self.services.is_none() {
            return Err("download needs the JMAP services");
        }
        let Ok(id) = raw_id.parse::<i64>() else {
            return Ok(crate::mailboxes::bare(400, "invalid email ID", ctx, rid));
        };
        let worker = self.worker.as_ref().unwrap_or(&self.exec);
        let owned = match setjoin_jmap::messages::owned_message(worker, a.user, id).await {
            Ok(Some(owned)) => owned,
            Ok(None) => return Ok(crate::mailboxes::bare(404, "email not found", ctx, rid)),
            Err(_) => return Ok(crate::mailboxes::bare(500, "database error", ctx, rid)),
        };
        let filename = format!("{}.eml", sanitize_filename(&owned.subject));
        // Go builds `<jmap>/<mailbox>/<rawRef>/<filename>` by formatting and lets
        // net/url parse it: a control byte or a bad escape cannot be parsed
        // (500); bytes the URL grammar would escape are escaped here the same
        // way, and a `/`, `?` or `#` in the reference never matches the
        // three-segment download route (404).
        let raw = owned.raw_ref.as_bytes();
        if raw.iter().any(|b| *b < 0x20 || *b == 0x7f) || bad_escape(raw) {
            return Ok(crate::mailboxes::bare(500, "internal error", ctx, rid));
        }
        let mut reference = String::new();
        for b in raw {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'%') {
                reference.push(*b as char);
            } else {
                reference.push_str(&format!("%{b:02X}"));
            }
        }
        // `/`, `?`, `#` were escaped above; the URL the proxy would build had them
        // raw and so never reaches a three-segment route.
        if raw.iter().any(|b| matches!(b, b'/' | b'?' | b'#')) {
            return Ok(crate::mailboxes::bare(404, "email not found", ctx, rid));
        }
        let uri = format!("/jmap/download/{}/{reference}/{filename}", owned.mailbox);
        let Ok(uri) = uri.parse::<hyper::Uri>() else {
            return Ok(crate::mailboxes::bare(500, "internal error", ctx, rid));
        };
        // Only the Authorization header is forwarded; ranges and validators of the
        // outer request never reach the inner download.
        let mut inner = Request::builder().method(Method::GET).uri(uri);
        if let Some(value) = parts.headers.get("authorization") {
            inner = inner.header("authorization", value);
        }
        let inner = inner
            .body(http_body_util::BodyExt::boxed(http_body_util::Empty::<Bytes>::new().map_err(|n| match n {})))
            .map_err(|_| "inner request")?;
        let response = self.download(&inner, ctx, &a.auth, rid).await;
        if response.status() != hyper::StatusCode::OK {
            return Ok(crate::mailboxes::bare(404, "email not found", ctx, rid));
        }
        // Go copies the inner body through its own writer: a short body leaves
        // with a Content-Length, a longer one is chunked (2 KiB framing). The
        // inner validators, ranges and cache headers do not travel.
        let mut inner_body = response.into_body();
        Ok(crate::compliance_export::stream(
            parts.method == Method::HEAD,
            "message/rfc822",
            format!("attachment; filename=\"{filename}\""),
            ctx,
            a.request_id.clone(),
            move |mut out| async move {
                while let Some(Ok(frame)) = inner_body.frame().await {
                    if let Ok(data) = frame.into_data() {
                        if out.write(data).await.is_err() {
                            return;
                        }
                    }
                }
                out.finish();
            },
        )
        .await)
    }

    async fn unsubscribe(
        &self,
        raw_id: &str,
        worker: &setjoin_pg::ScopedExecutor,
        ctx: &RequestContext,
        a: &Admitted,
    ) -> Result<Response<Body>, &'static str> {
        let rid = a.request_id.as_str();
        let (header, from) = match setjoin_jmap::messages::unsubscribe_source(worker, a.user, raw_id).await {
            Ok(Some(found)) => found,
            _ => return Ok(crate::mailboxes::bare(404, "message not found", ctx, rid)),
        };
        if header.is_empty() {
            return Ok(crate::mailboxes::bare(
                400,
                "no unsubscribe URL available for this message",
                ctx,
                rid,
            ));
        }
        let url = extract_unsubscribe_url(&header);
        if url.is_empty() {
            return Ok(crate::mailboxes::bare(400, "invalid List-Unsubscribe header", ctx, rid));
        }
        if !url.starts_with("mailto:") {
            if !go_validate_url(url) {
                return Ok(crate::mailboxes::bare(
                    400,
                    "unsubscribe URL is not allowed",
                    ctx,
                    rid,
                ));
            }
            // A failed POST still records the intent: the request may have arrived.
            if let Err(error) = post_one_click(&self.unsubscribe_client(), url).await {
                eprintln!("setjoin-gateway: newsletter unsubscribe POST failed: {error}");
            }
        }
        let target = raw_id.parse::<i64>().ok();
        let envelope = self.envelope(&a.auth, raw_id.as_bytes())?;
        let _ = a.mailbox;
        match setjoin_jmap::messages::record_unsubscribe(
            worker,
            &a.auth,
            &envelope,
            std::time::Instant::now() + super::COMMAND_DEADLINE,
            target,
            &from,
        )
        .await
        {
            CommandOutcome::Unknown { operation } => {
                return Ok(crate::mailboxes::unknown_outcome(operation, ctx, rid))
            }
            CommandOutcome::Committed(()) => {}
            // Go logs and answers 200 when its audit or block write fails.
            CommandOutcome::RolledBack(_) => {}
        }
        let mut response = reply::response(
            "{\"status\":\"unsubscribed\"}\n".into(),
            ctx.identity.proto,
            a.request_id.clone(),
        );
        // Go writes this reply without a Content-Type, so the server sniffs text.
        response
            .headers_mut()
            .insert("content-type", "text/plain; charset=utf-8".parse().unwrap());
        Ok(response)
    }

    fn unsubscribe_client(&self) -> reqwest::Client {
        crate::webhook::safe_http_client(std::time::Duration::from_secs(15))
    }
}

/// `url.Parse` rejects a `%` not followed by two hex digits.
fn bad_escape(raw: &[u8]) -> bool {
    raw.iter().enumerate().any(|(i, b)| {
        *b == b'%'
            && !(raw.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                && raw.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn focus_body_follows_go_decoding() {
        let ok = |b: &str| decode_focus(b.as_bytes());
        assert_eq!(ok(r#"{"focused":true}"#), Ok(true));
        assert_eq!(ok(r#"{"focused":false}"#), Ok(false));
        assert_eq!(ok(r#"{"FOCUSED":true}"#), Ok(true));
        assert_eq!(ok("{\"focu\u{17f}ed\":true}"), Ok(true));
        assert_eq!(ok(r#"{"focused":true,"Focused":null}"#), Ok(true));
        assert_eq!(ok(r#"{"focused":true,"focused":false}"#), Ok(false));
        assert_eq!(ok(r#"{"x":1e999,"focused":true} trailing"#), Ok(true));
        assert_eq!(ok("null"), Ok(false));
        assert_eq!(ok("{}"), Ok(false));
        for bad in ["", "  ", "[]", "5", "\"x\"", r#"{"focused":"true"}"#, r#"{"focused":1}"#,
            r#"{"focused":true"#, r#"{"focused":}"#, "{focused:true}"] {
            assert_eq!(ok(bad), Err(()), "{bad:?}");
        }
    }

    #[test]
    fn unsubscribe_url_prefers_http_over_mailto() {
        assert_eq!(extract_unsubscribe_url("<mailto:a@b>, <https://x/y>"), "https://x/y");
        assert_eq!(extract_unsubscribe_url("<http://x>"), "http://x");
        assert_eq!(extract_unsubscribe_url(" <mailto:a@b> "), "mailto:a@b");
        assert_eq!(extract_unsubscribe_url("<ftp://x>"), "");
        assert_eq!(extract_unsubscribe_url("https://x"), "");
        assert_eq!(extract_unsubscribe_url("<>"), "");
    }

    #[test]
    fn validate_matches_go() {
        for ok in ["https://example.com/u", "http://example.com:8080/u?x=1", "http://2130706433/", "https://[2606:4700::1]/"] {
            assert!(go_validate_url(ok), "{ok}");
        }
        for bad in ["http://127.0.0.1/", "http://10.1.2.3/u", "http://[::1]/", "http://169.254.169.254/", "ftp://example.com/",
            "https:foo", "http:///x", "http://:80/", "http://a b/", "http://exa\tmple.com/", "http://[::ffff:127.0.0.1]/"] {
            assert!(!go_validate_url(bad), "{bad}");
        }
    }

    #[test]
    fn literal_addresses_in_any_form_are_refused_before_dialing() {
        for raw in ["http://127.0.0.1/", "http://2130706433/", "http://0x7f.1/", "http://[::1]/", "http://169.254.169.254/latest",
            "http://[::ffff:10.0.0.1]/"] {
            assert!(one_click_target(raw).is_err(), "{raw}");
        }
        assert!(one_click_target("https://203.0.114.7/u").is_ok());
        assert!(one_click_target("https://example.com/u").is_ok());
        assert!(one_click_target("http://example.com:99999/").is_err());
    }

    #[tokio::test]
    async fn one_click_post_has_the_rfc_8058_shape_and_follows_no_redirect() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut seen = Vec::new();
            for _ in 0..1 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap();
                seen.push(String::from_utf8_lossy(&buf[..n]).into_owned());
                socket
                    .write_all(b"HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:9/never\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .await
                    .unwrap();
            }
            seen
        });
        let client = crate::webhook::safe_http_client(std::time::Duration::from_secs(5));
        let url = reqwest::Url::parse(&format!("http://{addr}/unsub?t=1")).unwrap();
        // The guarded path refuses the loopback target outright.
        assert!(one_click_target(url.as_str()).is_err());
        // The wire shape, on an unguarded send to the loopback receiver.
        send_one_click(&client, url).await.unwrap();
        let seen = server.await.unwrap();
        let request = seen[0].to_ascii_lowercase();
        assert!(seen[0].starts_with("POST /unsub?t=1 HTTP/1.1"), "{}", seen[0]);
        assert!(request.contains("content-type: application/x-www-form-urlencoded"));
        assert!(seen[0].ends_with("List-Unsubscribe=One-Click"));
    }

    #[test]
    fn zip_names_are_sanitized_and_deduped_like_go() {
        use super::super::messages_zip::dedupe;
        assert_eq!(sanitize_filename("../evil name.txt"), ".._evil_name.txt");
        assert_eq!(sanitize_filename(""), "message");
        assert_eq!(sanitize_filename("caf\u{e9}/x\\y"), "caf__x_y");
        assert_eq!(sanitize_filename(&"a".repeat(300)).len(), 100);
        let mut seen = std::collections::HashMap::new();
        let names: Vec<String> = ["a.txt", "a.txt", "a.txt", "b", "b", ".h", ".h"]
            .into_iter()
            .map(|n| dedupe(&mut seen, n.to_owned()))
            .collect();
        assert_eq!(names, ["a.txt", "a-2.txt", "a-3.txt", "b", "b-2", ".h", "-2.h"]);
    }

    #[test]
    fn targets_are_the_four_routes_with_their_methods() {
        use hyper::Method;
        assert_eq!(target(&Method::POST, "/api/messages/5/focus").map(|t| t.0), Some(Route::Focus));
        assert_eq!(target(&Method::GET, "/api/messages/5/download").map(|t| t.0), Some(Route::Download));
        assert_eq!(target(&Method::HEAD, "/api/messages/5/attachments.zip").map(|t| t.0), Some(Route::Zip));
        assert_eq!(target(&Method::POST, "/api/messages/5/unsubscribe").map(|t| t.0), Some(Route::Unsubscribe));
        assert!(target(&Method::GET, "/api/messages/5/focus").is_none());
        assert!(target(&Method::POST, "/api/messages//focus").is_none());
        assert!(target(&Method::POST, "/messages/5/focus").is_none());
        assert!(target(&Method::POST, "/api/messages/5/focus/x").is_none());
    }
}
