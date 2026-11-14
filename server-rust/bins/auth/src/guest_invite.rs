//! Frozen-Go `GET`/`HEAD`/`POST /auth/guest-invite/accept` transport (#342). See DOX.md.
use super::*;
use hyper::body::Body as _;
use setjoin_identity::guest_invite::{self as guest, Outcome};

const TERMINAL: &str = "invite link is invalid or has expired";
/// Go's enumConstantDelay, slept only after the transaction settled (never a floor).
const TERMINAL_DELAY: std::time::Duration = std::time::Duration::from_millis(100);
/// Go's outer limitRequestBody(guestInviteAcceptBodyLimit).
const BODY_LIMIT: usize = 1 << 20;

impl AuthServer {
    pub(super) async fn guest_invite(&self, req: Request<Body>) -> Response<Body> {
        if matches!(req.method(), &Method::GET | &Method::HEAD) {
            return self.guest_invite_get(req).await;
        }
        if req.method() == Method::POST {
            return self.guest_invite_post(req).await;
        }
        Response::builder()
            .status(405)
            .header("allow", "GET, HEAD, POST")
            .header("content-type", "text/plain; charset=utf-8")
            .header("x-content-type-options", "nosniff")
            .body(body("Method Not Allowed\n"))
            .unwrap()
    }

    async fn guest_reject() -> Response<Body> {
        tokio::time::sleep(TERMINAL_DELAY).await;
        Self::json_no_store(401, json!({ "error": TERMINAL }))
    }

    fn guest_limited() -> Response<Body> {
        Self::json_no_store(
            429,
            json!({ "error": "too many requests, please wait and try again" }),
        )
    }

    fn guest_internal(operation: Option<setjoin_contracts::ids::OperationId>) -> Response<Body> {
        let mut reply = Self::json_no_store(500, json!({ "error": "internal error" }));
        if let Some(op) = operation {
            reply.headers_mut().insert(
                "x-operation-id",
                uuid::Uuid::from_bytes(op.0).to_string().parse().unwrap(),
            );
        }
        reply
    }

    fn guest_disclosure(language_header: &str, d: guest::Disclosure) -> Response<Body> {
        let lang = language(language_header);
        let text = disclosure_copy(lang, &d.org_name, &d.channels, &d.locality, &d.addendum);
        let mut reply = Self::json_no_store(
            200,
            json!({
                "channels": d.channels,
                "disclosure_text": text,
                "disclosure_version": d.version,
                "expires_at": d.expires_at,
                "invited_email": d.invited_email,
                "org_name": d.org_name,
            }),
        );
        reply.headers_mut().insert(
            "content-language",
            hyper::header::HeaderValue::from_static(lang),
        );
        reply
    }

    // Go mounts no threat interceptor on GET (main.go:966).
    async fn guest_invite_get(&self, req: Request<Body>) -> Response<Body> {
        let head = req.method() == Method::HEAD;
        let ip = self.client_ip(&req).to_string();
        let language_header = req
            .headers()
            .get("accept-language")
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .unwrap_or_default();
        let token = go_query_first(req.uri().query().unwrap_or(""), "token").unwrap_or_default();
        drop(req);
        let mut response = if !self.recovery_ip.allow(&ip) {
            Self::guest_limited()
        } else {
            match (&self.guest_worker, token.is_empty()) {
                (_, true) => Self::guest_reject().await,
                (None, false) => Self::guest_internal(None),
                (Some(worker), false) => match guest::disclosure(worker, &token).await {
                    Outcome::Done(d) => Self::guest_disclosure(&language_header, d),
                    Outcome::Reject | Outcome::Invalid(_) => Self::guest_reject().await,
                    Outcome::Unknown(op) => Self::guest_internal(Some(op)),
                    Outcome::Failed => Self::guest_internal(None),
                },
            }
        };
        if head {
            if let Some(length) = response.body().size_hint().exact().filter(|n| *n > 0) {
                response
                    .headers_mut()
                    .insert("content-length", length.to_string().parse().unwrap());
            }
            *response.body_mut() = body("");
        }
        response
    }

    async fn guest_invite_post(&self, req: Request<Body>) -> Response<Body> {
        // Login's existing #420/#405 boundary (shared); no new forward path.
        if self.http_threat_pending().await {
            return self.forward(req).await;
        }
        let ip = self.client_ip(&req).to_string();
        let agent = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        // Go's outer limitRequestBody precedes the interceptor (main.go:966-967).
        let raw = match Limited::new(req.into_body(), BODY_LIMIT).collect().await {
            Ok(b) => b.to_bytes(),
            Err(error) => {
                let (status, text) = if error.is::<http_body_util::LengthLimitError>() {
                    (413, "request body too large\n")
                } else {
                    (400, "invalid request body\n")
                };
                return Response::builder()
                    .status(status)
                    .header("content-type", "text/plain; charset=utf-8")
                    .header("x-content-type-options", "nosniff")
                    .body(body(text))
                    .unwrap();
            }
        };
        let username = http_threat::field_username(&raw);
        if let Some(blocked) = self.http_ip_rules(&ip, &agent, &username).await {
            return blocked;
        }
        // X-Captcha-Token is ignored natively, as in native login (residual, #346).
        let reply = self.guest_invite_accept(&ip, &raw).await;
        let outcome = if matches!(reply.status().as_u16(), 200 | 204) {
            "success"
        } else {
            "failure"
        };
        self.http_attempt(&ip, &agent, &username, outcome).await;
        reply
    }

    async fn guest_invite_accept(&self, ip: &str, raw: &[u8]) -> Response<Body> {
        if !self.recovery_ip.allow(ip) {
            return Self::guest_limited();
        }
        let invalid = || Self::json_no_store(400, json!({ "error": "invalid JSON body" }));
        let Ok(fields) = ingress::closed_fields(
            raw,
            &[
                ("token", ingress::Field::Text),
                ("disclosure_accepted", ingress::Field::Bool),
                ("new_password", ingress::Field::Text),
            ],
        ) else {
            return invalid();
        };
        if !ingress::exact(&ingress::go_decode_bytes(raw)) {
            return invalid();
        }
        let token = fields.get("token").and_then(Value::as_str).unwrap_or("");
        if token.is_empty() {
            return Self::guest_reject().await;
        }
        if fields.get("disclosure_accepted").and_then(Value::as_bool) != Some(true) {
            return Self::json_no_store(
                400,
                json!({ "error": "disclosure acceptance is required" }),
            );
        }
        let password = fields
            .get("new_password")
            .and_then(Value::as_str)
            .unwrap_or("");
        if password.is_empty() {
            return Self::json_no_store(400, json!({ "error": "new password is required" }));
        }
        let Some(worker) = &self.guest_worker else {
            return Self::guest_internal(None);
        };
        let op = setjoin_contracts::ids::OperationId(*uuid::Uuid::new_v4().as_bytes());
        match guest::accept(
            worker,
            token,
            password,
            self.config.profile,
            Some(ip.to_owned()),
            op,
        )
        .await
        {
            Outcome::Done(a) => Self::json_no_store(
                200,
                json!({
                    "invited_email": a.invited_email,
                    "message": "Account activated. You may now sign in.",
                }),
            ),
            Outcome::Reject => Self::guest_reject().await,
            Outcome::Invalid(message) => Self::json_no_store(400, json!({ "error": message })),
            Outcome::Unknown(op) => Self::guest_internal(Some(op)),
            Outcome::Failed => Self::guest_internal(None),
        }
    }
}

/// Go's r.URL.Query().Get: '&' pairs, ';' pairs skipped, QueryUnescape, first match.
fn go_query_first(query: &str, name: &str) -> Option<Vec<u8>> {
    fn unescape(s: &str) -> Option<Vec<u8>> {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'%' => {
                    let h = b.get(i + 1..i + 3)?;
                    if !h.iter().all(u8::is_ascii_hexdigit) {
                        return None;
                    }
                    out.push(u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()?);
                    i += 3;
                }
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                c => {
                    out.push(c);
                    i += 1;
                }
            }
        }
        Some(out)
    }
    for pair in query.split('&') {
        if pair.is_empty() || pair.contains(';') {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let (Some(k), Some(v)) = (unescape(k), unescape(v)) else {
            continue;
        };
        if k == name.as_bytes() {
            return Some(v);
        }
    }
    None
}

/// Go's guestDisclosureLanguage.
fn language(header: &str) -> &'static str {
    let mut primary = header.trim();
    if let Some(i) = primary.find(|c| c == ',' || c == ';') {
        primary = primary[..i].trim();
    }
    let primary = primary.to_lowercase();
    if primary.starts_with("zh") {
        "zh"
    } else if primary.starts_with("de") {
        "de"
    } else {
        "en"
    }
}

/// Go's guestDisclosureCopy, byte for byte.
fn disclosure_copy(
    lang: &str,
    org: &str,
    channels: &[String],
    locality: &str,
    addendum: &str,
) -> String {
    let locality = if locality.is_empty() {
        match lang {
            "zh" => "在你所在组织的本地环境中",
            "de" => "lokal am Standort Ihrer Organisation",
            _ => "on-premise at your organization's location",
        }
        .to_owned()
    } else {
        locality.to_owned()
    };
    let mut text = match lang {
        "zh" => {
            let access = if channels.is_empty() {
                format!("{org} 中的聊天频道")
            } else {
                format!("{org} 中的以下聊天频道：{}", channels.join("、"))
            };
            format!("你将以外部来宾身份加入 {org}，并可访问{access}。你的消息、文件和活动将依照组织的数据保留政策保存。授权管理员可以使用组织的合规工具访问、导出和审查你的内容。你的内容将{locality}归档。继续即表示你同意此归档和监控。")
        }
        "de" => {
            let access = if channels.is_empty() {
                format!("Chat-Kanäle in {org}")
            } else {
                format!(
                    "die folgenden Chat-Kanäle in {org}: {}",
                    channels.join(", ")
                )
            };
            format!("Sie werden als externer Gast in {org} aufgenommen und erhalten Zugriff auf {access}. Ihre Nachrichten, Dateien und Aktivitäten werden gemäß den Aufbewahrungsrichtlinien der Organisation gespeichert. Autorisierte Administratoren können Ihre Inhalte mit den Compliance-Werkzeugen der Organisation aufrufen, exportieren und prüfen. Ihre Inhalte werden {locality} archiviert. Wenn Sie fortfahren, stimmen Sie dieser Archivierung und Überwachung zu.")
        }
        _ => {
            let access = if channels.is_empty() {
                format!("chat channels in {org}")
            } else {
                format!(
                    "the following chat channels in {org}: {}",
                    channels.join(", ")
                )
            };
            format!("You are being onboarded as an external guest user in {org} and will be able to access {access}. Your messages, files, and activity will be retained under the organization's data retention policies. Authorized administrators may access, export, and review your content using the organization's compliance tooling. Your content is archived {locality}. By proceeding you consent to this archival and monitoring.")
        }
    };
    if !addendum.is_empty() {
        text.push(' ');
        text.push_str(addendum);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_and_query_follow_go() {
        assert_eq!(language(" zh-CN,zh;q=0.9"), "zh");
        assert_eq!(language("DE;q=1"), "de");
        assert_eq!(language("fr"), "en");
        assert_eq!(
            go_query_first("a=1;b&token=x%2By+z&token=2", "token"),
            Some(b"x+y z".to_vec())
        );
        assert_eq!(
            go_query_first("token=%zz&token=ok", "token"),
            Some(b"ok".to_vec())
        );
        assert!(disclosure_copy("en", "Org", &[], "", "Extra").ends_with("monitoring. Extra"));
        assert!(
            disclosure_copy("de", "Org", &["A".into(), "B".into()], "", "").contains("Org: A, B")
        );
    }
}
