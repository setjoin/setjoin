//! Native HTTP threat admission (#349a): frozen Go `shared/threat` Middleware for
//! POST /auth/login, /auth/refresh and /auth/forgot-password/{begin,verify,reset},
//! plus the #342 guest-invite ingress helpers that #349b retires. Security
//! divergences: tests/conformance/identity-threat/divergences.json.
use super::*;
use setjoin_pg::Type;
use setjoin_threat::{CaptchaStep, Decision, Gate, ThreatAction};
use std::time::Duration;

/// Go `threatHTTPBodyLimit`.
const BODY_LIMIT: usize = 1 << 20;
/// Go authserverd `http.Server.ReadTimeout` bounds the middleware's body read.
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(15);
/// Go `maxThreatResponseDelay`.
const MAX_DELAY: Duration = Duration::from_secs(15);
const DENIED: &str = "Access denied by security policy";
/// Go `anyThreatFeatureEnabled` (authserverd security_runtime.go).
const CONTROLS: [&str; 6] = [
    "feature.threat_feed",
    "feature.geo_block",
    "feature.spray_detect",
    "feature.captcha",
    "feature.tarpit",
    "feature.rate_limit",
];

/// The admitted credential routes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Route {
    Login,
    Refresh,
    Reset,
    Begin,
    Verify,
}

impl Route {
    /// Go mounts (#349 F1/F2): login and refresh run the middleware only while one
    /// of [`CONTROLS`] is on (`dynamicCredentialHandler`); forgot-password routes
    /// are always wrapped (authserverd always installs the policy engine).
    fn dynamic(self) -> bool {
        matches!(self, Route::Login | Route::Refresh)
    }
}

/// Go `threat.WithUserID` / `WithVerifiedNoOutcome`, carried on the handler's
/// response extensions and removed by [`AuthServer::threat_tail`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ThreatOutcome {
    pub(super) user_id: i64,
    pub(super) verified_no_outcome: bool,
    /// Divergence `forgot-begin-success-keeps-lockout`: a 2xx that proves no
    /// credential writes Go's `success` attempt row but never clears lockout keys.
    pub(super) unproven: bool,
}

/// A request past the read stage: no database access and no effect so far.
pub(super) struct Staged {
    parts: hyper::http::request::Parts,
    stage: Stage,
}

enum Stage {
    /// Admission not mounted (dynamic route with every control off, or OPTIONS):
    /// the body is untouched and no tail runs.
    Pass(Body),
    Read {
        raw: Bytes,
        gate: Arc<Gate>,
        meta: Box<setjoin_threat::ConnectionMeta>,
    },
}

/// Admission ran (`Some`) or was not mounted (`None`) for the handled request.
pub(super) struct Admitted(Option<(Arc<Gate>, Box<setjoin_threat::ConnectionMeta>)>);

impl Staged {
    /// The buffered body when admission is mounted.
    pub(super) fn raw(&self) -> Option<&[u8]> {
        match &self.stage {
            Stage::Read { raw, .. } => Some(&raw[..]),
            Stage::Pass(_) => None,
        }
    }

    /// The whole original request, for a preflight forward before any admission effect.
    pub(super) fn into_request(self) -> Request<Body> {
        match self.stage {
            Stage::Pass(input) => Request::from_parts(self.parts, input),
            Stage::Read { raw, .. } => Request::from_parts(self.parts, body(raw)),
        }
    }
}

impl AuthServer {
    /// Stage 1 (Go Middleware through extractMeta): mount, OPTIONS, the 1 MiB body
    /// read and the request meta. No gate means 503: a server without a gate never
    /// skips admission (#349 invariant).
    pub(super) async fn threat_stage(
        &self,
        req: Request<Body>,
        route: Route,
    ) -> Result<Staged, Response<Body>> {
        let Some(gate) = self.gate.clone() else {
            return Err(Self::failure(
                503,
                "threat admission unavailable",
                req.uri().path(),
            ));
        };
        let mounted = !route.dynamic() || CONTROLS.iter().any(|key| gate.enabled(key));
        if req.method() == Method::OPTIONS || !mounted {
            let (parts, input) = req.into_parts();
            return Ok(Staged {
                parts,
                stage: Stage::Pass(input),
            });
        }
        let source_ip = self.client_ip(&req).to_string();
        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let (parts, input) = req.into_parts();
        let raw = match tokio::time::timeout(
            BODY_READ_TIMEOUT,
            Limited::new(input, BODY_LIMIT).collect(),
        )
        .await
        {
            Ok(Ok(collected)) => collected.to_bytes(),
            Ok(Err(error)) if error.is::<http_body_util::LengthLimitError>() => {
                return Err(threat_reply(
                    413,
                    "body_too_large",
                    "request body exceeds the security limit",
                    None,
                    Duration::ZERO,
                )
                .await);
            }
            _ => {
                return Err(threat_reply(
                    400,
                    "invalid_body",
                    "request body could not be read",
                    None,
                    Duration::ZERO,
                )
                .await);
            }
        };
        let meta = setjoin_threat::ConnectionMeta {
            source_ip,
            username: self.threat_username(route, &raw),
            protocol: "http".into(),
            user_agent,
            ..Default::default()
        };
        Ok(Staged {
            parts,
            stage: Stage::Read {
                raw,
                gate,
                meta: Box::new(meta),
            },
        })
    }

    /// Divergence `threat-username-handler-decode` (F1): the lockout/spray username
    /// is exactly what the route's handler decodes (Go's first-value decode, trailing
    /// data tolerated), never a separate whole-body Unmarshal. Divergence
    /// `refresh-username-verified-token` (F2): refresh keys only the verified token.
    fn threat_username(&self, route: Route, raw: &[u8]) -> String {
        match route {
            Route::Login => login_username(raw),
            Route::Refresh => self.refresh_username(raw),
            Route::Reset | Route::Begin | Route::Verify => field_username(raw),
        }
    }

    /// The `email` claim of a refresh token that verifies (signature, issuer,
    /// `typ=refresh`), as the refresh handler checks it; "" otherwise.
    fn refresh_username(&self, raw: &[u8]) -> String {
        let token = ingress::fields(raw, &["refresh_token"])
            .ok()
            .and_then(|f| f.get("refresh_token").cloned())
            .unwrap_or_default();
        if token.is_empty() {
            return String::new();
        }
        let Ok(legacy) = setjoin_authz::legacy_jwt::LegacyKeys::from_pem(
            self.config.secret.as_bytes(),
            &["authserver-hmac-1"],
            self.config.sm2_pem.as_deref(),
        ) else {
            return String::new();
        };
        setjoin_identity::session::Session::verify(
            &token,
            self.keys.as_deref(),
            &legacy,
            &self.config.issuer,
        )
        .filter(|s| s.text("typ") == "refresh")
        .map(|s| s.text("email").to_owned())
        .unwrap_or_default()
    }

    /// Stage 2: Go's pipeline (`Gate::decide_with`), with the #349 captcha
    /// divergences: a token is bound to IP, route and username and is single-use.
    /// Order (Fable V2-2): verify, run the pipeline, claim only when it allows, so
    /// a rate-limited request consumes no used-set slot. A verified and claimed
    /// token runs `Skip` (Go: a solve skips the captcha/tarpit step); a token that
    /// fails verification or its claim runs `TarpitOnly` and, if everything else
    /// allows, gets 403 `captcha`. Every refusal first writes Go's attempt row
    /// (outcomes outside auth_attempts_outcome_check write none).
    pub(super) async fn threat_admit(
        &self,
        staged: Staged,
    ) -> Result<(Request<Body>, Admitted), Response<Body>> {
        let Staged { parts, stage } = staged;
        let (raw, gate, meta) = match stage {
            Stage::Pass(input) => {
                return Ok((Request::from_parts(parts, input), Admitted(None)));
            }
            Stage::Read { raw, gate, meta } => (raw, gate, meta),
        };
        let secret = &self.config.threat.captcha_secret;
        let route = parts.uri.path().to_owned();
        let binding = captcha::Binding {
            ip: &meta.source_ip,
            route: &route,
            username: &meta.username,
        };
        let token = parts
            .headers
            .get("x-captcha-token")
            .map_or(&[][..], |v| v.as_bytes());
        let decision = if token.is_empty() {
            gate.decide_with(&meta, CaptchaStep::Full).await
        } else {
            let answer = parts
                .headers
                .get("x-captcha-answer")
                .map_or(&[][..], |v| v.as_bytes());
            let now = captcha::now();
            let verified = captcha::verify(secret, token, answer, &binding, now);
            let step = if verified.is_some() {
                CaptchaStep::Skip
            } else {
                CaptchaStep::TarpitOnly
            };
            let decision = gate.decide_with(&meta, step).await;
            // Claim only on Allow (V2-2); a failed claim (replay, full set) is a failed token.
            let solved = decision.action != ThreatAction::Allow
                || verified.is_some_and(|(mac, exp)| self.captcha_used.claim(&mac, exp, now));
            if !solved {
                gate.attempt(&meta, "captcha_needed").await;
                return Err(threat_reply(
                    403,
                    "captcha",
                    "CAPTCHA verification failed",
                    None,
                    Duration::ZERO,
                )
                .await);
            }
            decision
        };
        if decision.action != ThreatAction::Allow {
            gate.attempt(&meta, &decision.reason).await;
            return Err(threat_result(secret, &binding, &decision).await);
        }
        Ok((
            Request::from_parts(parts, body(raw)),
            Admitted(Some((gate, meta))),
        ))
    }

    /// Stage 3, Go postAuth: strip the outcome stamp, then record unless the
    /// handler stamped verified-no-outcome. 200 and 204 are success.
    pub(super) async fn threat_tail(
        &self,
        admitted: Admitted,
        mut reply: Response<Body>,
    ) -> Response<Body> {
        let outcome = reply
            .extensions_mut()
            .remove::<ThreatOutcome>()
            .unwrap_or_default();
        let Admitted(Some((gate, meta))) = admitted else {
            return reply;
        };
        if outcome.verified_no_outcome {
            return reply;
        }
        let success = matches!(reply.status().as_u16(), 200 | 204);
        if success && outcome.unproven {
            gate.attempt(&meta, "success").await;
        } else {
            gate.record(&meta, success, outcome.user_id).await;
        }
        reply
    }

    /// Go `threat.WithUserID` (auth.go:958).
    pub(super) fn threat_user(mut reply: Response<Body>, user_id: i64) -> Response<Body> {
        reply.extensions_mut().insert(ThreatOutcome {
            user_id,
            ..Default::default()
        });
        reply
    }

    /// Go `threat.WithVerifiedNoOutcome` (auth.go:841).
    pub(super) fn threat_no_outcome(mut reply: Response<Body>) -> Response<Body> {
        reply.extensions_mut().insert(ThreatOutcome {
            verified_no_outcome: true,
            ..Default::default()
        });
        reply
    }

    /// Go stamps verified-no-outcome only once a challenge was written: 202 MFA
    /// (auth.go:924, 947) or 403 enrollment (auth.go:884). Errors stay outcomes.
    pub(super) fn threat_challenge(reply: Response<Body>) -> Response<Body> {
        if matches!(reply.status().as_u16(), 202 | 403) {
            Self::threat_no_outcome(reply)
        } else {
            reply
        }
    }

    /// Divergence `forgot-begin-success-keeps-lockout` (the decoy 200 proves nothing).
    pub(super) fn threat_unproven(mut reply: Response<Body>) -> Response<Body> {
        reply.extensions_mut().insert(ThreatOutcome {
            unproven: true,
            ..Default::default()
        });
        reply
    }

    /// Login preflight (#349 F7): CA and device trust still forward whole (#351);
    /// both are decided from toggles alone, before any admission effect. A read
    /// error forwards (fail closed toward Go's full pipeline).
    pub(super) async fn login_ca_pending(&self) -> bool {
        for control in [
            "feature.conditional_access",
            "feature.device_trust_enforcement",
        ] {
            if !matches!(login::enabled(&self.exec, control).await, Ok(false)) {
                return true;
            }
        }
        false
    }

    /// The same decode the login handler uses: a non-empty `dpop_jwk` object.
    pub(super) fn login_dpop_requested(raw: &[u8]) -> bool {
        let decoded = ingress::go_decode_bytes(raw);
        let mut stream = serde_json::Deserializer::from_slice(&decoded);
        ingress::Login::deserialize(&mut stream)
            .is_ok_and(|input| input.dpop.as_object().is_some_and(|v| !v.is_empty()))
    }

    /// Guest-invite's existing #420/#405 boundary (#349b removes it).
    pub(super) async fn http_threat_pending(&self) -> bool {
        let rate = self
            .exec
            .read(
                "SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'),true)",
                &[],
            )
            .await;
        if self.config.threat_controls.iter().any(|v| *v)
            || rate.is_err()
            || rate.as_ref().is_ok_and(|r| r[0].get::<_, bool>(0))
        {
            return true;
        }
        for control in [
            "feature.conditional_access",
            "feature.device_trust_enforcement",
        ] {
            if !matches!(login::enabled(&self.exec, control).await, Ok(false)) {
                return true;
            }
        }
        false
    }

    fn http_country(&self, ip: &str) -> String {
        ip.parse()
            .ok()
            .and_then(|ip| self.geo.as_ref().map(|g| g.country(ip)))
            .unwrap_or_default()
    }

    /// Go recordAttempt/recordOutcome: best-effort row; errors are ignored as in Go
    /// (an 'ip_blocked' outcome violates auth_attempts_outcome_check, so no row).
    pub(super) async fn http_attempt(&self, ip: &str, agent: &str, username: &str, outcome: &str) {
        let country = self.http_country(ip);
        let fp = setjoin_threat::fingerprint(agent, ip);
        let _ = self
            .exec
            .protocol_statement(
                "INSERT INTO auth_attempts(source_ip,target_username,protocol,outcome,geo_country,device_fingerprint) VALUES($1::inet,$2,'http',$3,$4,$5)",
                &[
                    (&ip, Type::TEXT),
                    (&username, Type::TEXT),
                    (&outcome, Type::TEXT),
                    (&country, Type::TEXT),
                    (&fp, Type::TEXT),
                ],
            )
            .await;
    }

    /// Guest-invite stepIPRules (#342): an unanswered lookup rejects, as the
    /// protocol gate does (#367 `ip-rules-fail-closed`).
    pub(super) async fn http_ip_rules(
        &self,
        ip: &str,
        agent: &str,
        username: &str,
    ) -> Option<Response<Body>> {
        let reason = match setjoin_threat::ip_rule_blocked(&self.exec, ip).await {
            Ok(false) => return None,
            Ok(true) => "ip_blocked",
            Err(()) => "ip_rules_unavailable",
        };
        self.http_attempt(ip, agent, username, reason).await;
        Some(threat_reply(403, reason, DENIED, None, Duration::ZERO).await)
    }
}

/// The login handler's decode (`ingress::Login`): first JSON value, trailing data
/// tolerated, folded names, the last non-null string wins.
pub(super) fn login_username(raw: &[u8]) -> String {
    let decoded = ingress::go_decode_bytes(raw);
    let mut stream = serde_json::Deserializer::from_slice(&decoded);
    ingress::Login::deserialize(&mut stream)
        .map(|input| input.email)
        .unwrap_or_default()
}

/// `ingress::fields` email: the forgot-password and guest-invite handlers' decode.
pub(super) fn field_username(raw: &[u8]) -> String {
    ingress::fields(raw, &["email"])
        .ok()
        .and_then(|f| f.get("email").cloned())
        .unwrap_or_default()
}

/// Go `writeThreatResponse`: clamp, sleep before any header, then
/// `json.NewEncoder` of a map (sorted keys, trailing newline). `retry_after`
/// (whole seconds, truncated) and `X-Threat-Delay` appear only for a positive delay.
pub(super) async fn threat_reply(
    status: u16,
    category: &str,
    description: &str,
    token: Option<&str>,
    delay: Duration,
) -> Response<Body> {
    let delay = delay.min(MAX_DELAY);
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    // Inserted in sorted order: identical bytes with or without preserve_order.
    let mut doc = serde_json::Map::new();
    if !description.is_empty() {
        doc.insert("captcha_prompt".into(), Value::from(description));
    }
    if let Some(token) = token.filter(|t| !t.is_empty()) {
        doc.insert("captcha_token".into(), Value::from(token));
    }
    doc.insert("error".into(), Value::from(category));
    if !delay.is_zero() {
        doc.insert("retry_after".into(), Value::from(delay.as_secs()));
    }
    let mut reply = Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("x-threat-reason", category);
    if !delay.is_zero() {
        reply = reply.header("x-threat-delay", go_duration(delay));
    }
    reply
        .body(body(Value::Object(doc).to_string() + "\n"))
        .unwrap()
}

/// Go `writeResult`. `Reject + "captcha_needed"` is Go's ActionCaptchaNeeded; the
/// challenge token is bound to this request's IP, route and username.
async fn threat_result(secret: &[u8], binding: &captcha::Binding<'_>, decision: &Decision) -> Response<Body> {
    match (decision.action, decision.reason.as_str()) {
        (ThreatAction::Reject, "captcha_needed") => {
            let Some((a, b)) = captcha::operands() else {
                return AuthServer::failure(503, "captcha unavailable", "");
            };
            let token = captcha::mint(secret, &(a + b).to_string(), captcha::now() + 120, binding);
            threat_reply(
                403,
                "captcha",
                &format!("What is {a} + {b}?"),
                Some(&token),
                Duration::ZERO,
            )
            .await
        }
        (ThreatAction::RateLimited, _) => {
            threat_reply(429, "rate_limited", "Too many requests", None, Duration::ZERO).await
        }
        (ThreatAction::Tarpitted, _) => {
            threat_reply(429, "tarpit_applied", "Request throttled", None, decision.delay).await
        }
        (_, reason) => threat_reply(403, reason, DENIED, None, decision.delay).await,
    }
}

/// Go `time.Duration.String()` for the clamped (< 1 min) threat delays.
pub(super) fn go_duration(d: Duration) -> String {
    let n = d.as_nanos();
    if n == 0 {
        return "0s".into();
    }
    let (unit, scale): (&str, u128) = if n < 1_000 {
        ("ns", 1)
    } else if n < 1_000_000 {
        ("µs", 1_000)
    } else if n < 1_000_000_000 {
        ("ms", 1_000_000)
    } else {
        ("s", 1_000_000_000)
    };
    let mut text = (n / scale).to_string();
    let rest = n % scale;
    if rest > 0 {
        let digits = scale.to_string().len() - 1;
        let fraction = format!("{rest:0digits$}");
        text.push('.');
        text.push_str(fraction.trim_end_matches('0'));
    }
    text + unit
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: captcha::Binding<'static> = captcha::Binding {
        ip: "192.0.2.1",
        route: "/auth/login",
        username: "a@x",
    };

    /// F1: the threat username is the handler's decode, trailing data included.
    #[test]
    fn route_usernames_use_the_handler_decode() {
        for (raw, want) in [
            (r#"{"email":"a@x","password":"p"} x"#, "a@x"),
            (r#"{"email":"a@x","password":"p"}{"email":"b@x"}"#, "a@x"),
            (r#"{"email":"a@x"} {}"#, "a@x"),
            (r#"{"EMAIL":"a@x","email":"b@x"}"#, "b@x"),
            (r#"{"email":"a@x","email":null}"#, "a@x"),
            (r#"{"password":"p"} x"#, ""),
            ("null", ""),
            ("[]", ""),
        ] {
            assert_eq!(login_username(raw.as_bytes()), want, "{raw}");
        }
        for (raw, want) in [
            (r#"{"email":"v@x","code":"1"} trailing"#, "v@x"),
            (r#"{"email":"v@x","email":null}"#, "v@x"),
            (r#"{"Email":"v@x"} {}"#, "v@x"),
            ("{", ""),
        ] {
            assert_eq!(field_username(raw.as_bytes()), want, "{raw}");
        }
    }

    #[test]
    fn delay_header_uses_go_duration_string() {
        for (ms, want) in [
            (1, "1ms"),
            (500, "500ms"),
            (1000, "1s"),
            (1500, "1.5s"),
            (2250, "2.25s"),
            (15000, "15s"),
        ] {
            assert_eq!(go_duration(Duration::from_millis(ms)), want);
        }
        assert_eq!(go_duration(Duration::ZERO), "0s");
    }

    #[tokio::test]
    async fn threat_replies_match_go_write_threat_response() {
        let cases = [
            (ThreatAction::Reject, "lockout_unavailable", 0, 403, None, "{\"captcha_prompt\":\"Access denied by security policy\",\"error\":\"lockout_unavailable\"}\n"),
            (ThreatAction::Reject, "ip_rules_unavailable", 0, 403, None, "{\"captcha_prompt\":\"Access denied by security policy\",\"error\":\"ip_rules_unavailable\"}\n"),
            (ThreatAction::RateLimited, "rate_limited", 0, 429, None, "{\"captcha_prompt\":\"Too many requests\",\"error\":\"rate_limited\"}\n"),
            (ThreatAction::Tarpitted, "tarpit_applied", 1, 429, Some("1ms"), "{\"captcha_prompt\":\"Request throttled\",\"error\":\"tarpit_applied\",\"retry_after\":0}\n"),
            (ThreatAction::Reject, "lockout", 1, 403, Some("1ms"), "{\"captcha_prompt\":\"Access denied by security policy\",\"error\":\"lockout\",\"retry_after\":0}\n"),
        ];
        for (action, reason, ms, status, delay, want) in cases {
            let decision = Decision {
                action,
                reason: reason.into(),
                delay: Duration::from_millis(ms),
            };
            let reply = threat_result(b"k", &B, &decision).await;
            assert_eq!(reply.status().as_u16(), status, "{reason}");
            assert_eq!(reply.headers()["x-threat-reason"], reason);
            assert_eq!(
                reply.headers().get("x-threat-delay").map(|v| v.to_str().unwrap()),
                delay
            );
            assert_eq!(reply.headers()["content-type"], "application/json");
            let bytes = reply.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&bytes[..], want.as_bytes(), "{reason}");
        }
    }

    #[tokio::test]
    async fn captcha_challenge_is_a_bound_token_for_the_prompted_sum() {
        let decision = Decision {
            action: ThreatAction::Reject,
            reason: "captcha_needed".into(),
            delay: Duration::ZERO,
        };
        let reply = threat_result(b"secret", &B, &decision).await;
        assert_eq!(reply.status().as_u16(), 403);
        assert_eq!(reply.headers()["x-threat-reason"], "captcha");
        let raw = reply.into_body().collect().await.unwrap().to_bytes();
        let doc: Value = serde_json::from_slice(&raw).unwrap();
        let prompt = doc["captcha_prompt"].as_str().unwrap();
        let (a, b) = prompt
            .strip_prefix("What is ")
            .and_then(|p| p.strip_suffix('?'))
            .and_then(|p| p.split_once(" + "))
            .unwrap();
        let sum = (a.parse::<u32>().unwrap() + b.parse::<u32>().unwrap()).to_string();
        let token = doc["captcha_token"].as_str().unwrap();
        let now = captcha::now();
        assert!(captcha::verify(b"secret", token.as_bytes(), sum.as_bytes(), &B, now).is_some());
        let elsewhere = captcha::Binding { ip: "192.0.2.9", ..B };
        assert!(captcha::verify(b"secret", token.as_bytes(), sum.as_bytes(), &elsewhere, now).is_none());
        assert_eq!(doc["error"], "captcha");
        assert!(raw.ends_with(b"}\n"));
    }
}
