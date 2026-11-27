//! Native Conditional Access, device-trust claims, and session controls (#351).
use super::*;
use sha2::{Digest, Sha256};
use std::time::Duration;

pub struct CaListener(tokio::task::JoinHandle<()>);
impl Drop for CaListener {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(super) struct PendingMint<'a> {
    pub(super) user_id: i64,
    pub(super) email: &'a str,
    pub(super) amr: &'a [&'a str],
    pub(super) credential_fence: Option<&'a str>,
    pub(super) identity_fence: Option<&'a Value>,
}

impl AuthServer {
    /// Required CA and device-trust feature flags (#454/#457). A lookup error
    /// fails closed at the caller (500 on login/MFA/OIDC; 503 on SAML ACS).
    pub(super) async fn ca_flags(&self) -> Result<(bool, bool), ()> {
        let ca = login::enabled(&self.app_db, "feature.conditional_access")
            .await
            .map_err(|_| ())?;
        let dt = login::enabled(&self.app_db, "feature.device_trust_enforcement")
            .await
            .map_err(|_| ())?;
        Ok((ca, dt))
    }

    /// Borrows `ThreatGate::engine()` when attached, else the fallback policy
    /// engine initialized with the same policy source and refresh behavior.
    pub(super) fn policy_engine(&self) -> &setjoin_authz::policy::eval::Engine {
        self.gate
            .as_ref()
            .map_or(&self.ca_engine, |gate| gate.engine())
    }

    pub fn start_ca_listener(self: &Arc<Self>) -> Option<CaListener> {
        if self.gate.is_some() || self.config.direct_dsn.is_empty() {
            return None;
        }
        let server = self.clone();
        let dsn = self.config.direct_dsn.clone();
        Some(CaListener(tokio::spawn(async move {
            let mut retry = Duration::from_secs(1);
            loop {
                let connected = tokio::time::timeout(
                    Duration::from_secs(5),
                    setjoin_pg::workers::DirectListener::connect(&dsn, "conditional_access"),
                )
                .await;
                if let Ok(Ok(mut listener)) = connected {
                    let _ = server.ca_engine.invalidate_auth().await;
                    retry = Duration::from_secs(1);
                    while listener.recv().await.is_some() {
                        if let Err(err) = server.ca_engine.invalidate_auth().await {
                            eprintln!("auth CA reload: {}", err.message);
                        }
                    }
                }
                tokio::time::sleep(retry).await;
                retry = (retry * 2).min(Duration::from_secs(30));
            }
        })))
    }

    /// Multiplex `conditional_access` cache invalidation onto a shared
    /// [`setjoin_pg::ListenHub`] (#543).
    pub async fn start_ca_listener_with_hub(
        self: &Arc<Self>,
        hub: &setjoin_pg::ListenHub,
    ) -> Option<CaListener> {
        if self.gate.is_some() {
            return None;
        }
        let mut sub = hub.subscribe("conditional_access").await.ok()?;
        let server = self.clone();
        Some(CaListener(tokio::spawn(async move {
            let _ = server.ca_engine.invalidate_auth().await;
            while sub.recv().await.is_some() {
                if let Err(err) = server.ca_engine.invalidate_auth().await {
                    eprintln!("auth CA reload: {}", err.message);
                }
            }
        })))
    }

    /// Maps completed RFC 8176 AMR codes to the CA `auth_method` vocabulary
    /// (mirrors Go `authMethodFromCompletedFactors`).
    pub(super) fn auth_method_from_completed_factors(factors: &[String]) -> &'static str {
        let mut method = "password";
        for f in factors {
            match f.as_str() {
                "otp" => method = "totp",
                "swk" | "user" => method = "push",
                "hwk" if method == "password" => method = "webauthn",
                _ => {}
            }
        }
        method
    }

    pub(super) fn ca_context(
        &self,
        user_id: i64,
        is_guest: bool,
        ip: &str,
        agent: &str,
        device_binding: &setjoin_authz::device::Binding,
        auth_method: &str,
    ) -> setjoin_authz::policy::eval::Context {
        setjoin_authz::policy::eval::Context {
            user_id,
            is_guest,
            source_ip: ip.to_owned(),
            country: self.http_country(ip),
            device_fp: setjoin_threat::fingerprint(agent, ip),
            auth_method: auth_method.to_owned(),
            protocol: "http".into(),
            client_type: "web".into(),
            user_agent: agent.to_owned(),
            device_bound: device_binding.bound,
            enroll_state: device_binding.enroll_state.clone(),
            ..Default::default()
        }
    }

    /// Best-effort telemetry append via `ca_signin_log_append` (Go `PgxSignInRecorder`).
    async fn record_ca_signin(
        &self,
        ctx: &setjoin_authz::policy::eval::Context,
        result: &setjoin_authz::policy::eval::Result,
    ) {
        let mut row = json!({
            "user_id": ctx.user_id,
            "source_ip": ctx.source_ip,
            "protocol": ctx.protocol,
            "client_type": ctx.client_type,
            "device_fp": ctx.device_fp,
            "country": ctx.country,
            "decision": result.decision,
            "report_only": false,
            "evaluated": result.evaluated,
        });
        if result.policy_id != 0 {
            row["matched_policy_id"] = json!(result.policy_id);
        }
        if let Some(cid) = result.correlation_id.as_deref().filter(|s| !s.is_empty()) {
            row["correlation_id"] = json!(cid);
        }
        if result.policy_id == 0 && result.report_only && !result.would_decision.is_empty() {
            row["report_only"] = json!(true);
            row["would_decision"] = json!(result.would_decision);
        }
        let payload = row.to_string();
        if let Err(err) = self
            .exec
            .protocol_statement(
                "SELECT ca_signin_log_append($1::text::jsonb)",
                &[(&payload, setjoin_pg::Type::TEXT)],
            )
            .await
        {
            eprintln!(
                "ca_signin_log append failed (telemetry, ignored): {}",
                err.message
            );
        }
    }

    fn mint_mfa_pending(&self, spec: &PendingMint<'_>) -> Result<String, ()> {
        let jti = login::random_jti().map_err(|_| ())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let mut claims = json!({
            "uid": spec.user_id,
            "email": spec.email,
            "typ": "mfa_pending",
            "jti": jti,
            "iss": self.config.issuer,
            "sub": spec.user_id.to_string(),
            "aud": ["mailserver-gateway"],
            "iat": now,
            "nbf": now,
            "exp": now + 300,
            "amr": spec.amr,
        });
        if let Some(cf) = spec.credential_fence.filter(|s| !s.is_empty()) {
            claims["credential_fence"] = json!(cf);
        }
        if let Some(fence) = spec.identity_fence.filter(|v| !v.is_null()) {
            claims["identity_fence"] = fence.clone();
        }
        self.sign(&claims).map_err(|_| ())
    }

    /// Evaluates CA once, records telemetry once via `ca_signin_log_append`, and
    /// returns `Ok(matched_policy_id)` or `Err(terminal_response)`.
    ///
    /// `step_up_in_progress` MUST be `true` only on a verified server-pending
    /// MFA completion: repeated step-up challenges are suppressed there, while a
    /// fresh hard block remains terminal (403 + `X-CA-Correlation-Id`).
    pub(super) async fn evaluate_ca(
        &self,
        ca_enabled: bool,
        ctx: setjoin_authz::policy::eval::Context,
        step_up_in_progress: bool,
        pending_spec: Option<&PendingMint<'_>>,
        path: &str,
    ) -> Result<i64, Response<Body>> {
        if !ca_enabled {
            return Ok(0);
        }
        let result = boxed(|| self.policy_engine().evaluate(ctx.clone())).await;
        self.record_ca_signin(&ctx, &result).await;

        if result.decision == "block" && result.remediation.is_empty() {
            let detail = match result.correlation_id.as_deref().filter(|s| !s.is_empty()) {
                Some(cid) => format!("{} (reference {cid})", result.reason),
                None => result.reason.clone(),
            };
            let mut reply = Self::failure(403, &detail, path);
            if let Some(cid) = result.correlation_id.as_deref().filter(|s| !s.is_empty()) {
                if let Ok(hv) = cid.parse() {
                    reply.headers_mut().insert("x-ca-correlation-id", hv);
                }
            }
            return Err(reply);
        }

        if result.decision == "step_up" && !step_up_in_progress {
            let attach_cid = |reply: &mut Response<Body>| {
                if let Some(cid) = result.correlation_id.as_deref().filter(|s| !s.is_empty()) {
                    if let Ok(hv) = cid.parse() {
                        reply.headers_mut().insert("x-ca-correlation-id", hv);
                    }
                }
            };
            let Some(spec) = pending_spec else {
                let mut reply = Self::failure(500, "token issue failed", path);
                attach_cid(&mut reply);
                return Err(reply);
            };
            let Ok(mfa_token) = self.mint_mfa_pending(spec) else {
                let mut reply = Self::failure(500, "token issue failed", path);
                attach_cid(&mut reply);
                return Err(reply);
            };
            let mut reply = Self::json(
                202,
                json!({
                    "status": "mfa_required",
                    "mfa_required": true,
                    "mfa_token": mfa_token,
                    "mfa_method": "totp",
                    "step_up_reason": result.reason,
                    "step_up_methods": result.step_up_methods,
                    "correlation_id": result.correlation_id.as_deref().unwrap_or(""),
                }),
            );
            attach_cid(&mut reply);
            return Err(Self::threat_no_outcome(reply));
        }

        Ok(result.policy_id)
    }

    /// Produces the login-time `device` claim gated on `feature.device_trust_enforcement`.
    /// Uses an RLS-scoped user transaction + `device_hash=$1 AND user_id=$2`; row lookup
    /// failures fail open as `None` (no claim), keeping flag-read faults distinct.
    pub(super) async fn resolve_device_claim(
        &self,
        user_id: i64,
        agent: &str,
        ip: &str,
        dt_enabled: bool,
    ) -> Option<Value> {
        if !dt_enabled || user_id <= 0 {
            return None;
        }
        let fp = setjoin_threat::fingerprint(agent, ip);
        if fp.is_empty() {
            return None;
        }
        let device_hash = format!("{:x}", Sha256::digest(fp.as_bytes()));
        let actor = setjoin_contracts::ids::ActorId::new(user_id).ok()?;
        let rows = crate::policy_composition::user_read(
            &self.exec,
            actor,
            "SELECT compliance_status FROM managed_devices WHERE device_hash=$1 AND user_id=$2",
            &[
                (&device_hash, setjoin_pg::Type::TEXT),
                (&user_id, setjoin_pg::Type::INT8),
            ],
        )
        .await
        .ok()?;
        let status = rows.first()?.try_get::<_, String>(0).ok()?;
        map_managed_compliance_to_claim(&device_hash, &status)
    }

    /// Reads `policy_session_view(policy_id)` for `(sif_seconds, persistent_session)`.
    /// Matched-policy read errors fail closed: `sif = Some(3600)`, `persist = "never"`.
    pub(super) async fn session_controls(&self, policy_id: i64) -> (Option<i64>, String) {
        if policy_id == 0 {
            return (None, "always".to_owned());
        }
        let Ok(rows) = crate::policy_composition::pre_auth_read(
            self.pre_auth_pool.as_ref(),
            "SELECT policy_session_view($1)::text",
            &[(&policy_id, setjoin_pg::Type::INT8)],
        )
        .await
        else {
            return (Some(3600), "never".to_owned());
        };
        let Some(row) = rows.first() else {
            return (Some(3600), "never".to_owned());
        };
        let Ok(raw_opt) = row.try_get::<_, Option<String>>(0) else {
            return (Some(3600), "never".to_owned());
        };
        let Some(raw) = raw_opt else {
            return (None, "always".to_owned());
        };
        parse_session_controls(&raw)
    }

    /// Stamps `device`, `sif`, and original `auth_time` onto both access and refresh claims.
    pub(super) fn apply_session_claims(
        access: &mut Value,
        refresh: &mut Value,
        now: i64,
        device_claim: Option<&Value>,
        sif: Option<i64>,
    ) {
        if let Some(dc) = device_claim {
            access["device"] = dc.clone();
            refresh["device"] = dc.clone();
        }
        if let Some(secs) = sif {
            access["sif"] = json!(secs);
            access["auth_time"] = json!(now);
            refresh["sif"] = json!(secs);
            refresh["auth_time"] = json!(now);
        }
    }

    /// Formats the `access_token` `Set-Cookie` header honoring `persistent_session`.
    /// Never emits `Max-Age=0` (which deletes the cookie): `"never"` and unchecked
    /// `"user_choice"` omit `Max-Age` so the browser stores a session cookie.
    pub(super) fn access_cookie_header(
        &self,
        access: &str,
        secure: bool,
        persist: &str,
        stay_signed_in: bool,
    ) -> hyper::header::HeaderValue {
        let max_age = match persist {
            "never" => String::new(),
            "user_choice" if !stay_signed_in => String::new(),
            _ => format!(" Max-Age={};", self.config.access_seconds),
        };
        format!(
            "access_token={access}; Path=/;{max_age} HttpOnly;{} SameSite=Strict",
            if secure { " Secure;" } else { "" }
        )
        .parse()
        .unwrap()
    }
}

fn map_managed_compliance_to_claim(device_hash: &str, status: &str) -> Option<Value> {
    match status {
        "compliant" => Some(json!({
            "id": device_hash,
            "platform": "",
            "trust_tier": "compliant",
            "compliance_status": "ok",
            "wipe_requested": false,
        })),
        "non_compliant" => Some(json!({
            "id": device_hash,
            "platform": "",
            "trust_tier": "quarantined",
            "compliance_status": "",
            "wipe_requested": false,
        })),
        _ => None,
    }
}

fn parse_session_controls(raw: &str) -> (Option<i64>, String) {
    let Ok(view) = serde_json::from_str::<Value>(raw) else {
        return (Some(3600), "never".to_owned());
    };
    let sif = view.get("sign_in_frequency").and_then(|v| {
        if v.is_null() {
            return None;
        }
        let value = v.get("value").and_then(Value::as_i64).filter(|n| *n > 0)?;
        let unit = v.get("unit").and_then(Value::as_str)?;
        match unit {
            "hours" => value.checked_mul(3600),
            "days" => value.checked_mul(86400),
            _ => None,
        }
    });
    let persist = view
        .get("persistent_session")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("always")
        .to_owned();
    (sif, persist)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_method_maps_completed_factors_like_go() {
        assert_eq!(
            AuthServer::auth_method_from_completed_factors(&["pwd".into()]),
            "password"
        );
        assert_eq!(
            AuthServer::auth_method_from_completed_factors(&["pwd".into(), "otp".into()]),
            "totp"
        );
        assert_eq!(
            AuthServer::auth_method_from_completed_factors(&[
                "pwd".into(),
                "swk".into(),
                "user".into()
            ]),
            "push"
        );
        assert_eq!(
            AuthServer::auth_method_from_completed_factors(&["hwk".into()]),
            "webauthn"
        );
        assert_eq!(
            AuthServer::auth_method_from_completed_factors(&["hwk".into(), "otp".into()]),
            "totp"
        );
    }

    #[test]
    fn session_controls_parse_hours_days_absent_and_malformed() {
        assert_eq!(
            parse_session_controls(
                r#"{"sign_in_frequency":{"value":4,"unit":"hours"},"persistent_session":"never"}"#
            ),
            (Some(14400), "never".to_owned())
        );
        assert_eq!(
            parse_session_controls(
                r#"{"sign_in_frequency":{"value":2,"unit":"days"},"persistent_session":"user_choice"}"#
            ),
            (Some(172800), "user_choice".to_owned())
        );
        assert_eq!(
            parse_session_controls(r#"{"sign_in_frequency":null}"#),
            (None, "always".to_owned())
        );
        assert_eq!(
            parse_session_controls(r#"{"sign_in_frequency":{"value":0,"unit":"hours"}}"#),
            (None, "always".to_owned())
        );
        assert_eq!(
            parse_session_controls("not-json"),
            (Some(3600), "never".to_owned())
        );
    }

    #[test]
    fn managed_compliance_mapping_matches_go_producer() {
        let compliant = map_managed_compliance_to_claim("abc", "compliant").unwrap();
        assert_eq!(compliant["trust_tier"], "compliant");
        assert_eq!(compliant["compliance_status"], "ok");
        assert_eq!(compliant["id"], "abc");

        let quarantined = map_managed_compliance_to_claim("abc", "non_compliant").unwrap();
        assert_eq!(quarantined["trust_tier"], "quarantined");
        assert_eq!(quarantined["compliance_status"], "");

        assert!(map_managed_compliance_to_claim("abc", "unknown").is_none());
    }

    #[test]
    fn cookie_header_omits_max_age_without_zero_deletion() {
        let server = AuthServer::new(
            setjoin_pg::ScopedExecutor::from_dsn("postgres://nobody@127.0.0.1:1/none", 1).unwrap(),
        );
        let always = server
            .access_cookie_header("tok", false, "always", false)
            .to_str()
            .unwrap()
            .to_owned();
        assert!(always.contains("Max-Age=3600;"));
        let never = server
            .access_cookie_header("tok", true, "never", true)
            .to_str()
            .unwrap()
            .to_owned();
        assert!(!never.contains("Max-Age"));
        assert!(never.contains("Secure;"));
        let uc_false = server
            .access_cookie_header("tok", false, "user_choice", false)
            .to_str()
            .unwrap()
            .to_owned();
        assert!(!uc_false.contains("Max-Age"));
        let uc_true = server
            .access_cookie_header("tok", false, "user_choice", true)
            .to_str()
            .unwrap()
            .to_owned();
        assert!(uc_true.contains("Max-Age=3600;"));
    }
}
