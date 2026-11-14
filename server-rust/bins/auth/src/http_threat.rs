//! Shared native HTTP threat ingress (#342; reused by #346 for login/recovery/TOTP).
//! The parts of Go's ThreatInterceptor that run with every toggle off, the existing
//! login pending boundary, and the postAuth auth_attempts tail.
use super::*;
use setjoin_pg::Type;

impl AuthServer {
    /// Login's existing #420/#405 boundary, moved verbatim (no new forward path).
    /// DELETE (#142) must resolve these shapes for every caller together.
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

    /// Go stepIPRules: always runs, because authserverd always installs the policy
    /// engine (main.go:602). Returns Go's writeResult(ActionReject) bytes.
    pub(super) async fn http_ip_rules(
        &self,
        ip: &str,
        agent: &str,
        username: &str,
    ) -> Option<Response<Body>> {
        if !setjoin_threat::ip_rule_blocked(&self.exec, ip).await {
            return None;
        }
        self.http_attempt(ip, agent, username, "ip_blocked").await;
        Some(
            Response::builder()
                .status(403)
                .header("content-type", "application/json")
                .header("x-threat-reason", "ip_blocked")
                .body(body(
                    "{\"captcha_prompt\":\"Access denied by security policy\",\"error\":\"ip_blocked\"}\n",
                ))
                .unwrap(),
        )
    }
}

/// Go extractMeta username: a top-level string `email` (case-folded key), else the
/// email inside a `refresh_token` JWT payload (RawURL, then padded Std base64).
pub(super) fn threat_username(raw: &[u8]) -> String {
    use base64::Engine as _;
    fn folded(map: &serde_json::Map<String, Value>, name: &str) -> Option<String> {
        let mut out = None;
        for (k, v) in map {
            if ingress::fold_name(k) == name {
                match v {
                    Value::String(s) => out = Some(s.clone()),
                    Value::Null => {}
                    _ => return None,
                }
            }
        }
        out.filter(|s| !s.is_empty())
    }
    let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(&ingress::go_decode_bytes(raw))
    else {
        return String::new();
    };
    if let Some(email) = folded(&map, "email") {
        return email;
    }
    let Some(token) = folded(&map, "refresh_token") else {
        return String::new();
    };
    let Some(payload) = token.split('.').nth(1) else {
        return String::new();
    };
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(payload))
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v.as_object().and_then(|m| folded(m, "email")))
        .unwrap_or_default()
}
