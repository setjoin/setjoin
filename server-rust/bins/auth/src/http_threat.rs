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
        let reason = match setjoin_threat::ip_rule_blocked(&self.exec, ip).await {
            Ok(false) => return None,
            Ok(true) => "ip_blocked",
            // #367: an unanswered lookup rejects, as the protocol gate does.
            Err(()) => "ip_rules_unavailable",
        };
        self.http_attempt(ip, agent, username, reason).await;
        Some(
            Response::builder()
                .status(403)
                .header("content-type", "application/json")
                .header("x-threat-reason", reason)
                .body(body(format!(
                    "{{\"captcha_prompt\":\"Access denied by security policy\",\"error\":\"{reason}\"}}\n"
                )))
                .unwrap(),
        )
    }
}

/// Go `json.Unmarshal` into `struct { F string }` (encoding/json v1): the whole
/// document must be valid with only whitespace after it; object keys are visited in
/// document order and every key folding to `name` (exact or case-insensitive,
/// including the Kelvin/long-s folds) assigns the same field, so the last string
/// wins and `null` keeps the earlier value; any other value type is an
/// UnmarshalTypeError that fails the whole call even if a later key is a string.
/// A top-level `null` decodes to the zero value; any other non-object fails.
fn go_string_field(raw: &[u8], name: &str) -> Option<String> {
    use serde::de::{DeserializeSeed, Deserializer, Error as _, IgnoredAny, MapAccess, Visitor};
    struct Field<'a>(&'a str);
    impl<'de> Visitor<'de> for Field<'_> {
        type Value = String;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("object or null")
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<String, E> {
            Ok(String::new())
        }
        fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> Result<String, M::Error> {
            let mut out = String::new();
            let mut mismatch = false;
            while let Some(key) = m.next_key::<String>()? {
                if ingress::fold_name(&key) != self.0 {
                    m.next_value::<IgnoredAny>()?;
                    continue;
                }
                match m.next_value::<Value>()? {
                    Value::String(s) => out = s,
                    Value::Null => {}
                    _ => mismatch = true,
                }
            }
            if mismatch {
                Err(M::Error::custom("type mismatch"))
            } else {
                Ok(out)
            }
        }
    }
    impl<'de> DeserializeSeed<'de> for Field<'_> {
        type Value = String;
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<String, D::Error> {
            d.deserialize_any(self)
        }
    }
    let decoded = ingress::go_decode_bytes(raw);
    let mut de = serde_json::Deserializer::from_slice(&decoded);
    let value = Field(name).deserialize(&mut de).ok()?;
    de.end().ok()?;
    Some(value)
}

/// Go extractMeta (shared/threat/interceptor.go): a non-empty `email` from a
/// successful Unmarshal of the whole body, else a non-empty `refresh_token` whose
/// JWT payload segment (RawURLEncoding, then StdEncoding; both skip CR/LF and accept
/// non-zero trailing bits) Unmarshals into `email`.
pub(super) fn threat_username(raw: &[u8]) -> String {
    use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
    use base64::engine::DecodePaddingMode;
    use base64::{alphabet, Engine as _};
    if let Some(email) = go_string_field(raw, "email").filter(|s| !s.is_empty()) {
        return email;
    }
    let Some(token) = go_string_field(raw, "refresh_token").filter(|s| !s.is_empty()) else {
        return String::new();
    };
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return String::new();
    }
    let segment: String = parts[1]
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n'))
        .collect();
    let raw_url = GeneralPurpose::new(
        &alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireNone),
    );
    let std = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
    );
    let Ok(payload) = raw_url.decode(&segment).or_else(|_| std.decode(&segment)) else {
        return String::new();
    };
    go_string_field(&payload, "email").unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::threat_username;

    fn jwt(payload: &str) -> String {
        use base64::Engine as _;
        format!(
            "h.{}.s",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload)
        )
    }

    #[test]
    fn username_follows_go_unmarshal() {
        let token = jwt(r#"{"email":"j@x","EMAIL":null}"#);
        let cases = [
            (r#"{"email":"a@x","email":null}"#.to_owned(), "a@x"),
            (r#"{"Email":"a@x","email":"b@x"}"#.to_owned(), "b@x"),
            (r#"{"email":"b@x","EMAIL":"a@x"}"#.to_owned(), "a@x"),
            (r#"{"email":"a@x","email":1}"#.to_owned(), ""),
            (r#"{"email":"a@x"} {}"#.to_owned(), ""),
            (r#"{"email":""}"#.to_owned(), ""),
            ("null".to_owned(), ""),
            ("[]".to_owned(), ""),
            (format!(r#"{{"email":1,"refresh_token":"{token}"}}"#), "j@x"),
            (format!(r#"{{"refreſh_token":"{token}"}}"#), "j@x"),
            (
                format!(r#"{{"REFRESH_TOKEN":"{token}","refresh_token":null}}"#),
                "j@x",
            ),
            (r#"{"refresh_token":"no-dot"}"#.to_owned(), ""),
        ];
        for (body, want) in cases {
            assert_eq!(threat_username(body.as_bytes()), want, "{body}");
        }
    }
}
