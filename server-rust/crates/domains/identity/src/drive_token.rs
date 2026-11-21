//! Frozen gateway's narrow HS256 exception: a Drive-only mirror, never a new session.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::hmac;
use serde_json::json;
use setjoin_authz::push::PushIdentity;
pub struct Issuer {
    key: hmac::Key,
    issuer: String,
}
pub enum Refused {
    DeviceBound,
    Expired,
}
impl Issuer {
    pub fn new(secret: &[u8], issuer: String) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
            issuer,
        }
    }
    pub fn issue(&self, source: &PushIdentity, now: i64) -> Result<String, Refused> {
        if source.has_device_binding() {
            return Err(Refused::DeviceBound);
        }
        let expiry = source
            .expires_at()
            .map_or(now + 43200, |exp| (now + 43200).min(exp));
        if expiry <= now {
            return Err(Refused::Expired);
        }
        let mut claims = json!({"uid":source.user_id(),"email":source.email(),"typ":"access","scp":"drive","iss":self.issuer,"aud":["mailserver-gateway"],"iat":now,"exp":expiry});
        // Owner-approved security fix 2026-11-05 (#495): an impersonated source
        // keeps its `act` provenance in the derived Drive token.
        if let Some(act) = source.act() {
            if !setjoin_contracts::mutants::on("drive-token-drops-act") {
                claims["act"] = json!(act);
            }
        }
        for (name, value) in [
            ("jti", source.token_id()),
            ("fam", source.token_family()),
            ("acct", source.account_type()),
        ] {
            if !value.is_empty() {
                claims[name] = json!(value);
            }
        }
        let header = URL_SAFE_NO_PAD
            .encode(br#"{"alg":"HS256","kid":"mailserver-drive-native-1","typ":"JWT"}"#);
        let signed = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims.to_string()));
        let token = format!(
            "{signed}.{}",
            URL_SAFE_NO_PAD.encode(hmac::sign(&self.key, signed.as_bytes()).as_ref())
        );
        let expires = chrono::DateTime::from_timestamp(expiry, 0)
            .expect("verified JWT timestamp")
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        Ok(format!(
            "{}\n",
            crate::issuance::object(&[("token", json!(token)), ("expiresAt", json!(expires))])
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mints_12h_drive_token_from_basic_identity_without_panic() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let issuer = Issuer::new(secret, "mailserver".into());
        let source = PushIdentity::from_basic(42, "alice@example.test");
        let now = 1_700_000_000_i64;
        let body = issuer.issue(&source, now).expect("basic drive mint");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let token = parsed["token"].as_str().unwrap();
        let verifier = setjoin_authz::legacy_jwt::LegacyKeys::new(
            secret,
            &["mailserver-drive-native-1"],
            None,
        )
        .unwrap();
        let claims = verifier
            .validate(token, "mailserver", "mailserver-gateway", now as f64)
            .unwrap();
        assert_eq!(claims["uid"], 42);
        assert_eq!(claims["email"], "alice@example.test");
        assert_eq!(claims["scp"], "drive");
        assert_eq!(claims["typ"], "access");
        assert_eq!(claims["iat"], now);
        assert_eq!(claims["exp"], now + 43200);
        assert!(!claims.contains_key("act"));
        assert!(!claims.contains_key("jti"));
        assert!(!claims.contains_key("fam"));
        assert!(!claims.contains_key("acct"));
        let expires_at = chrono::DateTime::parse_from_rfc3339(
            parsed["expiresAt"].as_str().unwrap(),
        )
        .unwrap()
        .timestamp();
        assert_eq!(expires_at, now + 43200);
    }
}
