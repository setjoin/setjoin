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
        let expiry = (now + 43200).min(source.expires_at());
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
