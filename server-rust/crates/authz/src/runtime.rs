//! Verified request proof for the mailserver runtime gates. It grants no target
//! permission; route adapters retain mailbox, lifecycle and governed authority.
use super::token::KeySource;
use serde_json::Value;

pub struct Proof(Value);
impl Proof {
    /// Dedicated attachment credential, for the attachment HTTP surface only.
    /// This seals the same signed device/session claims as an ordinary proof;
    /// it grants no blob or mailbox authority.
    pub fn attachment(token: &str, issuer: &str, now: f64, secrets: &[&[u8]]) -> Option<Self> {
        let (_, claims) = super::token::attachment(token, issuer, now, secrets)?;
        Some(Self(claims))
    }

    pub async fn verify(
        token: &str,
        issuer: &str,
        now: f64,
        keys: &impl KeySource,
        drive: bool,
    ) -> Option<Self> {
        let claims =
            Value::Object(super::token::validate_first_party(token, issuer, now, keys).await?);
        if claims["typ"] != "access"
            || claims["uid"].as_i64().is_none_or(|id| id <= 0)
            || claims["acct"] == "guest"
        {
            return None;
        }
        let scope = claims["scp"].as_str().unwrap_or("");
        if !scope.is_empty() && !(drive && scope == "drive") {
            return None;
        }
        Some(Self(claims))
    }
    pub fn user_id(&self) -> i64 {
        self.0["uid"].as_i64().expect("verified positive uid")
    }
    pub fn claims(&self) -> &Value {
        &self.0
    }
}

impl Proof {
    /// Go's default legacy policy has no admitted claim-less token classes.
    pub fn compliance_denial(&self) -> Option<(&'static str, &'static str)> {
        let device = &self.0["device"];
        if device.is_null() {
            return Some(("device_compliance_unverifiable","Device compliance could not be verified from this token. Sign in again from your device."));
        }
        if device["wipe_requested"] == true {
            return Some((
                "Forbidden",
                "Device has been wiped. Contact your administrator.",
            ));
        }
        if device["trust_tier"] == "quarantined" {
            return Some((
                "Forbidden",
                "Device is quarantined. Check compliance status in device settings.",
            ));
        }
        None
    }
    pub fn device_id(&self) -> &str {
        self.0["device"]["id"].as_str().unwrap_or("")
    }
}
