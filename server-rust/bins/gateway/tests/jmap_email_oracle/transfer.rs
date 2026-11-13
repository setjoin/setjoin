//! Validate minted credentials with a fixed KDF result recorded from frozen Go,
//! then normalize only generated identity/time/signature and policy digest.
use super::{BoxError, Fx, scrub::scrub};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

pub fn normalize(
    raw: &str,
    parent: &str,
    fx: &Fx,
    generation: &str,
    seen: &mut Vec<String>,
) -> Result<String, BoxError> {
    if !raw.trim_start().starts_with('{') {
        return Ok(raw.into());
    }
    let response: Value = serde_json::from_str(raw)?;
    let Some(token) = response["token"].as_str() else {
        return Ok(raw.into());
    };
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("invalid minted JWT".into());
    }
    let header = String::from_utf8(URL_SAFE_NO_PAD.decode(parts[0])?)?;
    if header != r#"{"alg":"HS256","kid":"mailserver-mail-attachment-1","typ":"JWT"}"# {
        return Err("wrong attachment JWT header/order".into());
    }
    // Go cryptokey.DeriveMailAttachmentTokenKey(public fixture master), source
    // 1d9d2b58; command recorded in the JMAP2 oracle notes. Independent of Rust HKDF.
    let key = "8dd5bbff6530bfc2898d719fe4c95e5301e66a93f1d5c0191848284ff6ada926";
    let key: Vec<u8> = (0..key.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&key[i..i + 2], 16).unwrap())
        .collect();
    let mut mac = Hmac::<Sha256>::new_from_slice(&key)?;
    mac.update(format!("{}.{}", parts[0], parts[1]).as_bytes());
    mac.verify_slice(&URL_SAFE_NO_PAD.decode(parts[2])?)?;
    let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(parts[1])?)?;
    let p: Value = serde_json::from_str(&payload)?;
    let parent: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(parent.split('.').nth(1).ok_or("parent payload")?)?,
    )?;
    let id = p["jti"].as_str().ok_or("missing minted JTI")?;
    if id.len() != 36
        || &id[14..15] != "4"
        || !matches!(&id[19..20], "8" | "9" | "a" | "b")
        || seen.iter().any(|s| s == id)
        || p["jti"] == parent["jti"]
    {
        return Err("minted JTI is not fresh UUIDv4".into());
    }
    seen.push(id.into());
    let iat = p["iat"].as_i64().ok_or("minted iat")?;
    let exp = p["exp"].as_i64().ok_or("minted exp")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    if exp - iat != 300
        || !(0..=120).contains(&(now - iat))
        || exp <= parent["exp"].as_i64().ok_or("parent expiry")?
    {
        return Err("minted TTL/time or parent-expiry parity differs".into());
    }
    let expires = response["expiresAt"].as_str().ok_or("expiresAt")?;
    if chrono::DateTime::parse_from_rfc3339(expires)?.timestamp() != exp {
        return Err("expiry envelope mismatch".into());
    }
    for key in ["uid", "email", "fam", "device"] {
        if p[key] != parent[key] {
            return Err(format!("minted {key} differs from verified parent").into());
        }
    }
    if p["typ"] != "access"
        || p["scp"] != "mail-attachment"
        || p["iss"] != "mailserver"
        || p["aud"] != json!(["mailserver-gateway"])
    {
        return Err("minted scope/issuer/audience mismatch".into());
    }
    let expected = json!({"sha256":super::cases::OWN_BLOB,"account_id":fx.a.mailbox,"mailbox_id":fx.a.mailbox,"device_id":fx.extra["native-device"],"device_fingerprint":"gofree-jmap2-device","policy_generation":generation,"origin_jti":parent["jti"],"origin_iat":parent["iat"]});
    if p["attachment"] != expected {
        return Err(format!("incorrect attachment binding: {}", p["attachment"]).into());
    }
    for key in [
        "admin",
        "perms",
        "domain",
        "act",
        "acr",
        "amr",
        "auth_time",
        "cnf",
        "mam",
        "risk",
    ] {
        if p.get(key).is_some() {
            return Err(format!("minted token leaked parent {key}").into());
        }
    }
    let mut normalized = payload
        .replace(&format!("\"jti\":{}", p["jti"]), "\"jti\":\"<fresh-jti>\"")
        .replace(&format!("\"iat\":{iat}"), "\"iat\":\"<issued-at>\"")
        .replace(&format!("\"exp\":{exp}"), "\"exp\":\"<expires-at>\"")
        .replace(
            &format!("\"origin_iat\":{}", parent["iat"]),
            "\"origin_iat\":\"<origin-issued-at>\"",
        )
        .replace(parent["jti"].as_str().ok_or("parent jti")?, "<origin-jti>")
        .replace(
            parent["fam"].as_str().ok_or("parent family")?,
            "<origin-family>",
        )
        .replace(generation, "<verified-policy-generation>");
    normalized = scrub(&normalized, &fx.names);
    let token_normalized = format!(
        "{}.{}.<verified-signature>",
        parts[0],
        URL_SAFE_NO_PAD.encode(normalized)
    );
    Ok(raw.replace(token, &token_normalized))
}
