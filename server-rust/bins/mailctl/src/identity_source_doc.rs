//! The identity source file's closed offline schema, matching frozen Go.
use crate::{
    client::Failure,
    part_b::{json_arg, text},
};
use serde_json::Value;
fn bounded(s: &str, n: usize) -> bool {
    !s.is_empty() && s.trim() == s && s.len() <= n && !s.chars().any(|c| c < ' ' || c == '\u{7f}')
}
fn unknown(v: &Value, keys: &[&str]) -> Option<String> {
    v.as_object()?
        .keys()
        .find(|k| !keys.contains(&k.as_str()))
        .cloned()
}
pub(super) fn validate(raw: &str) -> Result<String, Failure> {
    if raw.is_empty() || raw.len() > 65536 {
        return Err("identity source file must be 1..65536 bytes".into());
    }
    let v = json_arg(raw, "invalid identity source file: ")?;
    if let Some(key) = unknown(&v, &["apiVersion", "kind", "metadata", "spec"])
        .or_else(|| unknown(&v["metadata"], &["sourceKey", "displayName"]))
    {
        return Err(format!("invalid identity source file: json: unknown field {key:?}").into());
    }
    let key = text(&v["metadata"], "sourceKey");
    if text(&v, "apiVersion") != "setjoin.io/v1"
        || text(&v, "kind") != "IdentitySource"
        || key.is_empty()
        || key.len() > 64
        || !bounded(text(&v["metadata"], "displayName"), 128)
    {
        return Err("identity source file has invalid apiVersion, kind, or metadata".into());
    }
    if !key
        .bytes()
        .enumerate()
        .all(|(i, b)| b.is_ascii_alphanumeric() || (i > 0 && b"._:-".contains(&b)))
    {
        return Err("identity source metadata.sourceKey is invalid".into());
    }
    let spec = &v["spec"];
    if !spec.is_object() {
        return Err("identity source spec must be an object".into());
    }
    let ty = text(spec, "type");
    let allowed: &[&str] = match ty {
        "local" => &[
            "type",
            "capabilities",
            "passwordPolicy",
            "passkeyPolicy",
            "mfaPolicy",
        ],
        "ad" | "ldap" => &[
            "type",
            "capabilities",
            "endpoint",
            "subjectAttribute",
            "baseDN",
            "bindDN",
            "userFilter",
            "groupFilter",
            "mapping",
            "deletionPolicy",
        ],
        "scim" => &[
            "type",
            "capabilities",
            "deletionPolicy",
            "mapping",
            "tokenLabel",
            "tokenExpiry",
        ],
        "saml" => &[
            "type",
            "capabilities",
            "registrationKey",
            "idpEntityId",
            "metadataUrl",
            "ssoUrl",
            "certificateRef",
            "spEntityId",
            "persistentNameId",
            "attributeMapping",
            "groupMapping",
            "jitPolicy",
        ],
        "oidc" => &[
            "type",
            "capabilities",
            "providerKey",
            "issuer",
            "clientId",
            "redirectUri",
            "scopes",
            "claimMapping",
            "subjectClaim",
            "jitPolicy",
        ],
        _ => return Err("identity source spec.type is unsupported".into()),
    };
    if let Some(k) = unknown(spec, allowed) {
        return Err(format!("identity source spec contains unsupported field {k:?}").into());
    }
    let require = |name: &str, max: usize| -> Result<&str, Failure> {
        let value = text(spec, name);
        if !bounded(value, max) {
            Err(format!("identity source spec.{name} is required and must be bounded text").into())
        } else {
            Ok(value)
        }
    };
    match ty {
        "ad" | "ldap" => {
            require("baseDN", 2048)?;
            let subject = require("subjectAttribute", 128)?;
            if ty == "ad" && !["objectGUID", "msDS-ConsistencyGuid"].contains(&subject) {
                return Err(
                    "AD subjectAttribute must be objectGUID or msDS-ConsistencyGuid".into(),
                );
            }
            let ep = &spec["endpoint"];
            if unknown(ep, &["host", "port", "tls"]).is_some()
                || !bounded(text(ep, "host"), 253)
                || !ep["port"]
                    .as_i64()
                    .is_some_and(|n| (1..=65535).contains(&n))
                || !["ldaps", "starttls"].contains(&text(ep, "tls"))
            {
                return Err("identity source endpoint requires bounded host, port, and tls".into());
            }
        }
        "saml" => {
            require("registrationKey", 255)?;
            require("idpEntityId", 2048)?;
        }
        "oidc" => {
            require("providerKey", 255)?;
            require("issuer", 2048)?;
            require("clientId", 1024)?;
            if require("subjectClaim", 128).ok() != Some("sub") {
                return Err("OIDC subjectClaim must be sub".into());
            }
        }
        _ => {}
    }
    if let Some(c) = spec.get("capabilities") {
        if !c.is_object() {
            return Err("identity source capabilities must be an object".into());
        }
        if let Some(k) = unknown(
            c,
            &[
                "authenticate",
                "provisionLifecycle",
                "passwordWriteback",
                "profileFields",
                "entitlements",
                "deltaCursor",
                "suspendDelete",
                "immutableSubject",
            ],
        ) {
            return Err(
                format!("identity source capabilities contain unsupported field {k:?}").into(),
            );
        }
    }
    Ok(key.into())
}
