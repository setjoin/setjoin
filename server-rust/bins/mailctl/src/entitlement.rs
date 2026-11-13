//! Offline purpose-separated Ed25519 entitlement documents.
use crate::client::Failure;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::io::Read;
#[derive(Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Signature {
    key_id: String,
    algorithm: String,
    value: String,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Entitlement {
    schema_version: i64,
    entitlement_id: String,
    installation_id: String,
    customer_id: String,
    channels: Option<Vec<String>>,
    version_ranges: Option<Vec<String>>,
    issued_at: String,
    valid_from: String,
    valid_until: String,
    grace_until: String,
    #[serde(skip_serializing_if = "empty")]
    non_production_rights: Option<Vec<String>>,
    key_id: String,
    signatures: Option<Vec<Signature>>,
}
fn empty<T>(v: &Option<Vec<T>>) -> bool {
    v.as_ref().is_none_or(Vec::is_empty)
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Roots {
    schema_version: i64,
    purpose: String,
    keys: Option<Vec<Key>>,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Key {
    id: String,
    algorithm: String,
    public_key: String,
    test_only: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Output<'a> {
    entitlement_id: &'a str,
    installation_id: &'a str,
    customer_id: &'a str,
    channels: &'a Option<Vec<String>>,
    version_ranges: &'a Option<Vec<String>>,
    valid_until: &'a str,
    grace_until: &'a str,
    state: &'a str,
    digest: String,
}
fn env(k: &str, default: &str) -> String {
    std::env::var(k)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or(default.into())
}
fn path() -> String {
    env("SETJOIN_ENTITLEMENT_PATH", "/etc/setjoin/entitlement.json")
}
fn read(path: &str, max: u64) -> Result<Vec<u8>, String> {
    let mut raw = vec![];
    std::fs::File::open(path)
        .map_err(|e| format!("open {path}: {}", crate::flags::go_io_error(&e)))?
        .take(max + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() as u64 > max {
        return Err(format!("file exceeds {max} bytes"));
    }
    Ok(raw)
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn bounded_text(path: &str) -> Result<String, String> {
    let raw = read(path, 256)?;
    let v = String::from_utf8_lossy(&raw).trim().to_owned();
    if !identifier(&v) {
        return Err("invalid bounded identifier".into());
    }
    Ok(v)
}
fn json<T: Serialize>(v: &T) -> String {
    serde_json::to_string(v)
        .unwrap()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}
fn version(s: &str) -> Result<(), String> {
    let invalid = || format!("invalid semantic version {s:?}");
    let (core, pre) = s
        .split_once('-')
        .map(|(a, b)| (a, Some(b)))
        .unwrap_or((s, None));
    let parts = core.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || parts.iter().any(|p| {
            p.is_empty()
                || (p.len() > 1 && p.starts_with('0'))
                || !p.bytes().all(|b| b.is_ascii_digit())
        })
    {
        return Err(invalid());
    }
    for p in parts {
        p.parse::<u64>()
            .map_err(|_| "semantic version component overflow")?;
    }
    if let Some(pre) = pre {
        for p in pre.split('.') {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err(invalid());
            }
            if p.len() > 1 && p.starts_with('0') && p.bytes().all(|b| b.is_ascii_digit()) {
                return Err("numeric prerelease identifiers cannot have leading zeroes".into());
            }
        }
    }
    Ok(())
}
fn validate(e: &Entitlement) -> Result<(), String> {
    if e.schema_version != 1 {
        return Err(format!(
            "unsupported entitlement schema {}",
            e.schema_version
        ));
    }
    for (name, value) in [
        ("entitlement_id", &e.entitlement_id),
        ("installation_id", &e.installation_id),
        ("customer_id", &e.customer_id),
        ("key_id", &e.key_id),
    ] {
        if !identifier(value) {
            return Err(format!("invalid {name}"));
        }
    }
    let channels = e.channels.as_deref().unwrap_or_default();
    if channels.is_empty() || channels.len() > 2 {
        return Err("invalid entitlement channels".into());
    }
    for (i, c) in channels.iter().enumerate() {
        if c != "enterprise" {
            return Err("local entitlement cannot gate community channel".into());
        }
        if i > 0 && channels[i - 1] >= *c {
            return Err("entitlement channels must be sorted and unique".into());
        }
    }
    let ranges = e.version_ranges.as_deref().unwrap_or_default();
    if ranges.is_empty() || ranges.len() > 16 {
        return Err("invalid entitlement version ranges".into());
    }
    for r in ranges {
        let parts = r.split_whitespace().collect::<Vec<_>>();
        let err = if parts.is_empty() || parts.len() > 4 {
            Some("version range requires one to four constraints".into())
        } else {
            parts.iter().find_map(|p| {
                let v = [">=", "<=", ">", "<", "="]
                    .iter()
                    .find_map(|op| p.strip_prefix(op))
                    .unwrap_or(p);
                version(v).err()
            })
        };
        if let Some(err) = err {
            return Err(format!("invalid entitlement version range: {err}"));
        }
    }
    for (name, t) in [
        ("issued_at", &e.issued_at),
        ("valid_from", &e.valid_from),
        ("valid_until", &e.valid_until),
        ("grace_until", &e.grace_until),
    ] {
        if !crate::offline::utc_second(t) {
            return Err(format!("{name} must be canonical UTC RFC3339 seconds"));
        }
    }
    if e.valid_from < e.issued_at || e.valid_until <= e.valid_from || e.grace_until < e.valid_until
    {
        return Err("invalid entitlement time ordering".into());
    }
    let rights = e.non_production_rights.as_deref().unwrap_or_default();
    for (i, r) in rights.iter().enumerate() {
        if !identifier(r) {
            return Err("invalid non_production_rights entry".into());
        }
        if i > 0 && rights[i - 1] >= *r {
            return Err("non_production_rights must be sorted and unique".into());
        }
    }
    let sig = e.signatures.as_deref().unwrap_or_default();
    if sig.len() != 1 {
        return Err("entitlement requires exactly one signature".into());
    }
    if sig[0].key_id != e.key_id || sig[0].algorithm != "ed25519" || sig[0].value.is_empty() {
        return Err("invalid entitlement signature".into());
    }
    Ok(())
}
pub fn run(action: &str, args: &[String]) -> Result<(), Failure> {
    let mut json_out = false;
    let mut positional = vec![];
    for a in args {
        if a == "--json" {
            json_out = true;
        } else if a.starts_with('-') {
            return Err(format!("unknown entitlement flag {a:?}").into());
        } else {
            positional.push(a);
        }
    }
    let input = match action {
        "show" if positional.is_empty() => path(),
        "import" if positional.len() == 1 => positional[0].to_owned(),
        "show" => return Err("usage: mailctl entitlement show [--json]".into()),
        "import" => return Err("usage: mailctl entitlement import <file> [--json]".into()),
        _ => {
            return Err(format!("unknown entitlement action: {action} (try: import, show)").into())
        }
    };
    let raw = read(&input, 1 << 20).map_err(|e| format!("read entitlement: {e}"))?;
    let roots = read(
        &env(
            "SETJOIN_ENTITLEMENT_TRUST_ROOTS",
            "/etc/setjoin/trust/entitlement-keys.json",
        ),
        1 << 20,
    )
    .map_err(|e| format!("read entitlement trust roots: {e}"))?;
    let r: Roots = crate::offline::strict(&roots).map_err(|e| format!("trust roots: {e}"))?;
    if r.schema_version != 1 || r.purpose != "entitlement" {
        return Err("trust root schema or purpose mismatch".into());
    }
    let keys = r.keys.as_deref().unwrap_or_default();
    if keys.is_empty() || keys.len() > 16 {
        return Err("trust root key count must be between 1 and 16".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for k in keys {
        if !identifier(&k.id) || k.algorithm != "ed25519" || !seen.insert(&k.id) {
            return Err("invalid or duplicate trust root key".into());
        }
        if STANDARD_NO_PAD
            .decode(&k.public_key)
            .map_or(true, |k| k.len() != 32)
        {
            return Err("invalid trust root public key".into());
        }
        if k.test_only {
            return Err(format!(
                "test trust root {:?} is forbidden by production policy",
                k.id
            )
            .into());
        }
    }
    let installation = bounded_text(&env(
        "SETJOIN_INSTALLATION_ID_FILE",
        "/etc/setjoin/installation-id",
    ))
    .map_err(|e| format!("read installation id: {e}"))?;
    let channel = bounded_text(&env(
        "SETJOIN_UPDATE_CHANNEL_FILE",
        "/etc/setjoin/update-channel",
    ))
    .map_err(|e| format!("read update channel: {e}"))?;
    if channel != "enterprise" {
        return Err(
            "local entitlement import is only valid for the configured enterprise channel".into(),
        );
    }
    let mut e: Entitlement =
        crate::offline::strict(&raw).map_err(|e| format!("entitlement: {e}"))?;
    validate(&e)?;
    if e.installation_id != installation {
        return Err("entitlement installation scope mismatch".into());
    }
    if !e
        .channels
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|c| c == &channel)
    {
        return Err("entitlement channel scope mismatch".into());
    }
    let signatures = e.signatures.take().unwrap();
    let canonical = json(&e);
    e.signatures = Some(signatures);
    let key = keys
        .iter()
        .find(|k| k.id == e.key_id)
        .ok_or("untrusted entitlement key")?;
    let signature = STANDARD_NO_PAD
        .decode(&e.signatures.as_ref().unwrap()[0].value)
        .map_err(|_| "invalid entitlement signature")?;
    let public = STANDARD_NO_PAD.decode(&key.public_key).unwrap();
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
        .verify(canonical.as_bytes(), &signature)
        .map_err(|_| "invalid entitlement signature")?;
    let now = chrono::Utc::now();
    let from = chrono::DateTime::parse_from_rfc3339(&e.valid_from).unwrap();
    let until = chrono::DateTime::parse_from_rfc3339(&e.valid_until).unwrap();
    let grace = chrono::DateTime::parse_from_rfc3339(&e.grace_until).unwrap();
    if now < from {
        return Err("entitlement is not yet valid".into());
    }
    let state = if now < until {
        "valid"
    } else if now < grace {
        "grace"
    } else {
        return Err("entitlement is expired".into());
    };
    if action == "import" {
        crate::offline::private_replace(&path(), &raw)
            .map_err(|e| format!("install entitlement: {e}"))?;
    }
    let output = Output {
        entitlement_id: &e.entitlement_id,
        installation_id: &e.installation_id,
        customer_id: &e.customer_id,
        channels: &e.channels,
        version_ranges: &e.version_ranges,
        valid_until: &e.valid_until,
        grace_until: &e.grace_until,
        state,
        digest: crate::offline::digest(canonical.as_bytes()),
    };
    if json_out {
        println!("{}", crate::part_b::ordered_pretty(&json(&output)));
    } else {
        println!("Entitlement {}: {}\nInstallation:        {}\nChannel:             {}\nState:               {}\nValid until:         {}\nGrace until:         {}\nDocument SHA-256:    {}",if action=="import"{"imported"}else{"installed"},e.entitlement_id,e.installation_id,e.channels.as_deref().unwrap_or_default().join(","),state,e.valid_until,e.grace_until,output.digest);
    }
    Ok(())
}
