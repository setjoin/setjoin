//! Backup transport and frozen signed formats shared by operator and server.
pub mod recovery;
pub mod restore;
pub mod store;
pub mod worker;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
};
pub fn digest(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}
pub fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key), data)
        .as_ref()
        .to_vec()
}
pub fn json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value)
        .unwrap()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}
pub fn file_digest(path: &Path) -> Result<(String, u64), String> {
    let mut f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut size = 0;
    loop {
        let n = f.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&buffer[..n]);
        size += n as u64;
    }
    Ok((hex(&h.finalize()), size))
}
pub struct TempFile {
    pub path: PathBuf,
}
impl TempFile {
    pub fn new(prefix: &str, suffix: &str) -> Result<Self, String> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut bytes = [0; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes)
            .map_err(|_| "temporary filename randomness")?;
        let path = std::env::temp_dir().join(format!("{prefix}{}{suffix}", hex(&bytes)));
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| e.to_string())?;
        Ok(Self { path })
    }
    pub fn write(&self, data: &[u8]) -> Result<(), String> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        f.write_all(data)
            .and_then(|_| f.sync_all())
            .map_err(|e| e.to_string())
    }
}
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct DumpEnvelope {
    pub schema: String,
    pub object_key: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub algorithm: String,
    pub created_at: String,
    pub hmac_sha256: String,
}
pub fn seal_dump(path: &Path, key: &str, secret: &[u8]) -> Result<Vec<u8>, String> {
    if secret.len() < 32 {
        return Err("dump authentication HMAC key must be at least 32 bytes".into());
    }
    let (hash, size) = file_digest(path)?;
    let mut e = DumpEnvelope {
        schema: "setjoin.mailctl.dump-auth/v1".into(),
        object_key: key.into(),
        size_bytes: size as i64,
        sha256: hash,
        algorithm: "hmac-sha256".into(),
        created_at: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        hmac_sha256: String::new(),
    };
    e.hmac_sha256 = hex(&hmac(secret, json(&e).as_bytes()));
    let mut out = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b" ");
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, formatter);
    serde::Serialize::serialize(&e, &mut serializer).map_err(|e| e.to_string())?;
    out.push(b'\n');
    Ok(out)
}
pub fn verify_dump(path: &Path, key: &str, secret: &[u8], sidecar: &[u8]) -> Result<(), String> {
    let mut e: DumpEnvelope = serde_json::from_slice(sidecar).map_err(|err| {
        let msg = err.to_string();
        if msg.starts_with("trailing characters") {
            return "dump authentication sidecar carries trailing data".into();
        }
        let msg = if let Some(rest) = msg.strip_prefix("unknown field `") {
            format!(
                "json: unknown field {:?}",
                rest.split('`').next().unwrap_or("")
            )
        } else {
            msg
        };
        format!("dump authentication sidecar is not valid setjoin.mailctl.dump-auth/v1 JSON: {msg}")
    })?;
    if e.schema != "setjoin.mailctl.dump-auth/v1" || e.algorithm != "hmac-sha256" {
        return Err(format!(
            "dump authentication sidecar schema/algorithm mismatch: {:?}/{:?}",
            e.schema, e.algorithm
        ));
    }
    if e.object_key != key {
        return Err(format!(
            "dump authentication sidecar binds {:?}, not the requested {key:?}",
            e.object_key
        ));
    }
    let digest_shape = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if e.size_bytes < 0 || !digest_shape(&e.sha256) || !digest_shape(&e.hmac_sha256) {
        return Err("dump authentication sidecar envelope is malformed".into());
    }
    if chrono::DateTime::parse_from_rfc3339(&e.created_at).is_err() {
        return Err(format!(
            "dump authentication sidecar timestamp is not RFC 3339: {:?}",
            e.created_at
        ));
    }
    if secret.len() < 32 {
        return Err("dump authentication HMAC key must be at least 32 bytes".into());
    }
    let signature = std::mem::take(&mut e.hmac_sha256);
    let signature = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&signature[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    ring::hmac::verify(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256,secret),json(&e).as_bytes(),&signature).map_err(|_|"dump authentication HMAC mismatch: the sidecar was not sealed under the configured key (wrong key or tampered binding)")?;
    let (hash, size) = file_digest(path)?;
    if size as i64 != e.size_bytes || hash != e.sha256 {
        return Err("dump bytes do not match the authenticated publication binding (size/digest mismatch) — the dump was substituted or corrupted after publication".into());
    }
    Ok(())
}

mod local;
