//! Offline operator tools: no API/config/database construction at dispatch.
use crate::client::Failure;

pub fn run(cmd: &str, action: &str, args: &[String]) -> Result<(), Failure> {
    match (cmd, action) {
        ("dane", "generate") => {
            let f = crate::flags::parse(
                "dane generate",
                args,
                &["cert", "hostname", "usage", "selector", "matching"],
                &[],
                false,
            );
            if f.get("cert").is_empty() {
                return Err("--cert is required (path to PEM certificate file)".into());
            }
            if f.get("hostname").is_empty() {
                return Err("--hostname is required (e.g., mail.example.com)".into());
            }
            let usage = f.get("usage").parse::<i64>().unwrap_or(3) as u8;
            let selector = f.get("selector").parse::<i64>().unwrap_or(1) as u8;
            let matching = f.get("matching").parse::<i64>().unwrap_or(1) as u8;
            if usage > 3 {
                return Err(format!(
                    "invalid usage {usage}: must be 0-3 (PKIX-TA, PKIX-EE, DANE-TA, DANE-EE)"
                )
                .into());
            }
            if selector > 1 {
                return Err(format!(
                    "invalid selector {selector}: must be 0 (full cert) or 1 (SPKI)"
                )
                .into());
            }
            if matching > 2 {
                return Err(format!("invalid matching type {matching}: must be 0 (exact), 1 (SHA-256), or 2 (SHA-512)").into());
            }
            let data = std::fs::read(f.get("cert")).map_err(|e| {
                format!(
                    "read certificate file: open {}: {}",
                    f.get("cert"),
                    crate::flags::go_io_error(&e)
                )
            })?;
            let (_, pem) = x509_parser::pem::parse_x509_pem(&data)
                .map_err(|_| format!("no PEM block found in {}", f.get("cert")))?;
            if pem.label != "CERTIFICATE" {
                return Err(
                    format!("PEM block type is {:?}, expected CERTIFICATE", pem.label).into(),
                );
            }
            let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents)
                .map_err(|e| format!("parse certificate: {e}"))?;
            use sha2::{Digest, Sha256, Sha512};
            let input = if selector == 0 {
                pem.contents.as_slice()
            } else {
                cert.public_key().raw
            };
            let digest = match matching {
                0 => input.to_vec(),
                1 => Sha256::digest(input).to_vec(),
                _ => Sha512::digest(input).to_vec(),
            };
            let hash = digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let host = f
                .get("hostname")
                .strip_suffix('.')
                .unwrap_or(f.get("hostname"));
            if host.is_empty() {
                return Err("hostname is empty".into());
            }
            if host.len() > 253 {
                return Err(format!("hostname exceeds 253 octets ({})", host.len()).into());
            }
            for label in host.split('.') {
                if label.is_empty() {
                    return Err(format!("hostname {host:?} has an empty label").into());
                }
                if label.len() > 63 {
                    return Err(format!("hostname label {label:?} exceeds 63 octets").into());
                }
                if label.starts_with('-') || label.ends_with('-') {
                    return Err(format!(
                        "hostname label {label:?} must not start or end with a hyphen"
                    )
                    .into());
                }
                if let Some(b) = label
                    .bytes()
                    .find(|b| !b.is_ascii_alphanumeric() && *b != b'-')
                {
                    return Err(format!("hostname label {label:?} contains character {:?} outside the DNS name grammar (letters, digits, hyphen)",b as char).into());
                }
            }
            println!("_25._tcp.{host}. IN TLSA {usage} {selector} {matching} {hash}");
            Ok(())
        }
        ("dane", _) => Err(format!("unknown dane action: {action}. Try: generate").into()),
        ("entitlement", _) => crate::entitlement::run(action, args),
        ("exchange-a0", _) => crate::exchange_a0::run(action, args),
        ("exchange", _) => crate::exchange::run(action, args),
        _ => unreachable!(),
    }
}

pub(super) fn private_new(path: &str, data: &[u8]) -> Result<(), Failure> {
    crate::part_b::publish_new(path, data)
}

pub(super) fn digest(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub(super) fn bounded(path: &str, max: u64) -> Result<Vec<u8>, Failure> {
    let info = std::fs::symlink_metadata(path)
        .map_err(|e| format!("lstat {path}: {}", crate::flags::go_io_error(&e)))?;
    if !info.is_file() || info.len() > max {
        return Err(format!("input must be a regular file no larger than {max} bytes").into());
    }
    std::fs::read(path)
        .map_err(|e| format!("open {path}: {}", crate::flags::go_io_error(&e)).into())
}
pub(super) fn utc_second(s: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(s).is_ok_and(|t| {
        t.with_timezone(&chrono::Utc)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
            == s
    })
}

pub(super) fn strict<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T, String> {
    use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
    struct Depth(usize);
    impl<'de> DeserializeSeed<'de> for Depth {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
            if self.0 > 64 {
                return Err(D::Error::custom("JSON nesting exceeds 64 levels"));
            }
            d.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Depth {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("JSON value")
        }
        fn visit_bool<E: Error>(self, _: bool) -> Result<(), E> {
            Ok(())
        }
        fn visit_i64<E: Error>(self, _: i64) -> Result<(), E> {
            Ok(())
        }
        fn visit_u64<E: Error>(self, _: u64) -> Result<(), E> {
            Ok(())
        }
        fn visit_f64<E: Error>(self, _: f64) -> Result<(), E> {
            Ok(())
        }
        fn visit_str<E: Error>(self, _: &str) -> Result<(), E> {
            Ok(())
        }
        fn visit_unit<E: Error>(self) -> Result<(), E> {
            Ok(())
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<(), A::Error> {
            while a.next_element_seed(Depth(self.0 + 1))?.is_some() {}
            Ok(())
        }
        fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<(), A::Error> {
            let mut seen = std::collections::BTreeSet::new();
            while let Some(k) = a.next_key::<String>()? {
                if !seen.insert(k.clone()) {
                    return Err(A::Error::custom(format!("duplicate JSON key {k:?}")));
                }
                a.next_value_seed(Depth(self.0 + 1))?;
            }
            Ok(())
        }
    }
    let mut d = serde_json::Deserializer::from_slice(raw);
    Depth(0)
        .deserialize(&mut d)
        .map_err(|e| json_diagnostic(raw, &e))?;
    d.end().map_err(|_| "multiple JSON values".to_owned())?;
    serde_json::from_slice(raw).map_err(|e| json_diagnostic(raw, &e))
}
pub(super) fn json_diagnostic(raw: &[u8], e: &serde_json::Error) -> String {
    let msg = e.to_string();
    let msg = msg.split(" at line ").next().unwrap_or(&msg);
    if msg.starts_with("duplicate JSON key ") || msg.starts_with("JSON nesting ") {
        return msg.into();
    }
    if let Some(rest) = msg.strip_prefix("unknown field `") {
        return format!(
            "json: unknown field {:?}",
            rest.split('`').next().unwrap_or("")
        );
    }
    crate::client::json_error(&String::from_utf8_lossy(raw), e, true)
}

pub(super) fn private_replace(path: &str, data: &[u8]) -> Result<(), Failure> {
    use std::os::unix::fs::MetadataExt;
    let expected = match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.is_file() => {
            return Err(format!("refusing to replace non-regular private artifact {path}").into())
        }
        Ok(meta) => Some(meta),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("inspect private artifact {path}: {e}").into()),
    };
    let parent = std::path::Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let tmp = parent.join(format!(
        ".mailctl-private-artifact-{}",
        crate::part_b::new_uuid()?
    ));
    private_new(&tmp.to_string_lossy(), data)?;
    let staged = std::fs::symlink_metadata(&tmp).map_err(|e| e.to_string())?;
    let result = if let Some(expected) = expected {
        exchange(&tmp,std::path::Path::new(path)).and_then(|()| {
            let displaced=std::fs::symlink_metadata(&tmp);
            if displaced.is_ok_and(|m|m.dev()==expected.dev()&&m.ino()==expected.ino()) {
                std::fs::remove_file(&tmp).map_err(|e|Failure::from(format!("remove replaced private artifact: {e}")))
            } else {
                // Keep the displaced target if rollback itself fails: deleting it
                // would destroy another writer's artifact after a namespace race.
                exchange(&tmp,std::path::Path::new(path)).map_err(|e|Failure::from(format!("target identity changed during private artifact replacement; restore intervening target: {e}")))?;
                let _=std::fs::remove_file(&tmp);
                Err("target identity changed during private artifact replacement".into())
            }
        })
    } else {
        std::fs::hard_link(&tmp, path)
            .map_err(|e| Failure::from(format!("publish absent private artifact: {e}")))
            .and_then(|()| std::fs::remove_file(&tmp).map_err(|e| Failure::from(e.to_string())))
    };
    if result.is_err() {
        // Only clean our staging entry while it still names our new content.
        if std::fs::symlink_metadata(&tmp)
            .is_ok_and(|m| m.dev() == staged.dev() && m.ino() == staged.ino())
        {
            let _ = std::fs::remove_file(&tmp);
        }
    }
    result?;
    std::fs::File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(())
}
fn exchange(first: &std::path::Path, second: &std::path::Path) -> Result<(), Failure> {
    use std::os::unix::ffi::OsStrExt;
    let first = std::ffi::CString::new(first.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let second =
        std::ffi::CString::new(second.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    #[cfg(target_os = "linux")]
    // SAFETY: both C strings live through the syscall; it only swaps names.
    let status = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            first.as_ptr(),
            libc::AT_FDCWD,
            second.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    #[cfg(target_os = "macos")]
    // SAFETY: same ownership and lifetime as the Linux call.
    let status = unsafe { libc::renamex_np(first.as_ptr(), second.as_ptr(), libc::RENAME_SWAP) };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let status = -1;
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string().into())
    }
}
