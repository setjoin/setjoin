//! Outbound `EmailSubmission/set` preprocessing (#328, #356 Wave 2b):
//! attachment `multipart/mixed` assembly, fail-closed S/MIME signing, and
//! S/MIME encryption with encrypt-to-self and mandatory domain journaling.
//!
//! Security posture:
//! - Signing & harvested-recipient private/owned keys ALWAYS query by the
//!   authenticated actor (`$actor`), never by the target mailbox owner
//!   (delegated send never confers owner's private keys).
//! - `signSMIME: true` fails closed: missing S3 store, missing/unusable key or
//!   cert, attachment load failure, or S3 put error rejects the creation into
//!   `notCreated` (`smime_no_cert` / `smime_no_matching_cert` / `smime_sign_failed`)
//!   instead of stripping `signSMIME` and sending unsigned.
//! - Draft queries and `size_bytes` updates explicitly filter by the
//!   authorized `mailbox_id`.

use super::reply;
use crate::recovery_worker::{ObjectStore, S3Store};
use serde::de::{MapAccess, Visitor};
use serde_json::value::RawValue;
use serde_json::{json, Value};
use setjoin_jmap::submission::ProcessedSize;
use setjoin_pg::{MailboxAuthContext, ScopedExecutor, Type};
use setjoin_smtp::smime::{
    self, cert_fingerprint_hex, cert_matches_email, cert_validity_unix, encrypt_message, hex_lower,
    is_encryption_capable, is_validly_signed_by, parse_cert_pem, random_boundary, resolve_and_sign,
    write_base64_lines, EncryptAlgorithm, SignCandidate, X509,
};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_SIGN_SIZE: usize = 50 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentPart {
    pub filename: String,
    pub content_type: String,
    pub disposition: String,
    pub content_id: String,
    pub data: Vec<u8>,
}

pub struct ProcessedSubmissions {
    /// Modified `create` JSON object (with `signSMIME`/`encryptSMIME` stripped).
    pub modified_create_json: String,
    /// Optional JSON object `{creationId: processedS3Key}` for `$5`.
    pub processed_refs_json: Option<String>,
    /// Optional JSON object `{creationId: bool}` for `$6`.
    pub is_encrypted_json: Option<String>,
    /// Atomic draft `size_bytes` updates to apply inside `submission::create`.
    pub processed_sizes: Vec<ProcessedSize>,
    /// Gateway-side `notCreated` entries to merge into reducer response.
    pub not_created: BTreeMap<String, Value>,
}

struct OrderedFields(Vec<(String, Box<RawValue>)>);
impl<'de> serde::Deserialize<'de> for OrderedFields {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Obj;
        impl<'de> Visitor<'de> for Obj {
            type Value = OrderedFields;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut fields = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    fields.push(entry);
                }
                Ok(OrderedFields(fields))
            }
        }
        d.deserialize_map(Obj)
    }
}

#[derive(Default)]
struct CreationFlags {
    email_id: String,
    email_id_present: bool,
    email_id_invalid: bool,
    sign_smime: bool,
    encrypt_smime: bool,
    envelope_rcpts: Vec<String>,
}

fn parse_envelope_rcpts(raw_env: &str) -> Vec<String> {
    let Ok(OrderedFields(fields)) = serde_json::from_str::<OrderedFields>(raw_env) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (k, v) in fields {
        if crate::guests_input::fold(&k) == "rcptto" {
            if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(v.get()) {
                for item in items {
                    if let Some(obj) = item.as_object() {
                        for (rk, rv) in obj {
                            if crate::guests_input::fold(rk) == "email" {
                                if let Some(addr) = rv.as_str() {
                                    if !addr.is_empty() {
                                        out.push(addr.to_owned());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

fn parse_creation_flags(raw: &str) -> CreationFlags {
    let mut flags = CreationFlags::default();
    let Ok(OrderedFields(fields)) = serde_json::from_str::<OrderedFields>(raw) else {
        return flags;
    };
    let (mut valid_sign, mut valid_encrypt) = (true, true);
    for (k, v) in fields {
        let vr = v.get();
        match crate::guests_input::fold(&k).as_str() {
            "emailid" => {
                flags.email_id_present = true;
                if vr == "null" {
                    flags.email_id.clear();
                    flags.email_id_invalid = true;
                } else {
                    let bytes = crate::guests_input::go_json_bytes(vr.as_bytes());
                    if let Ok(s) = serde_json::from_slice::<String>(&bytes) {
                        flags.email_id = s;
                        flags.email_id_invalid = false;
                    } else {
                        flags.email_id.clear();
                        flags.email_id_invalid = true;
                    }
                }
            }
            "signsmime" if vr != "null" => match serde_json::from_str::<bool>(vr) {
                Ok(b) => flags.sign_smime = b,
                Err(_) => valid_sign = false,
            },
            "encryptsmime" if vr != "null" => match serde_json::from_str::<bool>(vr) {
                Ok(b) => flags.encrypt_smime = b,
                Err(_) => valid_encrypt = false,
            },
            "envelope" if vr != "null" => {
                flags.envelope_rcpts = parse_envelope_rcpts(vr);
            }
            _ => {}
        }
    }
    if !valid_sign {
        flags.sign_smime = false;
    }
    if !valid_encrypt {
        flags.encrypt_smime = false;
    }
    flags
}

fn normalize_envelope_value(val: Value) -> Value {
    let Value::Object(map) = val else {
        return val;
    };
    let mut out = serde_json::Map::with_capacity(map.len());
    for (k, v) in map {
        let canonical = match crate::guests_input::fold(&k).as_str() {
            "mailfrom" => "mailFrom".to_owned(),
            "rcptto" => "rcptTo".to_owned(),
            _ => k,
        };
        let norm_v = match canonical.as_str() {
            "mailFrom" => normalize_addr_obj(v),
            "rcptTo" => match v {
                Value::Array(arr) => {
                    Value::Array(arr.into_iter().map(normalize_addr_obj).collect())
                }
                other => other,
            },
            _ => v,
        };
        out.insert(canonical, norm_v);
    }
    Value::Object(out)
}

fn normalize_addr_obj(val: Value) -> Value {
    let Value::Object(map) = val else {
        return val;
    };
    let mut out = serde_json::Map::with_capacity(map.len());
    for (k, v) in map {
        let canonical = if crate::guests_input::fold(&k) == "email" {
            "email".to_owned()
        } else {
            k
        };
        out.insert(canonical, v);
    }
    Value::Object(out)
}

fn strip_smime_keys(raw: &str) -> String {
    let Ok(OrderedFields(fields)) = serde_json::from_str::<OrderedFields>(raw) else {
        return raw.to_owned();
    };
    let mut kept = serde_json::Map::with_capacity(fields.len());
    for (k, v) in fields {
        let folded = crate::guests_input::fold(&k);
        if folded == "signsmime" || folded == "encryptsmime" {
            continue;
        }
        let Ok(val) = serde_json::from_str::<Value>(v.get()) else {
            continue;
        };
        let canonical = match folded.as_str() {
            "emailid" => "emailId".to_owned(),
            "identityid" => "identityId".to_owned(),
            "draftsessionid" => "draftSessionId".to_owned(),
            "draftleaseepoch" => "draftLeaseEpoch".to_owned(),
            "draftrevision" => "draftRevision".to_owned(),
            "envelope" => "envelope".to_owned(),
            "sendat" => "sendAt".to_owned(),
            "onsendundowindowseconds" => "onSendUndoWindowSeconds".to_owned(),
            "onsuccessupdateemail" => "onSuccessUpdateEmail".to_owned(),
            _ => k,
        };
        let norm_val = if canonical == "envelope" {
            normalize_envelope_value(val)
        } else {
            val
        };
        kept.insert(canonical, norm_val);
    }
    serde_json::to_string(&Value::Object(kept)).unwrap_or_else(|_| raw.to_owned())
}

fn smime_description(reason: &str) -> &'static str {
    match reason {
        smime::REASON_NO_CERT => {
            "S/MIME signing was requested but you have no usable signing certificate."
        }
        smime::REASON_NO_MATCHING_CERT => {
            "S/MIME signing was requested but none of your certificates matches the From address."
        }
        smime::REASON_SIGN_FAILED => {
            "S/MIME signing was requested but the message could not be signed."
        }
        smime::REASON_ENCRYPT_NO_CERT => {
            "Encryption was requested but no usable certificate is available for one or more recipients."
        }
        smime::REASON_ENCRYPT_NO_SENDER_CERT => {
            "Encryption was requested but you have no usable encryption certificate (needed so you can read your own sent copy)."
        }
        smime::REASON_ENCRYPT_NO_JOURNAL_CERT => {
            "Encryption was requested but no journal certificate is configured, and this domain requires journaling."
        }
        _ => "S/MIME signing failed.",
    }
}

fn smime_not_created(reason: &str, addresses: &[String]) -> Value {
    if addresses.is_empty() {
        json!({
            "type": reason,
            "description": smime_description(reason),
        })
    } else {
        json!({
            "type": reason,
            "description": smime_description(reason),
            "addresses": addresses,
        })
    }
}

/// Reports whether `s` contains any header-breaking octet (C0 control, DEL, or
/// raw non-ASCII byte), matching Go's `containsHeaderBreakingOctets`.
pub fn contains_header_breaking_octets(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b > 0x7e)
}

fn format_content_disposition(disposition: &str, filename: &str) -> String {
    let disp = if disposition.eq_ignore_ascii_case("inline") {
        "inline"
    } else {
        "attachment"
    };
    if filename.is_empty() {
        return disp.to_owned();
    }
    if !contains_header_breaking_octets(filename) {
        let escaped = filename.replace('\\', "\\\\").replace('"', "\\\"");
        return format!("{disp}; filename=\"{escaped}\"");
    }
    // Percent-encode RFC 5987 ext-value for non-ASCII / control filenames so no
    // raw control byte or CRLF can ever enter a MIME header.
    let mut encoded = String::with_capacity(filename.len() * 3);
    for b in filename.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            encoded.push(b as char);
        } else if b >= 0x20 && b != 0x7f || b >= 0x80 {
            encoded.push('%');
            encoded.push_str(&hex_lower(&[b]).to_ascii_uppercase());
        }
    }
    format!("{disp}; filename*=utf-8''{encoded}")
}

fn split_headers_body(raw: &[u8]) -> Option<(&[u8], &[u8])> {
    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((&raw[..pos], &raw[pos + 4..]));
    }
    if let Some(pos) = raw.windows(2).position(|w| w == b"\n\n") {
        return Some((&raw[..pos], &raw[pos + 2..]));
    }
    None
}

fn unfold_header_lines(headers: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur: Option<Vec<u8>> = None;
    for raw_line in headers.split(|b| *b == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        if matches!(line.first(), Some(b' ' | b'\t')) {
            if let Some(buf) = cur.as_mut() {
                buf.extend_from_slice(b"\r\n");
                buf.extend_from_slice(line);
            }
        } else {
            if let Some(prev) = cur.take() {
                out.push(prev);
            }
            cur = Some(line.to_vec());
        }
    }
    if let Some(last) = cur {
        out.push(last);
    }
    out
}

/// Assembles a body-only RFC 5322 draft and its attachment parts into a
/// `multipart/mixed` wire message (`top + "MIME-Version: 1.0\r\n" + entity`).
pub fn assemble_mixed_mime(raw_draft: &[u8], parts: &[AttachmentPart]) -> Result<Vec<u8>, String> {
    let (headers_bytes, body_bytes) = split_headers_body(raw_draft)
        .ok_or_else(|| "draft missing header/body separator".to_owned())?;

    let mut top_headers = Vec::new();
    let mut body_ct: Option<String> = None;
    let mut body_cte: Option<String> = None;

    for hdr in unfold_header_lines(headers_bytes) {
        let Some(colon) = hdr.iter().position(|b| *b == b':') else {
            continue;
        };
        let name = hdr[..colon].trim_ascii();
        let val = String::from_utf8_lossy(hdr[colon + 1..].trim_ascii()).into_owned();
        if name.eq_ignore_ascii_case(b"Content-Type") {
            if body_ct.is_none() {
                body_ct = Some(val);
            }
        } else if name.eq_ignore_ascii_case(b"Content-Transfer-Encoding") {
            if body_cte.is_none() {
                body_cte = Some(val);
            }
        } else if name.eq_ignore_ascii_case(b"MIME-Version") {
            continue;
        } else {
            top_headers.push(hdr);
        }
    }

    let body_ct = match body_ct {
        Some(ct) if !ct.is_empty() && !contains_header_breaking_octets(&ct) => ct,
        _ => "text/plain; charset=utf-8".to_owned(),
    };
    let boundary = random_boundary("mixed")?;

    let mut out = Vec::with_capacity(raw_draft.len() + parts.len() * 1024 + 512);
    for hdr in top_headers {
        out.extend_from_slice(&hdr);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"MIME-Version: 1.0\r\n");
    out.extend_from_slice(
        format!("Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n").as_bytes(),
    );

    // Part 0: original message body.
    out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    out.extend_from_slice(format!("Content-Type: {body_ct}\r\n").as_bytes());
    if let Some(cte) = body_cte.filter(|s| !s.is_empty() && !contains_header_breaking_octets(s)) {
        out.extend_from_slice(format!("Content-Transfer-Encoding: {cte}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body_bytes);
    if !body_bytes.ends_with(b"\r\n") && !body_bytes.ends_with(b"\n") {
        out.extend_from_slice(b"\r\n");
    }

    // Parts 1..N: attachment parts with emission-time header validation.
    for part in parts {
        let ct = if part.content_type.is_empty()
            || contains_header_breaking_octets(&part.content_type)
        {
            "application/octet-stream"
        } else {
            part.content_type.as_str()
        };
        let cd = format_content_disposition(&part.disposition, &part.filename);
        out.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
        out.extend_from_slice(format!("Content-Type: {ct}\r\n").as_bytes());
        out.extend_from_slice(b"Content-Transfer-Encoding: base64\r\n");
        out.extend_from_slice(format!("Content-Disposition: {cd}\r\n").as_bytes());
        if !part.content_id.is_empty() && !contains_header_breaking_octets(&part.content_id) {
            out.extend_from_slice(format!("Content-ID: <{}>\r\n", part.content_id).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        write_base64_lines(&mut out, &part.data);
    }
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(out)
}

async fn raw_from_ref(store: Option<&S3Store>, raw_ref: &str) -> Result<Vec<u8>, String> {
    if raw_ref.contains('\n') || raw_ref.contains('\r') {
        return Ok(raw_ref.as_bytes().to_vec());
    }
    let store = store.ok_or_else(|| "object store not configured".to_owned())?;
    store.read(raw_ref, MAX_SIGN_SIZE).await
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_lower(digest.as_slice())
}

struct DraftRow {
    from_addr: String,
    raw_ref: String,
    received_at: SystemTime,
    has_attachments: bool,
}

async fn load_draft(
    worker: &ScopedExecutor,
    auth: &MailboxAuthContext,
    email_id: i64,
) -> Result<Option<DraftRow>, String> {
    let mailbox_id = auth.mailbox().get();
    let rows = crate::policy_composition::worker_mailbox_read(
        worker,
        auth,
        "SELECT COALESCE(from_addr, ''), COALESCE(raw_ref, ''), received_at, COALESCE(has_attachments, FALSE) \
         FROM messages WHERE id = $1 AND mailbox_id = $2",
        &[(&email_id, Type::INT8), (&mailbox_id, Type::INT8)],
    )
    .await
    .map_err(|e| e.message)?;
    Ok(rows.first().map(|r| DraftRow {
        from_addr: r.get(0),
        raw_ref: r.get(1),
        received_at: r.get(2),
        has_attachments: r.get(3),
    }))
}

async fn load_attachment_parts(
    worker: &ScopedExecutor,
    store: Option<&S3Store>,
    auth: &MailboxAuthContext,
    email_id: i64,
    received_at: SystemTime,
) -> Result<Vec<AttachmentPart>, String> {
    let mailbox_id = auth.mailbox().get();
    // Join through messages with mailbox_id = $3 so attachment metadata stays
    // scoped to the authorized mailbox.
    let rows = crate::policy_composition::worker_mailbox_read(
        worker,
        auth,
        "SELECT ma.blob_sha256, \
                COALESCE(ma.filename, 'attachment'), \
                COALESCE(ma.content_type, 'application/octet-stream'), \
                COALESCE(ma.disposition, 'attachment'), \
                COALESCE(ma.content_id, '') \
         FROM message_attachments ma \
         JOIN messages m ON m.id = ma.message_id AND m.received_at = ma.received_at \
         WHERE ma.message_id = $1 AND ma.received_at = $2 AND m.mailbox_id = $3 \
         ORDER BY ma.id",
        &[
            (&email_id, Type::INT8),
            (&received_at, Type::TIMESTAMPTZ),
            (&mailbox_id, Type::INT8),
        ],
    )
    .await
    .map_err(|e| e.message)?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let store = store.ok_or_else(|| "object store not configured".to_owned())?;
    let mut parts = Vec::with_capacity(rows.len());
    for row in rows {
        let blob_sha: String = row.get(0);
        let data = store.read(&blob_sha, MAX_SIGN_SIZE).await?;
        parts.push(AttachmentPart {
            filename: row.get(1),
            content_type: row.get(2),
            disposition: row.get(3),
            content_id: row.get(4),
            data,
        });
    }
    Ok(parts)
}

async fn load_sign_candidates(
    worker: &ScopedExecutor,
    auth: &MailboxAuthContext,
) -> Result<Vec<SignCandidate>, String> {
    let actor_user_id = auth.actor().get();
    let rows = crate::policy_composition::worker_mailbox_read(
        worker,
        auth,
        "SELECT cert_pem, \
                pgp_sym_decrypt(private_key_enc::bytea, current_setting('app.encryption_key')), \
                is_default \
         FROM user_smime_certs \
         WHERE user_id = $1 AND private_key_enc IS NOT NULL \
           AND (expires_at IS NULL OR expires_at > now()) \
         ORDER BY is_default DESC, created_at DESC",
        &[(&actor_user_id, Type::INT8)],
    )
    .await
    .map_err(|e| e.message)?;
    Ok(rows
        .into_iter()
        .map(|r| SignCandidate {
            cert_pem: r.get(0),
            key_pem: r.get(1),
            is_default: r.get(2),
        })
        .collect())
}

fn canonicalize_addr(raw: &str) -> String {
    let s = raw.trim();
    let addr = if let (Some(l), Some(r)) = (s.rfind('<'), s.rfind('>')) {
        if r > l + 1 {
            &s[l + 1..r]
        } else {
            s
        }
    } else {
        s
    };
    addr.trim().to_ascii_lowercase()
}

async fn canon_recipient_email(
    worker: &ScopedExecutor,
    auth: &MailboxAuthContext,
    raw: &str,
) -> String {
    let c = canonicalize_addr(raw);
    if c.is_empty() {
        return c;
    }
    let rows = crate::policy_composition::worker_mailbox_read(
        worker,
        auth,
        "SELECT a2.email \
         FROM aliases a1 \
         JOIN aliases a2 ON a2.mailbox_id = a1.mailbox_id AND a2.is_primary = TRUE \
         WHERE a1.email = $1 \
         LIMIT 1",
        &[(&c, Type::TEXT)],
    )
    .await;
    if let Ok(rows) = rows {
        if let Some(row) = rows.first() {
            let primary: String = row.get(0);
            let cp = canonicalize_addr(&primary);
            if !cp.is_empty() {
                return cp;
            }
        }
    }
    c
}

async fn is_cert_revoked(
    worker: &ScopedExecutor,
    auth: &MailboxAuthContext,
    fingerprint: &str,
) -> bool {
    let rows = crate::policy_composition::worker_mailbox_read(
        worker,
        auth,
        "SELECT EXISTS(SELECT 1 FROM smime_revocation_blocklist WHERE fingerprint = $1) \
             OR EXISTS(SELECT 1 FROM smime_cert_revocations WHERE fingerprint = $1)",
        &[(&fingerprint, Type::TEXT)],
    )
    .await;
    match rows {
        Ok(r) => r.first().is_some_and(|row| row.get::<_, bool>(0)),
        // Fail-closed if revocation check errors.
        Err(_) => true,
    }
}

async fn resolve_encrypt_cert(
    worker: &ScopedExecutor,
    auth: &MailboxAuthContext,
    raw_email: &str,
) -> Option<X509> {
    let email = canon_recipient_email(worker, auth, raw_email).await;
    if email.is_empty() {
        return None;
    }
    let actor_user_id = auth.actor().get();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut pems: Vec<String> = Vec::new();
    // 1. Internal org directory certs (`user_smime_certs`).
    if let Ok(rows) = crate::policy_composition::worker_mailbox_read(
        worker,
        auth,
        "SELECT sc.cert_pem \
         FROM user_smime_certs sc \
         JOIN users u ON u.id = sc.user_id \
         WHERE lower(u.email) = $1 \
         ORDER BY sc.is_default DESC, sc.created_at DESC",
        &[(&email, Type::TEXT)],
    )
    .await
    {
        for r in rows {
            if let Ok(pem) = r.try_get::<_, String>(0) {
                pems.push(pem);
            }
        }
    }
    // 2. Actor's harvested/uploaded `recipient_smime_certs`.
    if let Ok(rows) = crate::policy_composition::worker_mailbox_read(
        worker,
        auth,
        "SELECT cert_pem \
         FROM recipient_smime_certs \
         WHERE owner_user_id = $1 AND email = $2 \
         ORDER BY last_seen DESC",
        &[(&actor_user_id, Type::INT8), (&email, Type::TEXT)],
    )
    .await
    {
        for r in rows {
            if let Ok(pem) = r.try_get::<_, String>(0) {
                pems.push(pem);
            }
        }
    }

    for pem in pems {
        let Ok(cert) = parse_cert_pem(&pem) else {
            continue;
        };
        if !is_encryption_capable(&cert) {
            continue;
        }
        let Ok((nb, na)) = cert_validity_unix(&cert) else {
            continue;
        };
        if now < nb || now > na {
            continue;
        }
        if !cert_matches_email(&cert, &email) {
            continue;
        }
        let Ok(fp) = cert_fingerprint_hex(&cert) else {
            continue;
        };
        if is_cert_revoked(worker, auth, &fp).await {
            continue;
        }
        return Some(cert);
    }
    None
}

fn extract_json_emails(val: &Value) -> Vec<String> {
    let Some(arr) = val.as_array() else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|v| v.get("email").and_then(Value::as_str))
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

struct SenderInfo {
    from_addr: String,
    domain_id: i64,
    recipients: Vec<String>,
}

async fn load_sender_info(
    worker: &ScopedExecutor,
    auth: &MailboxAuthContext,
    email_id: i64,
) -> Result<Option<SenderInfo>, String> {
    let mailbox_id = auth.mailbox().get();
    let rows = crate::policy_composition::worker_mailbox_read(
        worker,
        auth,
        "SELECT COALESCE(m.from_addr, ''), mb.domain_id, \
                COALESCE(m.to_addrs, '[]'::jsonb)::text, \
                COALESCE(m.cc_addrs, '[]'::jsonb)::text, \
                COALESCE(m.bcc_addrs, '[]'::jsonb)::text \
         FROM messages m \
         JOIN mailboxes mb ON mb.id = m.mailbox_id \
         WHERE m.id = $1 AND m.mailbox_id = $2",
        &[(&email_id, Type::INT8), (&mailbox_id, Type::INT8)],
    )
    .await
    .map_err(|e| e.message)?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let from_addr: String = row.get(0);
    let domain_id: i64 = row.get(1);
    let mut recipients = Vec::new();
    for col in [2usize, 3, 4] {
        let raw: String = row.get(col);
        if let Ok(v) = serde_json::from_str::<Value>(&raw) {
            recipients.extend(extract_json_emails(&v));
        }
    }
    Ok(Some(SenderInfo {
        from_addr,
        domain_id,
        recipients,
    }))
}

async fn load_domain_journal_cert(
    worker: &ScopedExecutor,
    auth: &MailboxAuthContext,
    domain_id: i64,
) -> Result<Option<X509>, &'static str> {
    let req_rows = crate::policy_composition::worker_mailbox_read(
        worker,
        auth,
        "SELECT journaling_required_for_domain($1)",
        &[(&domain_id, Type::INT8)],
    )
    .await
    .map_err(|_| smime::REASON_ENCRYPT_NO_JOURNAL_CERT)?;
    let required = req_rows
        .first()
        .is_some_and(|r| r.try_get::<_, bool>(0).unwrap_or(false));
    if !required {
        return Ok(None);
    }
    let cert_rows = crate::policy_composition::worker_mailbox_read(
        worker,
        auth,
        "SELECT COALESCE(journal_cert_pem_for_domain($1), '')",
        &[(&domain_id, Type::INT8)],
    )
    .await
    .map_err(|_| smime::REASON_ENCRYPT_NO_JOURNAL_CERT)?;
    let pem: String = cert_rows
        .first()
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .unwrap_or_default();
    if pem.is_empty() {
        return Err(smime::REASON_ENCRYPT_NO_JOURNAL_CERT);
    }
    let cert = parse_cert_pem(&pem).map_err(|_| smime::REASON_ENCRYPT_NO_JOURNAL_CERT)?;
    if !is_encryption_capable(&cert) {
        return Err(smime::REASON_ENCRYPT_NO_JOURNAL_CERT);
    }
    let fp = cert_fingerprint_hex(&cert).map_err(|_| smime::REASON_ENCRYPT_NO_JOURNAL_CERT)?;
    if is_cert_revoked(worker, auth, &fp).await {
        return Err(smime::REASON_ENCRYPT_NO_JOURNAL_CERT);
    }
    Ok(Some(cert))
}

fn build_encrypt_cert_set(recipients: Vec<X509>, sender: X509, journal: Option<X509>) -> Vec<X509> {
    let mut out = Vec::with_capacity(recipients.len() + 2);
    let mut seen = HashSet::new();
    for cert in recipients
        .into_iter()
        .chain(std::iter::once(sender))
        .chain(journal)
    {
        if let Ok(fp) = cert_fingerprint_hex(&cert) {
            if seen.insert(fp) {
                out.push(cert);
            }
        }
    }
    out
}

async fn assemble_draft_wire(
    worker: &ScopedExecutor,
    store: &S3Store,
    auth: &MailboxAuthContext,
    email_id: i64,
    draft: &DraftRow,
) -> Result<(Vec<u8>, bool), String> {
    let raw = raw_from_ref(Some(store), &draft.raw_ref).await?;
    if raw.len() > MAX_SIGN_SIZE {
        return Err("draft exceeds maximum size".into());
    }
    if draft.has_attachments {
        let parts =
            load_attachment_parts(worker, Some(store), auth, email_id, draft.received_at).await?;
        if !parts.is_empty() {
            let wire = assemble_mixed_mime(&raw, &parts)?;
            return Ok((wire, true));
        }
    }
    Ok((raw, false))
}

async fn sign_one(
    worker: &ScopedExecutor,
    store: Option<&S3Store>,
    auth: &MailboxAuthContext,
    email_id: i64,
) -> Result<Option<(String, i64)>, &'static str> {
    let Some(store) = store else {
        return Err(smime::REASON_SIGN_FAILED);
    };
    let draft = match load_draft(worker, auth, email_id).await {
        Ok(Some(d)) => d,
        Ok(None) => return Ok(None), // Let reducer emit notFound.
        Err(_) => return Err(smime::REASON_SIGN_FAILED),
    };
    let candidates = load_sign_candidates(worker, auth)
        .await
        .map_err(|_| smime::REASON_SIGN_FAILED)?;
    if candidates.is_empty() {
        return Err(smime::REASON_NO_CERT);
    }
    let (content, had_attachments) = assemble_draft_wire(worker, store, auth, email_id, &draft)
        .await
        .map_err(|_| smime::REASON_SIGN_FAILED)?;
    if !had_attachments && is_validly_signed_by(&candidates, &draft.from_addr, &content)? {
        return Ok(None);
    }
    let signed = resolve_and_sign(&candidates, &draft.from_addr, &content)?;
    let size = signed.len() as i64;
    let key = sha256_hex(&signed);
    worker
        .protocol_statement(
            "SELECT public.blob_gc_reactivate($1)",
            &[(&key, setjoin_pg::Type::TEXT)],
        )
        .await
        .map_err(|_| smime::REASON_SIGN_FAILED)?;
    store
        .put(&key, &signed, "message/rfc822")
        .await
        .map_err(|_| smime::REASON_SIGN_FAILED)?;
    Ok(Some((key, size)))
}

#[allow(clippy::too_many_arguments)]
async fn encrypt_one(
    worker: &ScopedExecutor,
    store: Option<&S3Store>,
    algorithm: EncryptAlgorithm,
    auth: &MailboxAuthContext,
    email_id: i64,
    sign_requested: bool,
    envelope_rcpts: &[String],
) -> Result<Option<(String, i64)>, (&'static str, Vec<String>)> {
    let Some(store) = store else {
        return Err((smime::REASON_ENCRYPT_NO_CERT, Vec::new()));
    };
    let info = match load_sender_info(worker, auth, email_id).await {
        Ok(Some(i)) => i,
        Ok(None) => return Ok(None), // Let reducer emit notFound.
        Err(_) => return Err((smime::REASON_ENCRYPT_NO_CERT, Vec::new())),
    };

    // Match mail_encrypt.go:295-323: resolve sender cert BEFORE recipients,
    // and prefer explicit non-empty envelope.rcptTo over draft to/cc/bcc headers.
    let sender_cert = resolve_encrypt_cert(worker, auth, &info.from_addr)
        .await
        .ok_or((smime::REASON_ENCRYPT_NO_SENDER_CERT, Vec::new()))?;

    let delivery_rcpts = if envelope_rcpts.is_empty() {
        info.recipients.as_slice()
    } else {
        envelope_rcpts
    };
    let mut seen_rcpt = HashSet::new();
    let mut rcpt_certs = Vec::new();
    let mut missing = Vec::new();
    for raw_addr in delivery_rcpts {
        let canon = canonicalize_addr(raw_addr);
        if canon.is_empty() || !seen_rcpt.insert(canon.clone()) {
            continue;
        }
        match resolve_encrypt_cert(worker, auth, raw_addr).await {
            Some(cert) => rcpt_certs.push(cert),
            None => missing.push(canon),
        }
    }
    if seen_rcpt.is_empty() || !missing.is_empty() {
        return Err((smime::REASON_ENCRYPT_NO_CERT, missing));
    }

    let journal_cert = load_domain_journal_cert(worker, auth, info.domain_id)
        .await
        .map_err(|r| (r, Vec::new()))?;
    let cert_set = build_encrypt_cert_set(rcpt_certs, sender_cert, journal_cert);

    let draft = match load_draft(worker, auth, email_id).await {
        Ok(Some(d)) => d,
        Ok(None) => return Ok(None),
        Err(_) => return Err((smime::REASON_ENCRYPT_NO_CERT, Vec::new())),
    };
    let (mut content, _) = assemble_draft_wire(worker, store, auth, email_id, &draft)
        .await
        .map_err(|_| (smime::REASON_ENCRYPT_NO_CERT, Vec::new()))?;

    if sign_requested {
        let candidates = load_sign_candidates(worker, auth)
            .await
            .map_err(|_| (smime::REASON_SIGN_FAILED, Vec::new()))?;
        content = resolve_and_sign(&candidates, &draft.from_addr, &content)
            .map_err(|r| (r, Vec::new()))?;
    }

    let encrypted = encrypt_message(&content, &cert_set, algorithm)
        .map_err(|_| (smime::REASON_ENCRYPT_NO_CERT, Vec::new()))?;
    let size = encrypted.len() as i64;
    let key = sha256_hex(&encrypted);
    worker
        .protocol_statement(
            "SELECT public.blob_gc_reactivate($1)",
            &[(&key, setjoin_pg::Type::TEXT)],
        )
        .await
        .map_err(|_| (smime::REASON_ENCRYPT_NO_CERT, Vec::new()))?;
    store
        .put(&key, &encrypted, "message/rfc822")
        .await
        .map_err(|_| (smime::REASON_ENCRYPT_NO_CERT, Vec::new()))?;

    Ok(Some((key, size)))
}

async fn assemble_plain_attachment(
    worker: &ScopedExecutor,
    store: Option<&S3Store>,
    auth: &MailboxAuthContext,
    email_id: i64,
) -> Result<Option<(String, i64)>, String> {
    let draft = match load_draft(worker, auth, email_id).await? {
        Some(d) => d,
        None => return Ok(None),
    };
    if !draft.has_attachments {
        return Ok(None);
    }
    let parts = load_attachment_parts(worker, store, auth, email_id, draft.received_at).await?;
    if parts.is_empty() {
        return Ok(None);
    }
    let store = store.ok_or_else(|| "object store not configured".to_owned())?;
    let raw = raw_from_ref(Some(store), &draft.raw_ref).await?;
    if raw.len() > MAX_SIGN_SIZE {
        return Err("draft exceeds maximum size".into());
    }
    let wire = assemble_mixed_mime(&raw, &parts)?;
    let size = wire.len() as i64;
    let key = sha256_hex(&wire);
    worker
        .protocol_statement(
            "SELECT public.blob_gc_reactivate($1)",
            &[(&key, setjoin_pg::Type::TEXT)],
        )
        .await
        .map_err(|e| format!("blob gc reactivate failed: {}", e.message))?;
    store.put(&key, &wire, "message/rfc822").await?;
    Ok(Some((key, size)))
}

/// Preprocesses `EmailSubmission/set` creations: assembles attachments and
/// performs fail-closed S/MIME signing & encryption prior to calling
/// `jmap_email_submission_set`.
pub async fn process_submissions(
    worker: &ScopedExecutor,
    store: Option<&S3Store>,
    algorithm: EncryptAlgorithm,
    auth: &MailboxAuthContext,
    create_json: &str,
) -> ProcessedSubmissions {
    let Ok(map) = serde_json::from_str::<BTreeMap<String, Box<RawValue>>>(create_json) else {
        return ProcessedSubmissions {
            modified_create_json: create_json.to_owned(),
            processed_refs_json: None,
            is_encrypted_json: None,
            processed_sizes: Vec::new(),
            not_created: BTreeMap::new(),
        };
    };

    let mut modified: BTreeMap<String, Box<RawValue>> = BTreeMap::new();
    let mut processed_refs: BTreeMap<String, String> = BTreeMap::new();
    let mut is_encrypted: BTreeMap<String, bool> = BTreeMap::new();
    let mut processed_sizes: Vec<ProcessedSize> = Vec::new();
    let mut not_created: BTreeMap<String, Value> = BTreeMap::new();

    for (cid, raw_val) in map {
        let raw = raw_val.get();
        let flags = parse_creation_flags(raw);
        let stripped = strip_smime_keys(raw);
        let stripped_box = RawValue::from_string(stripped).unwrap_or_else(|_| raw_val.clone());

        let email_id_opt = if flags.email_id.is_empty() || flags.email_id_invalid {
            None
        } else {
            flags.email_id.parse::<i64>().ok()
        };

        if flags.encrypt_smime {
            let Some(email_id) = email_id_opt else {
                if flags.email_id_present {
                    not_created.insert(cid, smime_not_created(smime::REASON_ENCRYPT_NO_CERT, &[]));
                    continue;
                }
                modified.insert(cid, stripped_box);
                continue;
            };
            match encrypt_one(
                worker,
                store,
                algorithm,
                auth,
                email_id,
                flags.sign_smime,
                &flags.envelope_rcpts,
            )
            .await
            {
                Ok(Some((key, size_bytes))) => {
                    processed_refs.insert(cid.clone(), key);
                    is_encrypted.insert(cid.clone(), true);
                    processed_sizes.push(ProcessedSize {
                        creation_id: cid.clone(),
                        email_id,
                        size_bytes,
                    });
                    modified.insert(cid, stripped_box);
                }
                Ok(None) => {
                    modified.insert(cid, stripped_box);
                }
                Err((reason, addrs)) => {
                    not_created.insert(cid, smime_not_created(reason, &addrs));
                }
            }
            continue;
        }

        if flags.sign_smime {
            let Some(email_id) = email_id_opt else {
                if flags.email_id_present {
                    not_created.insert(cid, smime_not_created(smime::REASON_SIGN_FAILED, &[]));
                    continue;
                }
                modified.insert(cid, stripped_box);
                continue;
            };
            match sign_one(worker, store, auth, email_id).await {
                Ok(Some((key, size_bytes))) => {
                    processed_refs.insert(cid.clone(), key);
                    processed_sizes.push(ProcessedSize {
                        creation_id: cid.clone(),
                        email_id,
                        size_bytes,
                    });
                    modified.insert(cid, stripped_box);
                }
                Ok(None) => {
                    modified.insert(cid, stripped_box);
                }
                Err(reason) => {
                    not_created.insert(cid, smime_not_created(reason, &[]));
                }
            }
            continue;
        }

        if let Some(email_id) = email_id_opt {
            match assemble_plain_attachment(worker, store, auth, email_id).await {
                Ok(Some((key, size_bytes))) => {
                    processed_refs.insert(cid.clone(), key);
                    processed_sizes.push(ProcessedSize {
                        creation_id: cid.clone(),
                        email_id,
                        size_bytes,
                    });
                    modified.insert(cid, stripped_box);
                }
                Ok(None) => {
                    modified.insert(cid, stripped_box);
                }
                Err(_) => {
                    not_created.insert(
                        cid,
                        json!({
                            "type": "serverFail",
                            "description": "failed to assemble attachments",
                        }),
                    );
                }
            }
            continue;
        }

        modified.insert(cid, stripped_box);
    }

    let modified_create_json = reply::marshal_sorted(&modified).unwrap_or_else(|| "{}".to_owned());
    let processed_refs_json = (!processed_refs.is_empty())
        .then(|| serde_json::to_string(&processed_refs).unwrap_or_default());
    let is_encrypted_json = (!is_encrypted.is_empty())
        .then(|| serde_json::to_string(&is_encrypted).unwrap_or_default());

    ProcessedSubmissions {
        modified_create_json,
        processed_refs_json,
        is_encrypted_json,
        processed_sizes,
        not_created,
    }
}

/// Merges gateway-side `notCreated` entries into the reducer's `EmailSubmission/set`
/// JSON response, preserving any existing reducer `notCreated` entries.
pub fn merge_not_created(
    result_json: &str,
    gateway_not_created: &BTreeMap<String, Value>,
) -> String {
    if gateway_not_created.is_empty() {
        return result_json.to_owned();
    }
    let Ok(mut resp) = serde_json::from_str::<BTreeMap<String, Box<RawValue>>>(result_json) else {
        return result_json.to_owned();
    };
    let mut existing: BTreeMap<String, Value> = resp
        .get("notCreated")
        .and_then(|r| serde_json::from_str(r.get()).ok())
        .unwrap_or_default();
    for (k, v) in gateway_not_created {
        existing.insert(k.clone(), v.clone());
    }
    let Ok(merged_str) = serde_json::to_string(&existing) else {
        return result_json.to_owned();
    };
    let Ok(merged_raw) = RawValue::from_string(merged_str) else {
        return result_json.to_owned();
    };
    resp.insert("notCreated".into(), merged_raw);
    reply::marshal_sorted(&resp).unwrap_or_else(|| result_json.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_smime_keys_handles_ascii_and_unicode_folded_keys() {
        let out = strip_smime_keys(r#"{"emailId":"42","signSMIME":true,"encryptſMIME":true}"#);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["emailId"], "42");
        assert!(v.get("signSMIME").is_none());
        assert!(v.get("encryptſMIME").is_none());
    }

    #[test]
    fn parse_creation_flags_matches_unicode_fold() {
        let f = parse_creation_flags(r#"{"emailId":"42","encryptſMIME":true,"signSMIME":null}"#);
        assert_eq!(f.email_id, "42");
        assert!(f.encrypt_smime);
        assert!(!f.sign_smime);
    }

    #[test]
    fn assemble_mixed_mime_neutralizes_header_breaking_octets() {
        let draft = b"From: alice@test.local\r\nTo: bob@test.local\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nhello\r\n";
        let parts = vec![AttachmentPart {
            filename: "report\r\nX-Injected: yes.pdf".into(),
            content_type: "application/pdf\r\nBcc: victim@example.com".into(),
            disposition: "attachment".into(),
            content_id: "cid1\r\nX-Injected: yes".into(),
            data: b"PDF-BYTES".to_vec(),
        }];
        let wire = assemble_mixed_mime(draft, &parts).unwrap();
        let text = String::from_utf8(wire).unwrap();
        assert!(!text.contains("Bcc:"));
        assert!(!text.contains("X-Injected:"));
        assert!(!text.contains("Content-ID:"));
        assert!(text.contains("Content-Type: application/octet-stream\r\n"));
        assert!(text.contains("UERG\n") || text.contains("UERGLUJZVEVT"));
    }

    #[test]
    fn merge_not_created_preserves_existing_entries() {
        let res = r#"{"created":{},"notCreated":{"r1":{"type":"notFound","description":"x"}}}"#;
        let mut extra = BTreeMap::new();
        extra.insert("k2".into(), smime_not_created(smime::REASON_NO_CERT, &[]));
        let out = merge_not_created(res, &extra);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["notCreated"]["r1"]["type"], "notFound");
        assert_eq!(v["notCreated"]["k2"]["type"], "smime_no_cert");
    }
}
