use super::{
    account, batch, family, gates,
    http::{envelope, problem},
    reply,
    token::KeySource,
    ws_request, JmapCommands,
};
use crate::{recovery_worker::ObjectStore, Body, RequestContext};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response};
use serde::{Deserialize, Serialize};
use setjoin_contracts::ids::{ActorId, Generation, MailboxId};
use setjoin_pg::{CommandOutcome, MailboxAuthContext, Rejection};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const MAX_RECOVERY_BYTES: u64 = 50 << 20;
const MAX_RECOVERY_RECEIPT_IDS: usize = 64;

#[derive(Default)]
struct RecoveryReceiptArgs {
    account_id: String,
    ids: Vec<String>,
}

/// Mirror Go's `decodeStrictJSON` for `recoveryReceiptArgs`:
/// case-folded `accountId` and `ids` only, rejecting unknown fields and
/// trailing tokens (`null` decodes to empty args).
fn decode_recovery_receipt_args(raw: &str) -> Result<RecoveryReceiptArgs, ()> {
    use serde::de::{self, MapAccess, Visitor};
    use serde::Deserializer;

    struct ArgsVisitor;
    impl<'de> Visitor<'de> for ArgsVisitor {
        type Value = RecoveryReceiptArgs;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("recovery receipt request object")
        }
        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(RecoveryReceiptArgs::default())
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut out = RecoveryReceiptArgs::default();
            while let Some(key) = map.next_key::<String>()? {
                match crate::guests_input::fold(&key).as_str() {
                    "accountid" => {
                        if let Some(v) = map.next_value::<Option<String>>()? {
                            out.account_id = v;
                        }
                    }
                    "ids" => {
                        out.ids = map
                            .next_value::<Option<Vec<Option<String>>>>()?
                            .unwrap_or_default()
                            .into_iter()
                            .map(Option::unwrap_or_default)
                            .collect();
                    }
                    _ => return Err(de::Error::custom("unknown field")),
                }
            }
            Ok(out)
        }
    }
    let mut de = serde_json::Deserializer::from_str(raw);
    let args = de.deserialize_any(ArgsVisitor).map_err(|_| ())?;
    de.end().map_err(|_| ())?;
    Ok(args)
}

#[derive(Deserialize)]
struct ContextMeta {
    #[serde(rename = "installationId")]
    installation_id: String,
    #[serde(rename = "timelineGeneration")]
    timeline_generation: String,
    #[serde(rename = "stateWatermark")]
    state_watermark: String,
}

#[derive(Deserialize, Serialize, Clone)]
struct AttachmentRow {
    #[serde(rename = "blobId")]
    blob_id: String,
    sha256: String,
    size: String,
    role: String,
}

#[derive(Deserialize)]
struct ContextRow {
    id: String,
    #[serde(rename = "rawRef")]
    raw_ref: String,
    #[serde(rename = "receivedAt")]
    received_at: String,
    eligibility: String,
    #[serde(default)]
    attachments: Vec<AttachmentRow>,
}

#[derive(Deserialize)]
struct ContextResult {
    context: ContextMeta,
    #[serde(default)]
    list: Vec<ContextRow>,
}

/// Wire order matches `shared/continuity/receipt.go` `BlobDigest`.
#[derive(Serialize, Clone)]
struct BlobDigest {
    #[serde(rename = "blobId")]
    blob_id: String,
    sha256: String,
    size: String,
}

/// Wire order matches `shared/continuity/receipt.go` `ReceiptClaims` (`canonicalReceipt`).
#[derive(Serialize)]
struct ReceiptClaims {
    v: i32,
    #[serde(rename = "installationId")]
    installation_id: String,
    #[serde(rename = "accountId")]
    account_id: String,
    #[serde(rename = "originalMessageId")]
    original_message_id: String,
    eligibility: String,
    #[serde(rename = "rawMimeSha256")]
    raw_mime_sha256: String,
    #[serde(rename = "rawMimeSize")]
    raw_mime_size: String,
    blobs: Vec<BlobDigest>,
    #[serde(rename = "timelineGeneration")]
    timeline_generation: String,
    #[serde(rename = "stateWatermark")]
    state_watermark: String,
    #[serde(rename = "bootEpoch")]
    boot_epoch: String,
    #[serde(rename = "issuedAt")]
    issued_at: String,
    #[serde(rename = "keyId")]
    key_id: String,
}

#[derive(Serialize)]
struct CanonicalReceiptClaims<'a> {
    v: i32,
    #[serde(rename = "installationId")]
    installation_id: &'a str,
    #[serde(rename = "accountId")]
    account_id: &'a str,
    #[serde(rename = "originalMessageId")]
    original_message_id: &'a str,
    eligibility: &'a str,
    #[serde(rename = "rawMimeSha256")]
    raw_mime_sha256: &'a str,
    #[serde(rename = "rawMimeSize")]
    raw_mime_size: &'a str,
    blobs: Option<Vec<BlobDigest>>,
    #[serde(rename = "timelineGeneration")]
    timeline_generation: &'a str,
    #[serde(rename = "stateWatermark")]
    state_watermark: &'a str,
    #[serde(rename = "bootEpoch")]
    boot_epoch: &'a str,
    #[serde(rename = "issuedAt")]
    issued_at: &'a str,
    #[serde(rename = "keyId")]
    key_id: &'a str,
}

fn canonical_claims(claims: &ReceiptClaims) -> CanonicalReceiptClaims<'_> {
    // Go's canonicalReceipt copies into a nil slice (`null` when empty) and sorts by blobId.
    let blobs = if claims.blobs.is_empty() {
        None
    } else {
        let mut sorted = claims.blobs.clone();
        sorted.sort_by(|a, b| a.blob_id.cmp(&b.blob_id));
        Some(sorted)
    };
    CanonicalReceiptClaims {
        v: claims.v,
        installation_id: &claims.installation_id,
        account_id: &claims.account_id,
        original_message_id: &claims.original_message_id,
        eligibility: &claims.eligibility,
        raw_mime_sha256: &claims.raw_mime_sha256,
        raw_mime_size: &claims.raw_mime_size,
        blobs,
        timeline_generation: &claims.timeline_generation,
        state_watermark: &claims.state_watermark,
        boot_epoch: &claims.boot_epoch,
        issued_at: &claims.issued_at,
        key_id: &claims.key_id,
    }
}

#[derive(Serialize)]
struct SignedReceipt {
    claims: ReceiptClaims,
    signature: String,
}

fn valid_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| matches!(i, 8 | 13 | 18 | 23) || b.is_ascii_hexdigit())
}

fn valid_decimal(value: &str) -> bool {
    if value == "0" {
        return true;
    }
    let bytes = value.as_bytes();
    (1..=19).contains(&bytes.len())
        && (b'1'..=b'9').contains(&bytes[0])
        && bytes[1..].iter().all(u8::is_ascii_digit)
        && value.parse::<u64>().is_ok_and(|n| n <= i64::MAX as u64)
}

fn valid_identifier(value: &str, min: usize, max: usize) -> bool {
    let bytes = value.as_bytes();
    (min..=max).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'.' | b'_' | b':' | b'-'))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn validate_claims(claims: &ReceiptClaims) -> bool {
    let canonical = canonical_claims(claims);
    let sorted_blobs = canonical.blobs.as_deref().unwrap_or(&[]);
    if claims.v != 1
        || !valid_uuid(&claims.installation_id)
        || !valid_uuid(&claims.boot_epoch)
        || !valid_decimal(&claims.account_id)
        || claims.account_id == "0"
        || !valid_identifier(&claims.original_message_id, 1, 256)
        || !matches!(claims.eligibility.as_str(), "received" | "sent-terminal")
        || !valid_digest(&claims.raw_mime_sha256)
        || !valid_decimal(&claims.raw_mime_size)
        || claims.raw_mime_size == "0"
        || !valid_decimal(&claims.timeline_generation)
        || claims.timeline_generation == "0"
        || !valid_decimal(&claims.state_watermark)
        || !valid_identifier(&claims.key_id, 1, 64)
        || sorted_blobs.len() > 4096
    {
        return false;
    }
    for (idx, blob) in sorted_blobs.iter().enumerate() {
        if !valid_identifier(&blob.blob_id, 1, 256)
            || !valid_digest(&blob.sha256)
            || !valid_decimal(&blob.size)
            || (idx > 0 && sorted_blobs[idx - 1].blob_id == blob.blob_id)
        {
            return false;
        }
    }
    true
}

fn artifact_identity(claims: &ReceiptClaims) -> String {
    let payload = format!(
        "v1\0{}\0{}\0{}\0{}",
        claims.installation_id,
        claims.account_id,
        claims.original_message_id,
        claims.raw_mime_sha256
    );
    let digest = Sha256::digest(payload.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn server_fail_detail(detail: &str) -> (String, String) {
    (
        "error".into(),
        reply::jmap_error_json("serverFail", 500, detail),
    )
}

impl<K: KeySource> JmapCommands<K> {
    pub(super) async fn execute_recovery_receipt(
        &self,
        user_id: i64,
        raw_args: &str,
        operation: [u8; 16],
        digest: [u8; 32],
    ) -> (String, String) {
        // Check toggle + signer/boot readiness BEFORE decoding args (recovery_receipt.go:97).
        let Some(enabled) = gates::toggle_state(&self.exec, batch::RECEIPTS_FLAG).await else {
            return ("error".into(), ws_request::server_fail());
        };
        let signer_and_boot = self.services.as_ref().and_then(|s| {
            Some((
                s,
                s.continuity_signer.as_deref()?,
                s.continuity_boot.as_deref()?,
            ))
        });
        if !enabled || signer_and_boot.is_none() {
            return (
                "error".into(),
                reply::jmap_error_json("forbidden", 500, "client recovery receipts are disabled"),
            );
        }
        let (services, signer, boot) = signer_and_boot.unwrap();

        let args = match decode_recovery_receipt_args(raw_args) {
            Ok(a) if !a.ids.is_empty() && a.ids.len() <= MAX_RECOVERY_RECEIPT_IDS => a,
            _ => {
                return (
                    "error".into(),
                    reply::jmap_error_json(
                        "invalidArguments",
                        400,
                        "invalid recovery receipt request",
                    ),
                );
            }
        };

        let resolved = match account::resolve_account(
            &self.exec,
            user_id,
            &args.account_id,
            family::Gate::Read,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => return ("error".into(), e.json()),
        };

        let mut parsed_ids = Vec::with_capacity(args.ids.len());
        for id in &args.ids {
            let Some(parsed) = id.parse::<i64>().ok().filter(|n| *n > 0) else {
                return (
                    "error".into(),
                    reply::jmap_error_json("invalidArguments", 400, "invalid recovery message id"),
                );
            };
            parsed_ids.push(parsed);
        }

        let env = envelope(&resolved.auth, operation, digest);
        // Runs in a receipted scoped tx and commits/releases BEFORE S3 reads & signing.
        let raw_ctx = match setjoin_jmap::http_blob::recovery_receipt_contexts(
            &self.exec,
            &resolved.auth,
            &env,
            &parsed_ids,
            boot,
        )
        .await
        {
            CommandOutcome::Committed(raw) => raw,
            CommandOutcome::Unknown { operation } => {
                return (
                    "error".into(),
                    reply::jmap_error_json(
                        "serverFail",
                        500,
                        &format!(
                            "commit outcome unknown; look up operation {}",
                            reply::hex(&operation.0)
                        ),
                    ),
                );
            }
            CommandOutcome::RolledBack(Rejection::Statement(failure)) => {
                return (
                    "error".into(),
                    reply::failure_or_server_fail(setjoin_jmap::classify_failure(&failure)),
                );
            }
            CommandOutcome::RolledBack(_) => {
                return ("error".into(), ws_request::server_fail());
            }
        };

        let ctx_result: ContextResult = match serde_json::from_str(&raw_ctx) {
            Ok(v) => v,
            Err(_) => return ("error".into(), ws_request::server_fail()),
        };

        let att_limit =
            if services.max_upload > 0 && (services.max_upload as u64) <= MAX_RECOVERY_BYTES {
                services.max_upload as u64
            } else {
                MAX_RECOVERY_BYTES
            };

        let mut found: HashSet<String> = HashSet::with_capacity(ctx_result.list.len());
        let mut items: Vec<serde_json::Value> = Vec::with_capacity(ctx_result.list.len());

        for row in ctx_result.list {
            found.insert(row.id.clone());

            let (raw_len, raw_sha256) = if row.raw_ref.contains(['\r', '\n']) {
                let bytes = row.raw_ref.as_bytes();
                if bytes.is_empty() || (bytes.len() as u64) > MAX_RECOVERY_BYTES {
                    return server_fail_detail("raw MIME is unavailable for recovery");
                }
                let digest: String = Sha256::digest(bytes)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                (bytes.len() as u64, digest)
            } else {
                let Some(store) = services.store.as_ref() else {
                    return server_fail_detail("raw MIME is unavailable for recovery");
                };
                match store.digest_object(&row.raw_ref, MAX_RECOVERY_BYTES).await {
                    Ok((len, sha)) if len > 0 && len <= MAX_RECOVERY_BYTES => (len, sha),
                    _ => return server_fail_detail("raw MIME is unavailable for recovery"),
                }
            };

            let mut blob_digests = Vec::with_capacity(row.attachments.len());
            for att in &row.attachments {
                let Ok(declared_size) = att.size.parse::<i64>().map_err(|_| ()) else {
                    return server_fail_detail("attachment metadata is invalid");
                };
                if declared_size <= 0 {
                    return server_fail_detail("attachment metadata is invalid");
                }
                let declared_u64 = declared_size as u64;
                if declared_u64 > att_limit {
                    return server_fail_detail("attachment bytes failed recovery verification");
                }
                let Some(store) = services.store.as_ref() else {
                    return server_fail_detail("attachment bytes failed recovery verification");
                };
                let Ok((actual_len, actual_sha)) =
                    store.digest_object(&att.blob_id, att_limit).await
                else {
                    return server_fail_detail("attachment bytes failed recovery verification");
                };
                if actual_len != declared_u64 || actual_sha != att.sha256 {
                    return server_fail_detail("attachment bytes failed recovery verification");
                }
                blob_digests.push(BlobDigest {
                    blob_id: att.blob_id.clone(),
                    sha256: actual_sha,
                    size: actual_len.to_string(),
                });
            }
            let claims = ReceiptClaims {
                v: 1,
                installation_id: ctx_result.context.installation_id.clone(),
                account_id: args.account_id.clone(),
                original_message_id: row.id.clone(),
                eligibility: row.eligibility.clone(),
                raw_mime_sha256: raw_sha256,
                raw_mime_size: raw_len.to_string(),
                blobs: blob_digests,
                timeline_generation: ctx_result.context.timeline_generation.clone(),
                state_watermark: ctx_result.context.state_watermark.clone(),
                boot_epoch: boot.to_owned(),
                issued_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                key_id: signer.key_id().to_owned(),
            };
            if !validate_claims(&claims) {
                return server_fail_detail("recovery receipt signing failed");
            }
            let Ok(claims_json) = serde_json::to_string(&canonical_claims(&claims)) else {
                return server_fail_detail("recovery receipt signing failed");
            };
            let Some(canonical) = reply::go_compact(&claims_json) else {
                return server_fail_detail("recovery receipt signing failed");
            };
            let sig = signer.sign(canonical.as_bytes());
            let signed = SignedReceipt {
                claims,
                signature: URL_SAFE_NO_PAD.encode(sig),
            };
            let identity = artifact_identity(&signed.claims);
            let item = serde_json::json!({
                "id": row.id,
                "eligibility": row.eligibility,
                "receivedAt": row.received_at,
                "artifactIdentity": identity,
                "receipt": signed,
                "raw": {
                    "sha256": signed.claims.raw_mime_sha256,
                    "size": signed.claims.raw_mime_size,
                    "url": format!("/jmap/recovery-raw/{}/{}", args.account_id, row.id),
                },
                "blobs": row.attachments,
            });
            items.push(item);
        }

        let not_found: Vec<&str> = args
            .ids
            .iter()
            .filter(|id| !found.contains(id.as_str()))
            .map(String::as_str)
            .collect();
        let response = serde_json::json!({
            "accountId": args.account_id,
            "list": items,
            "notFound": not_found,
        });
        match reply::go_compact(&response.to_string()) {
            Some(json) => ("Email/recoveryReceipt".into(), json),
            None => ("error".into(), ws_request::server_fail()),
        }
    }

    pub(super) async fn recovery_raw(
        &self,
        req: &Request<Body>,
        ctx: &RequestContext,
        auth: &MailboxAuthContext,
        id: &str,
    ) -> Response<Body> {
        let services = self.services.as_ref().unwrap();
        let Some(boot) = services.continuity_boot.as_deref() else {
            return problem(
                404,
                "notFound",
                "recovery raw endpoint is disabled",
                ctx,
                id,
            );
        };
        if super::gates::toggle_state(&self.exec, "feature.client_recovery_receipts").await
            != Some(true)
        {
            return problem(
                404,
                "notFound",
                "recovery raw endpoint is disabled",
                ctx,
                id,
            );
        }
        let parts = req.uri().path()[19..]
            .split('/')
            .map(|s| String::from_utf8_lossy(&crate::inventory::unescape(s)).into_owned())
            .collect::<Vec<_>>();
        let account = parts[0].parse::<i64>().ok().filter(|n| *n > 0);
        let message = parts[1].parse::<i64>().ok().filter(|n| *n > 0);
        let denied = || problem(403, "forbidden", "recovery account access denied", ctx, id);
        let (Some(account), Some(message)) = (account, message) else {
            return denied();
        };
        if !setjoin_jmap::http_blob::account_read(&services.worker, auth, account)
            .await
            .unwrap_or(false)
        {
            return denied();
        }
        let target = MailboxAuthContext::from_authenticated_session(
            ActorId::new(auth.actor().get()).unwrap(),
            MailboxId::new(account).unwrap(),
            Generation(1),
        );
        let Ok(operation) = super::random_bytes() else {
            return problem(500, "serverFail", "recovery context unavailable", ctx, id);
        };
        let env = envelope(
            &target,
            operation,
            Sha256::digest(req.uri().to_string()).into(),
        );
        let missing = || {
            problem(
                404,
                "emailNotFound",
                "recoverable message not found",
                ctx,
                id,
            )
        };
        let raw = match setjoin_jmap::http_blob::recovery_context(
            &self.exec, &target, &env, message, boot,
        )
        .await
        {
            setjoin_pg::CommandOutcome::Committed(raw) => raw,
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                let mut r = problem(
                    503,
                    "serverUnavailable",
                    "recovery outcome unknown",
                    ctx,
                    id,
                );
                r.headers_mut().insert(
                    "x-operation-id",
                    setjoin_pg::operation_hex(operation).parse().unwrap(),
                );
                return r;
            }
            _ => return missing(),
        };
        let value: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(_) => return missing(),
        };
        let Some(list) = value["list"].as_array().filter(|l| l.len() == 1) else {
            return missing();
        };
        let Some(reference) = list[0]["rawRef"].as_str() else {
            return missing();
        };
        let unavailable = || problem(503, "serverUnavailable", "raw MIME unavailable", ctx, id);
        let bytes = if reference.contains('\n') {
            reference.as_bytes().to_vec()
        } else {
            let Some(store) = &services.store else {
                return unavailable();
            };
            match store.read(reference, (50 << 20) + 1).await {
                Ok(bytes) => bytes,
                Err(_) => return unavailable(),
            }
        };
        if bytes.is_empty() || bytes.len() > 50 << 20 {
            return unavailable();
        }
        let mut r = reply::response(String::new(), ctx.identity.proto, id.into());
        let len = bytes.len();
        *r.body_mut() = Full::new(bytes::Bytes::from(bytes))
            .map_err(|n| match n {})
            .boxed();
        let h = r.headers_mut();
        h.insert("content-type", "message/rfc822".parse().unwrap());
        h.insert("content-length", len.to_string().parse().unwrap());
        h.insert(
            "content-disposition",
            format!("attachment; filename=\"recovery-{message}.eml\"")
                .parse()
                .unwrap(),
        );
        h.insert(
            "content-security-policy",
            "default-src 'none'; sandbox".parse().unwrap(),
        );
        r
    }
}

/// Go disables this surface when loading fails; it does not generate a key.
pub(super) fn continuity_from_env() -> Option<(String, super::family::ContinuitySigner)> {
    let path = std::env::var_os("CONTINUITY_SIGNING_KEY_FILE")
        .unwrap_or_else(|| "/etc/setjoin/continuity-signing-key.pem".into());
    let path = std::path::Path::new(&path);
    if !path.is_absolute()
        || path
            .components()
            .collect::<std::path::PathBuf>()
            .as_os_str()
            != path.as_os_str()
    {
        return None;
    }
    let id = std::env::var("CONTINUITY_SIGNING_KEY_ID").unwrap_or_else(|_| "continuity-v1".into());
    if id.is_empty()
        || id.len() > 64
        || !id.as_bytes()[0].is_ascii_alphanumeric()
        || !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(&c))
    {
        return None;
    }
    let pem = zeroize::Zeroizing::new(std::fs::read(path).ok()?);
    let begin = pem.windows(11).position(|v| v == b"-----BEGIN ")?;
    if !pem[begin..].starts_with(b"-----BEGIN PRIVATE KEY-----") {
        return None;
    }
    let footer = b"-----END PRIVATE KEY-----";
    let end = pem.windows(footer.len()).position(|v| v == footer)? + footer.len();
    if !matches!(&pem[end..], b"" | b"\n" | b"\r\n") {
        return None;
    }
    use tokio_rustls::rustls::pki_types::{pem::PemObject, PrivateKeyDer};
    let key = PrivateKeyDer::from_pem_slice(&pem).ok()?;
    let der = zeroize::Zeroizing::new(key.secret_der().to_vec());
    let key = ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der).ok()?;
    Some((
        super::http::uuid()?,
        super::family::ContinuitySigner::new(id, key),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_decode_rejects_unknown_fields_and_trailing_tokens() {
        let ok = decode_recovery_receipt_args(r#"{"ACCOUNTID":"12","ids":["1","2"]}"#).unwrap();
        assert_eq!(ok.account_id, "12");
        assert_eq!(ok.ids, vec!["1", "2"]);
        assert!(
            decode_recovery_receipt_args(r#"{"accountId":"12","ids":["1"],"extra":1}"#).is_err()
        );
        assert!(
            decode_recovery_receipt_args(r#"{"accountId":"12","ids":["1"]} trailing"#).is_err()
        );
    }

    #[test]
    fn artifact_identity_matches_v1_null_delimited_sha256() {
        let claims = ReceiptClaims {
            v: 1,
            installation_id: "11111111-1111-4111-8111-111111111111".into(),
            account_id: "12".into(),
            original_message_id: "345".into(),
            eligibility: "received".into(),
            raw_mime_sha256: "a".repeat(64),
            raw_mime_size: "10".into(),
            blobs: Vec::new(),
            timeline_generation: "1".into(),
            state_watermark: "0".into(),
            boot_epoch: "22222222-2222-4222-8222-222222222222".into(),
            issued_at: "2026-11-21T00:00:00Z".into(),
            key_id: "continuity-v1".into(),
        };
        assert!(validate_claims(&claims));
        let expected: String = Sha256::digest(
            format!(
                "v1\0{}\012\0345\0{}",
                claims.installation_id, claims.raw_mime_sha256
            )
            .as_bytes(),
        )
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
        assert_eq!(artifact_identity(&claims), expected);
    }
}
