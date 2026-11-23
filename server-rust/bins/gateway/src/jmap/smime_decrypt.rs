//! Inbound `Email/get` decrypt-on-read (#328, #356 Wave 2b).
//!
//! Settled controls enforced here:
//! 1. Charge the `120/min` per-user reader budget BEFORE any key or S3 object work.
//! 2. Load decryption keys via `worker.read_scoped` (`AUDIT_SCOPE` `app.encryption_key`)
//!    filtered explicitly by `user_id = $actor` (delegate mailbox access never
//!    confers the owner's private keys).
//! 3. Unwrap DER / MIME CMS via OpenSSL (`setjoin_smtp::smime`) collapsing
//!    matched-key unwrap/body/recipient errors into `wrong_key`.
//! 4. Gate plaintext release on a successful `email_decrypt_read` audit write
//!    keyed by authenticated actor, REAL resolved mailbox ID, and numeric
//!    message ID.
//! 5. Inject ONLY `decryptState`, transient `bodyText`, and `preview` sliced to
//!    256 bytes BEFORE UTF-8 lossy replacement (never `bodyHTML`, never persisted).

use super::limit::Limiter;
use super::reply;
use crate::recovery_worker::{ObjectStore, S3Store};
use serde_json::value::RawValue;
use serde_json::Value;
use setjoin_pg::{MailboxAuthContext, ScopedExecutor, Type};
use setjoin_smtp::smime::{
    self, decode_enveloped_der, decrypt_multi, parse_decrypt_candidate, DecryptError, DecryptKey,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_DECRYPT_BLOB_BYTES: usize = 50 << 20;

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn decrypt_allowed(limiter: Option<&Limiter>, actor_user_id: i64, now_unix: u64) -> bool {
    match limiter {
        Some(lim) => lim.allow_key(format!("decrypt:{actor_user_id}").as_bytes(), now_unix),
        None => true,
    }
}

async fn load_decrypt_keys(
    worker: &ScopedExecutor,
    auth: &MailboxAuthContext,
) -> Result<Vec<DecryptKey>, ()> {
    let actor_user_id = auth.actor().get();
    let rows = worker
        .read_scoped(
            auth,
            "SELECT cert_pem, \
                    pgp_sym_decrypt(private_key_enc::bytea, current_setting('app.encryption_key')) \
             FROM user_smime_certs \
             WHERE user_id = $1 AND private_key_enc IS NOT NULL \
             ORDER BY is_default DESC, created_at DESC",
            &[(&actor_user_id, Type::INT8)],
        )
        .await
        .map_err(|_| ())?;
    let mut keys = Vec::new();
    for r in rows {
        let cert_pem: String = r.get(0);
        let key_pem: String = r.get(1);
        if let Some(dk) = parse_decrypt_candidate(&cert_pem, &key_pem) {
            keys.push(dk);
        }
    }
    Ok(keys)
}

/// Injects transient `bodyText` and a 256-byte-pre-lossy `preview` into `email`.
/// Never populates or alters `bodyHTML`.
pub fn inject_cleartext(email: &mut BTreeMap<String, Value>, plaintext: &[u8]) {
    let preview_end = plaintext.len().min(256);
    let body_text = String::from_utf8_lossy(plaintext).into_owned();
    let preview = String::from_utf8_lossy(&plaintext[..preview_end]).into_owned();
    email.insert("bodyText".into(), Value::String(body_text));
    email.insert("preview".into(), Value::String(preview));
}

async fn record_decrypt_audit(
    exec: &ScopedExecutor,
    mailbox_id: i64,
    actor_user_id: i64,
    message_id: i64,
) -> Result<(), ()> {
    exec.protocol_statement(
        "INSERT INTO mailbox_audit_log (mailbox_id, actor_user_id, action, message_id) \
         VALUES ($1, $2, 'email_decrypt_read', $3)",
        &[
            (&mailbox_id, Type::INT8),
            (&actor_user_id, Type::INT8),
            (&message_id, Type::INT8),
        ],
    )
    .await
    .map_err(|_| ())
}

async fn decrypt_one_email(
    exec: &ScopedExecutor,
    store: Option<&S3Store>,
    mailbox_id: i64,
    actor_user_id: i64,
    email: &mut BTreeMap<String, Value>,
    keys: Arc<Vec<DecryptKey>>,
) -> &'static str {
    let Some(store) = store else {
        return smime::DECRYPT_STATE_ERROR;
    };
    let blob_id = email
        .get("blobId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let msg_id = email
        .get("id")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|id| *id > 0);
    if blob_id.is_empty() || msg_id.is_none() {
        return smime::DECRYPT_STATE_ERROR;
    }
    let msg_id = msg_id.unwrap();

    let Ok(raw) = store.read(&blob_id, MAX_DECRYPT_BLOB_BYTES).await else {
        return smime::DECRYPT_STATE_ERROR;
    };
    let Ok(der) = decode_enveloped_der(&raw) else {
        return smime::DECRYPT_STATE_ERROR;
    };
    let decrypt_res = tokio::task::spawn_blocking(move || decrypt_multi(&der, &keys)).await;
    let plaintext = match decrypt_res {
        Ok(Ok(pt)) => pt,
        Ok(Err(DecryptError::WrongKey)) => return smime::DECRYPT_STATE_WRONG_KEY,
        Ok(Err(DecryptError::MalformedCms)) | Err(_) => return smime::DECRYPT_STATE_ERROR,
    };

    // Gate plaintext release on a successful audit row write.
    if record_decrypt_audit(exec, mailbox_id, actor_user_id, msg_id)
        .await
        .is_err()
    {
        return smime::DECRYPT_STATE_ERROR;
    }

    inject_cleartext(email, &plaintext);
    smime::DECRYPT_STATE_DECRYPTED
}

/// Inspects an `Email/get` JSON response; if any entry has `cryptoType ==
/// "smime-encrypted"`, enforces per-user `120/min` budget, decrypts using
/// `$actor`'s keys, gates plaintext on `email_decrypt_read` audit, and sets
/// `decryptState` (`decrypted` / `no_key` / `wrong_key` / `error`).
/// Non-encrypted results are returned byte-for-byte unchanged.
pub async fn decrypt_email_result(
    exec: &ScopedExecutor,
    worker: &ScopedExecutor,
    store: Option<&S3Store>,
    limiter: Option<&Limiter>,
    auth: &MailboxAuthContext,
    raw_json: &str,
) -> String {
    let Ok(mut top) = serde_json::from_str::<BTreeMap<String, Box<RawValue>>>(raw_json) else {
        return raw_json.to_owned();
    };
    let Some(list_raw) = top.get("list") else {
        return raw_json.to_owned();
    };
    let Ok(list_vals) = serde_json::from_str::<Vec<Value>>(list_raw.get()) else {
        return raw_json.to_owned();
    };
    let has_encrypted = list_vals
        .iter()
        .any(|v| v.get("cryptoType").and_then(Value::as_str) == Some("smime-encrypted"));
    if !has_encrypted {
        return raw_json.to_owned();
    }

    let actor_user_id = auth.actor().get();
    let mailbox_id = auth.mailbox().get();
    let mut cached_keys: Option<Result<Arc<Vec<DecryptKey>>, ()>> = None;
    let mut out_list = Vec::with_capacity(list_vals.len());

    for item in list_vals {
        let Value::Object(map) = item else {
            out_list.push(item);
            continue;
        };
        if map.get("cryptoType").and_then(Value::as_str) != Some("smime-encrypted") {
            out_list.push(Value::Object(map));
            continue;
        }
        let mut obj: BTreeMap<String, Value> = map.into_iter().collect();

        // Charge per-user 120/min budget BEFORE key load or S3 object fetch.
        if !decrypt_allowed(limiter, actor_user_id, now_unix_secs()) {
            obj.insert(
                "decryptState".into(),
                Value::String(smime::DECRYPT_STATE_ERROR.into()),
            );
            out_list.push(Value::Object(obj.into_iter().collect()));
            continue;
        }

        let keys = match &cached_keys {
            Some(res) => res.clone(),
            None => {
                let loaded = load_decrypt_keys(worker, auth).await.map(Arc::new);
                cached_keys = Some(loaded.clone());
                loaded
            }
        };
        let state = match keys {
            Err(()) => smime::DECRYPT_STATE_ERROR,
            Ok(k) if k.is_empty() => smime::DECRYPT_STATE_NO_KEY,
            Ok(k) => decrypt_one_email(exec, store, mailbox_id, actor_user_id, &mut obj, k).await,
        };
        obj.insert("decryptState".into(), Value::String(state.into()));
        out_list.push(Value::Object(obj.into_iter().collect()));
    }

    let Ok(list_str) = serde_json::to_string(&out_list) else {
        return raw_json.to_owned();
    };
    let Ok(list_box) = RawValue::from_string(list_str) else {
        return raw_json.to_owned();
    };
    top.insert("list".into(), list_box);
    reply::marshal_sorted(&top).unwrap_or_else(|| raw_json.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_cleartext_slices_preview_before_utf8_lossy_and_skips_html() {
        // Multi-byte UTF-8 sequence straddling the 256-byte boundary:
        // 255 ASCII 'a' bytes followed by 4-byte emoji (U+1F600) so slicing at
        // 256 bytes cuts mid-codepoint BEFORE lossy replacement.
        let mut raw = vec![b'a'; 255];
        raw.extend_from_slice("😀tail".as_bytes());
        let mut email = BTreeMap::new();
        email.insert("bodyHTML".into(), Value::String("existing".into()));

        inject_cleartext(&mut email, &raw);

        assert_eq!(email["bodyHTML"], "existing");
        let preview = email["preview"].as_str().unwrap();
        assert_eq!(preview.len(), 255 + "\u{FFFD}".len());
        assert!(preview.starts_with(&"a".repeat(255)));
        assert!(preview.ends_with('\u{FFFD}'));
        assert!(email["bodyText"].as_str().unwrap().ends_with("😀tail"));
    }

    #[test]
    fn decrypt_allowed_charges_budget_per_user() {
        let lim = Limiter::new(2, 60);
        assert!(decrypt_allowed(Some(&lim), 7, 120));
        assert!(decrypt_allowed(Some(&lim), 7, 120));
        assert!(!decrypt_allowed(Some(&lim), 7, 120));
        assert!(decrypt_allowed(Some(&lim), 8, 120));
        assert!(decrypt_allowed(None, 7, 120));
    }
}
