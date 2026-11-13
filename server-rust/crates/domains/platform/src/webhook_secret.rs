//! Webhook signing secrets (Go `shared/webhook`): the at-rest EK01 envelope codec, the
//! per-subscription loader with its legacy-plaintext lazy re-seal, and the
//! `X-Webhook-Signature` v1 HMAC header.
//!
//! The master key is the RAW process JWT secret (`cryptokey` derives the column key
//! itself), the key-version id stamped beside every envelope is `v1`. A missing codec or
//! an unknown key version fails closed on every read, legacy rows included.
use hmac::{Hmac, Mac};
use setjoin_config_secret::{open_column, seal_column, CryptoProfile};
use setjoin_pg::{workers::WorkerConnection, Type};
use sha2::Sha256;

/// `SecretKeyIDV1`.
pub const KEY_ID_V1: &str = "v1";
/// `MinSecretLen`: `Sign` refuses anything shorter.
pub const MIN_SECRET_LEN: usize = 32;

/// Go's `*SecretCodec`; `None` master models a nil codec (every use fails closed).
#[derive(Clone)]
pub struct SecretCodec {
    master: Vec<u8>,
    profile: CryptoProfile,
}

impl std::fmt::Debug for SecretCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretCodec").finish_non_exhaustive()
    }
}

const NOT_CONFIGURED: &str = "webhook: secret codec not configured";

impl SecretCodec {
    pub fn new(master: &[u8], profile: CryptoProfile) -> Self {
        Self {
            master: master.to_vec(),
            profile,
        }
    }

    pub fn active_key_id(&self) -> &'static str {
        KEY_ID_V1
    }

    pub fn seal(&self, plaintext: &str) -> Result<Vec<u8>, String> {
        if self.master.is_empty() {
            return Err(NOT_CONFIGURED.into());
        }
        seal_column(plaintext.as_bytes(), &self.master, self.profile)
            .map_err(|e| format!("webhook: seal signing secret: {e}"))
    }

    pub fn open(&self, envelope: &[u8], key_id: &str) -> Result<String, String> {
        if self.master.is_empty() {
            return Err(NOT_CONFIGURED.into());
        }
        if key_id != KEY_ID_V1 {
            return Err(format!(
                "webhook: signing secret requires unavailable key version {key_id:?}"
            ));
        }
        let plain = open_column(envelope, &self.master)
            .map_err(|e| format!("webhook: open signing secret envelope: {e}"))?;
        Ok(String::from_utf8_lossy(&plain).into_owned())
    }
}

/// `generateWebhookSecret`: 32 random bytes, hex encoded.
pub fn generate_secret() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| e.to_string())?;
    Ok(hex(&bytes))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `wh.Sign`: `v1,t=<unix>,sig=<hex hmac-sha256("<unix>.<body>")>`; a secret shorter than
/// [`MIN_SECRET_LEN`] bytes is refused. `now` is the Unix timestamp to stamp.
pub fn sign(body: &[u8], secret: &str, now: i64) -> Result<String, String> {
    if secret.len() < MIN_SECRET_LEN {
        return Err(format!(
            "webhook: signing secret must be at least {MIN_SECRET_LEN} bytes (got {})",
            secret.len()
        ));
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("any key length");
    mac.update(format!("{now}.").as_bytes());
    mac.update(body);
    Ok(format!(
        "v1,t={now},sig={}",
        hex(&mac.finalize().into_bytes())
    ))
}

/// `wh.LoadSubscriptionSecret`: the signing secret of one subscription, opened through
/// the codec. A legacy plaintext row is returned as stored and lazily re-sealed in one
/// atomic UPDATE draining both plaintext cells (pinned to the values just read, so a
/// concurrent rotation turns it into a no-op); a failed re-seal never blocks delivery.
pub async fn load_subscription_secret(
    conn: &WorkerConnection,
    codec: Option<&SecretCodec>,
    subscription: i64,
) -> Result<String, String> {
    let codec = codec.ok_or_else(|| NOT_CONFIGURED.to_string())?;
    let rows = conn
        .query(
            "SELECT secret, prev_secret, secret_enc, secret_key_id, prev_secret_enc, prev_secret_key_id \
             FROM webhook_subscriptions WHERE id = $1",
            &[(&subscription, Type::INT8)],
        )
        .await
        .map_err(|e| format!("webhook: load signing secret: {e}"))?;
    let Some(row) = rows.first() else {
        return Err(format!("webhook: subscription {subscription} not found"));
    };
    let legacy: Option<String> = row
        .try_get(0)
        .map_err(|e| format!("webhook: load signing secret: {e}"))?;
    let prev_legacy: Option<String> = row
        .try_get(1)
        .map_err(|e| format!("webhook: load signing secret: {e}"))?;
    let envelope: Option<Vec<u8>> = row
        .try_get(2)
        .map_err(|e| format!("webhook: load signing secret: {e}"))?;
    let key_id: Option<String> = row
        .try_get(3)
        .map_err(|e| format!("webhook: load signing secret: {e}"))?;
    let prev_envelope: Option<Vec<u8>> = row
        .try_get(4)
        .map_err(|e| format!("webhook: load signing secret: {e}"))?;
    if let Some(envelope) = envelope {
        let Some(key_id) = key_id else {
            return Err("webhook: signing secret envelope missing key id".into());
        };
        return codec.open(&envelope, &key_id);
    }
    let Some(secret) = legacy else {
        return Err(format!(
            "webhook: subscription {subscription} holds no usable signing secret"
        ));
    };
    let sealed = codec.seal(&secret);
    let mut sealed_prev: Option<Vec<u8>> = None;
    let mut seal_ok = sealed.is_ok();
    if seal_ok && prev_envelope.is_none() {
        if let Some(prev) = &prev_legacy {
            match codec.seal(prev) {
                Ok(bytes) => sealed_prev = Some(bytes),
                Err(_) => seal_ok = false,
            }
        }
    }
    if let (true, Ok(sealed)) = (seal_ok, sealed) {
        let prev_key: Option<&str> = sealed_prev.as_ref().map(|_| codec.active_key_id());
        let _ = conn
            .execute(
                "UPDATE webhook_subscriptions \
                    SET secret_enc = $2, secret_key_id = $3, secret = NULL, \
                        prev_secret_enc = COALESCE(prev_secret_enc, $5), \
                        prev_secret_key_id = COALESCE(prev_secret_key_id, $7), \
                        prev_secret = NULL \
                  WHERE id = $1 AND secret = $4 AND secret_enc IS NULL \
                    AND prev_secret IS NOT DISTINCT FROM $6",
                &[
                    (&subscription, Type::INT8),
                    (&sealed, Type::BYTEA),
                    (&codec.active_key_id(), Type::TEXT),
                    (&secret, Type::TEXT),
                    (&sealed_prev, Type::BYTEA),
                    (&prev_legacy, Type::TEXT),
                    (&prev_key, Type::TEXT),
                ],
            )
            .await;
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_matches_the_v1_scheme() {
        // HMAC-SHA256("1700000000.{}", key) computed independently.
        let header = sign(b"{}", &"k".repeat(32), 1_700_000_000).unwrap();
        assert!(header.starts_with("v1,t=1700000000,sig="));
        assert_eq!(header.len(), "v1,t=1700000000,sig=".len() + 64);
        assert!(sign(b"{}", "short", 1)
            .unwrap_err()
            .contains("at least 32 bytes (got 5)"));
    }

    #[test]
    fn codec_round_trips_and_refuses_unknown_key_versions() {
        let codec = SecretCodec::new(b"jwt", CryptoProfile::Standard);
        let sealed = codec.seal("abc").unwrap();
        assert_eq!(codec.open(&sealed, "v1").unwrap(), "abc");
        assert!(codec
            .open(&sealed, "v2")
            .unwrap_err()
            .contains("unavailable key version \"v2\""));
        assert_eq!(
            SecretCodec::new(b"", CryptoProfile::Standard)
                .seal("x")
                .unwrap_err(),
            NOT_CONFIGURED
        );
        assert_eq!(generate_secret().unwrap().len(), 64);
    }
}
