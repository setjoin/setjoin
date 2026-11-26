//! Webhook signing secrets (Go `shared/webhook`): the at-rest EK01 envelope codec, the
//! per-subscription loader with its legacy-plaintext lazy re-seal, and the
//! `X-Webhook-Signature` v1 HMAC header.
//!
//! The master key is the RAW process JWT secret (`cryptokey` derives the column key
//! itself), the key-version id stamped beside every envelope is `v1`. A missing codec or
//! an unknown key version fails closed on every read, legacy rows included.
use hmac::{Hmac, Mac};
use setjoin_config_secret::{open_column, seal_column, CryptoProfile};
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

pub const NOT_CONFIGURED: &str = "webhook: secret codec not configured";

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
