//! Frozen shared/device proof verification. HMAC, hashes and EK01 use the
//! maintained RustCrypto/ring-backed foundation; no primitive is implemented here.
use crate::runtime::Proof;
use hmac::{Hmac, Mac};
use setjoin_config_secret::{open_column, seal_column, CryptoProfile};
use setjoin_pg::{ScopedExecutor, Type};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub struct DeviceRequest<'a> {
    pub headers: &'a hyper::HeaderMap,
    pub method: &'a str,
    pub uri: &'a str,
    pub body: &'a [u8],
}
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Binding {
    pub bound: bool,
    pub device_id: i64,
    pub enroll_state: String,
}
/// Device authority created only after HMAC, body binding, freshness and the
/// deployment-wide nonce claim have all succeeded. It carries no user/session grant.
pub struct VerifiedDevice(i64);
impl VerifiedDevice {
    pub fn id(&self) -> i64 {
        self.0
    }
}

pub struct DeviceResolver {
    exec: ScopedExecutor,
    master: Zeroizing<Vec<u8>>,
    profile: CryptoProfile,
}
impl DeviceResolver {
    pub fn new(exec: ScopedExecutor, master: Vec<u8>, profile: CryptoProfile) -> Self {
        Self {
            exec,
            master: Zeroizing::new(master),
            profile,
        }
    }
    pub async fn resolve(&self, proof: &Proof, r: DeviceRequest<'_>) -> Binding {
        self.checked(proof, r).await.unwrap_or_default()
    }
    async fn checked(&self, proof: &Proof, r: DeviceRequest<'_>) -> Option<Binding> {
        let id = r
            .headers
            .get("x-device-id")?
            .to_str()
            .ok()?
            .parse::<i64>()
            .ok()?;
        // Owner-approved security fix 2026-11-05 (#499): ownership is checked
        // BEFORE the proof consumes the device's single-use nonce, so a foreign
        // caller cannot burn another user's device nonce with a refused request.
        let rows=self.exec.read("SELECT enroll_state,revoked_at IS NOT NULL FROM devices WHERE id=$1 AND user_id=$2",&[(&id,Type::INT8),(&proof.user_id(),Type::INT8)]).await.ok()?;
        let restored = setjoin_contracts::mutants::on("device-nonce-before-ownership");
        if !restored {
            rows.first()?;
        }
        self.verify_request(id, r).await?;
        let row = rows.first()?;
        Some(Binding {
            bound: !row.get::<_, bool>(1),
            device_id: id,
            enroll_state: row.get(0),
        })
    }

    /// Frozen VerifyDeviceRequest: telemetry's claimed ID is authenticated by
    /// this exact request's proof. Unlike session attribution, it needs no JWT
    /// or X-Device-ID header and grants authority only to the proved device.
    pub async fn verify_request(&self, id: i64, r: DeviceRequest<'_>) -> Option<VerifiedDevice> {
        if id <= 0 {
            return None;
        }
        let h = |key| {
            r.headers
                .get(key)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
        };
        let provided = h("x-device-hmac");
        let nonce = h("x-device-nonce");
        let hash = h("x-device-body-sha256");
        let ts = h("x-device-timestamp");
        if self.master.is_empty()
            || nonce.is_empty()
            || nonce.len() > 128
            || provided.len() != 64
            || hash.len() != 64
            || r.body.len() > (1 << 20)
        {
            return None;
        }
        if ![provided, hash].iter().all(|s| {
            s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) {
            return None;
        }
        let timestamp = timestamp(ts)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs_f64();
        if (now - timestamp).abs() > 300.0 || format!("{:x}", Sha256::digest(r.body)) != hash {
            return None;
        }
        // This is a credential lookup, not a user-data read: Go verifies the
        // hardware proof before attributing it to the verified session below.
        let rows=self.exec.read("SELECT hmac_secret,hmac_secret_enc,hmac_secret_key_id FROM devices WHERE id=$1 AND revoked_at IS NULL AND enroll_state<>'revoked'",&[(&id,Type::INT8)]).await.ok()?;
        let row = rows.first()?;
        let legacy: Option<String> = row.get(0);
        let envelope: Option<Vec<u8>> = row.get(1);
        let key_id: Option<String> = row.get(2);
        let secret = if let Some(envelope) = envelope {
            if key_id.as_deref() != Some("v1") {
                return None;
            }
            Zeroizing::new(open_column(&envelope, &self.master).ok()?)
        } else {
            let legacy = Zeroizing::new(legacy?);
            // Go's compatibility migration is a separate best-effort autocommit,
            // before HMAC verification; retain those transaction boundaries.
            // Owner-approved security fix 2026-11-05 (#513 item 1): Go's UPDATE ran with no
            // user GUC, so under app RLS (devices_self) it matched nothing and the plaintext
            // secret outlived every successful proof. The re-seal is a credential-maintenance
            // reducer keyed on the id AND the exact plaintext just loaded (R3); it never
            // reads a secret back. The restored-bug mutant keeps Go's request-pool UPDATE.
            if let Ok(sealed) = seal_column(legacy.as_bytes(), &self.master, self.profile) {
                if setjoin_contracts::mutants::on("device-reseal-under-rls") {
                    let _=self.exec.protocol_statement("UPDATE devices SET hmac_secret_enc=$2,hmac_secret_key_id='v1',hmac_secret=NULL WHERE id=$1 AND hmac_secret=$3 AND hmac_secret_enc IS NULL",&[(&id,Type::INT8),(&sealed,Type::BYTEA),(&legacy.as_str(),Type::TEXT)]).await;
                } else {
                    let _=self.exec.protocol_statement("SELECT rust_device_secret_reseal($1,$2,'v1',$3)",&[(&id,Type::INT8),(&sealed,Type::BYTEA),(&legacy.as_str(),Type::TEXT)]).await;
                }
            }
            Zeroizing::new(legacy.as_bytes().to_vec())
        };
        let challenge = format!("{id}:{ts}:{}:{}:{hash}:{nonce}", r.method, r.uri);
        let signature: Vec<u8> = (0..provided.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&provided[i..i + 2], 16))
            .collect::<Result<_, _>>()
            .ok()?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&secret).ok()?;
        mac.update(challenge.as_bytes());
        mac.verify_slice(&signature).ok()?;
        // The deployment-wide single-use claim commits before attribution, as
        // in Go. Its reducer owns expiry cleanup plus the nonce INSERT atomically.
        self.exec
            .protocol_statement(
                "SELECT device_nonce_claim($1,$2,660)",
                &[(&id, Type::INT8), (&nonce, Type::TEXT)],
            )
            .await
            .ok()?;
        Some(VerifiedDevice(id))
    }
}
fn timestamp(raw: &str) -> Option<f64> {
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(raw) {
        return Some(t.timestamp() as f64 + t.timestamp_subsec_nanos() as f64 / 1e9);
    }
    // fmt.Sscanf("%d") accepts a signed decimal prefix and ignores trailing text.
    let s = raw.trim_start();
    let sign = usize::from(s.starts_with(['+', '-']));
    let end = sign + s[sign..].bytes().take_while(u8::is_ascii_digit).count();
    s.get(..end)?.parse::<i64>().ok().map(|n| n as f64)
}
