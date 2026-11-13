// guard-core — SetJoin secure-value core (Rust)
// Vault · TOTP · ECDH push · secure-store · wipe.
//
// This crate owns secure values, not the device-auth lifecycle. Device
// checkin / token refresh / registration is HTTP that the platform bridge
// owns (desktop `bridge.rs`, the C2 `mam.rs`), not guard-core.

uniffi::setup_scaffolding!();

pub mod db;
pub mod ecdh;
pub mod error;
pub mod provider;
mod securestore;
pub mod totp;
pub mod types;
pub mod vault;

pub use error::GuardError;
pub use provider::MamPolicy;
pub use securestore::{KeyTier, SecureStore, SecureStoreError};
pub use types::{PushApprovalAssertion, TotpAccount, TotpCode};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rusqlite::Connection;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use vault::kdf::{derive_key, derive_subkey, KdfParams};
use zeroize::Zeroizing;

/// In-memory device/MAM state, not persisted to the vault SQLite DB.
///
/// Held for the C2 `mam.rs` lifecycle (device id + cached policy); the
/// vault-wipe flag latches the secure store closed after a remote wipe.
struct DeviceState {
    device_id: Option<String>,
    mam_policy: Option<MamPolicy>,
    wipe_requested: bool,
    took_device_fallback: bool,
}

#[derive(uniffi::Object)]
pub struct GuardCore {
    conn: Mutex<Connection>,
    key: Zeroizing<[u8; 32]>,
    state: Mutex<DeviceState>,
}

// ── UniFFI-exported methods (TOTP + ECDH) ──────────────────────────────

/// A2 legacy-vault follow-up (see `GuardCore::new`): probe whatever
/// already-encrypted data the vault might hold and confirm `key` decrypts it.
/// AES-256-GCM authentication makes a wrong key fail decryption, so this is
/// exactly as strong a check as the `kek_check` sentinel itself. Returns
/// `Ok(())` with no check performed only if the vault holds none of these (a
/// genuinely empty, first-run vault).
///
/// `ecdh_sk_enc`, secure-store (`ss:`) rows, `totp_accounts.seed_enc` and
/// `vault_items.data_enc` are raw/base64 AES-256-GCM ciphertext from the
/// moment they're first written, so they're safe to probe unconditionally.
/// D-CLIENTS-RUST-GUARD-CORE-P1-001: skipping the seed/item probes on a
/// pre-migration vault let a sentinel-less vault whose ONLY ciphertext was
/// TOTP seeds / vault items "verify" unchecked, and `new` then provisioned
/// `kek_check` under a WRONG passphrase — permanently locking out the right
/// one. `totp_accounts.label` / `vault_items.kind` are only ciphertext (base64
/// via `enc_text`) *after* `migrate_plaintext_metadata` has run
/// (`metadata_enc='1'`) — before that they're legacy cleartext (or, in test
/// fixtures, placeholder bytes) and not a valid probe.
///
/// med-shard3-004 r2: every probe distinguishes an ABSENT row
/// (`QueryReturnedNoRows` → the probe doesn't apply, move on) from a real
/// query/column-type error (`Err` → fail-closed refusal). The old
/// `if let Ok(blob)` swallowed ciphertext-query/type errors into "absent", so
/// a sentinel-less TOTP row stored with TEXT in `seed_enc` (unrecognized or
/// corrupt shape — real writes always store a raw AES-256-GCM blob) beside an
/// intact encrypted `uri_enc` was treated as an EMPTY vault and got a
/// wrong-key sentinel baked in. Emptiness must be PROVEN; an unrecognized
/// shape refuses provisioning for every key.
fn probe_blob_ciphertext(conn: &Connection, sql: &str, key: &[u8; 32]) -> Result<bool, GuardError> {
    match conn.query_row(sql, [], |r| r.get::<_, Vec<u8>>(0)) {
        Ok(blob) => {
            db::store::decrypt(key, &blob)?;
            Ok(true)
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(e) => Err(GuardError::Database(format!(
            "vault ciphertext probe failed: {e} — refusing to treat the vault as empty"
        ))),
    }
}

/// TEXT-column twin of `probe_blob_ciphertext` (base64 `enc_text` ciphertext).
fn probe_text_ciphertext(conn: &Connection, sql: &str, key: &[u8; 32]) -> Result<bool, GuardError> {
    match conn.query_row(sql, [], |r| r.get::<_, String>(0)) {
        Ok(ct) => {
            db::store::dec_text(key, &ct)?;
            Ok(true)
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(e) => Err(GuardError::Database(format!(
            "vault ciphertext probe failed: {e} — refusing to treat the vault as empty"
        ))),
    }
}

fn verify_key_against_existing_ciphertext(
    conn: &Connection,
    key: &[u8; 32],
) -> Result<(), GuardError> {
    if probe_blob_ciphertext(conn, "SELECT value FROM meta WHERE key='ecdh_sk_enc'", key)? {
        return Ok(());
    }
    if probe_text_ciphertext(
        conn,
        "SELECT value FROM meta WHERE key LIKE 'ss:%' LIMIT 1",
        key,
    )? {
        return Ok(());
    }
    if probe_blob_ciphertext(conn, "SELECT seed_enc FROM totp_accounts LIMIT 1", key)? {
        return Ok(());
    }
    if probe_blob_ciphertext(conn, "SELECT data_enc FROM vault_items LIMIT 1", key)? {
        return Ok(());
    }
    let migrated = match conn.query_row::<String, _, _>(
        "SELECT value FROM meta WHERE key='metadata_enc'",
        [],
        |r| r.get(0),
    ) {
        Ok(v) => v == "1",
        Err(rusqlite::Error::QueryReturnedNoRows) => false,
        Err(e) => {
            return Err(GuardError::Database(format!(
                "vault ciphertext probe failed: {e} — refusing to treat the vault as empty"
            )))
        }
    };
    if migrated {
        if probe_text_ciphertext(conn, "SELECT label FROM totp_accounts LIMIT 1", key)? {
            return Ok(());
        }
        if probe_text_ciphertext(conn, "SELECT kind FROM vault_items LIMIT 1", key)? {
            return Ok(());
        }
    }
    Ok(())
}

#[uniffi::export]
impl GuardCore {
    /// Open/create the Guard database and derive the encryption key.
    #[uniffi::constructor]
    pub fn new(db_path: String, passphrase: String) -> Result<Arc<Self>, GuardError> {
        let conn = Connection::open(&db_path)?;
        db::schema::apply_migrations(&conn)?;

        let params: KdfParams = conn
            .query_row("SELECT value FROM meta WHERE key='kdf_params'", [], |r| {
                r.get::<_, String>(0)
            })
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| {
                let p = KdfParams::default();
                let _ = conn.execute(
                    "INSERT OR REPLACE INTO meta (key,value) VALUES ('kdf_params',?1)",
                    rusqlite::params![serde_json::to_string(&p).unwrap_or_default()],
                );
                p
            });

        let key = derive_key(&passphrase, &params)?;

        // A2/#5: verify the KEK sentinel here too, same as new_with_keystore's
        // read_sentinel — otherwise a wrong passphrase derives a wrong key and
        // "unlocks" anyway (no read touches the DB until a caller queries
        // encrypted data, by which point the wrong key already looked fine).
        // First run (no sentinel row yet) provisions it under the new key.
        match conn.query_row::<String, _, _>(
            "SELECT value FROM meta WHERE key='kek_check'",
            [],
            |r| r.get(0),
        ) {
            Ok(ct) => {
                if db::store::dec_text(&key, &ct)? != "ok" {
                    return Err(GuardError::WrongPassphrase);
                }
            }
            Err(_) => {
                // A2 legacy-vault follow-up: an absent sentinel is NOT always
                // first-run — a vault created by a pre-A2 build has real
                // ciphertext (ecdh_sk_enc / totp seeds / vault items / ss:
                // secure-store rows) but never got a kek_check row. Blindly
                // provisioning here would bake the sentinel in under a WRONG
                // derived key, and every later open with the RIGHT passphrase
                // would then fail forever (permanent lockout of a vault whose
                // data is fine). Validate the derived key against whatever
                // ciphertext already exists first; only provision blind when
                // the vault is genuinely empty.
                verify_key_against_existing_ciphertext(&conn, &key)?;
                let ct = db::store::enc_text(&key, "ok")?;
                conn.execute(
                    "INSERT OR REPLACE INTO meta (key,value) VALUES ('kek_check',?1)",
                    rusqlite::params![ct],
                )?;
            }
        }

        // Upgrade any pre-encryption rows (cleartext label/issuer/kind) to the
        // column-level encrypted form. Idempotent; no-op once migrated.
        db::store::migrate_plaintext_metadata(&conn, &key)?;

        // The remote-wipe latch is DURABLE: persisted in meta so a force-quit +
        // relaunch cannot resurrect a wiped device. Read it back at open time.
        let wiped = conn
            .query_row("SELECT value FROM meta WHERE key='wiped'", [], |r| {
                r.get::<_, String>(0)
            })
            .map(|v| v == "1")
            .unwrap_or(false);

        Ok(Arc::new(GuardCore {
            conn: Mutex::new(conn),
            key: Zeroizing::new(key),
            state: Mutex::new(DeviceState {
                device_id: None,
                mam_policy: None,
                wipe_requested: wiped,
                took_device_fallback: false,
            }),
        }))
    }

    pub fn add_totp_account(&self, uri: String) -> Result<String, GuardError> {
        let parsed = totp::parser::parse_otpauth_uri(&uri)?;
        let id = uuid::Uuid::new_v4().to_string();
        let seed = parsed.totp.get_secret_base32();
        let conn = self
            .conn
            .lock()
            .map_err(|_| GuardError::Database("lock".into()))?;
        db::store::insert_totp(
            &conn,
            &self.key,
            &id,
            &parsed.label,
            &parsed.issuer,
            &uri,
            &seed,
        )?;
        Ok(id)
    }

    pub fn generate_totp(&self, account_id: String) -> Result<TotpCode, GuardError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GuardError::Database("lock".into()))?;
        let uri = db::store::get_totp_uri(&conn, &self.key, &account_id)?;
        let parsed = totp::parser::parse_otpauth_uri(&uri)?;
        totp::engine::generate(&parsed.totp)
    }

    pub fn list_accounts(&self) -> Result<Vec<TotpAccount>, GuardError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GuardError::Database("lock".into()))?;
        db::store::list_totp_accounts(&conn, &self.key)
    }

    pub fn remove_account(&self, account_id: String) -> Result<(), GuardError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GuardError::Database("lock".into()))?;
        db::store::delete_totp(&conn, &account_id)
    }

    pub fn get_or_create_ecdh_public_key(&self) -> Result<Vec<u8>, GuardError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GuardError::Database("lock".into()))?;
        if let Ok(enc_sk) = conn.query_row::<Vec<u8>, _, _>(
            "SELECT value FROM meta WHERE key='ecdh_sk_enc'",
            [],
            |r| r.get(0),
        ) {
            let sk_der = db::store::decrypt(&self.key, &enc_sk)?;
            let sk = p256::SecretKey::from_pkcs8_der(&sk_der)
                .map_err(|e| GuardError::Crypto(e.to_string()))?;
            let pk_der = sk
                .public_key()
                .to_public_key_der()
                .map_err(|e| GuardError::Crypto(e.to_string()))?;
            return Ok(pk_der.as_bytes().to_vec());
        }
        let (sk_der, pk_der) = ecdh::generate_keypair()?;
        let enc_sk = db::store::encrypt(&self.key, &sk_der)?;
        conn.execute(
            "INSERT OR REPLACE INTO meta (key,value) VALUES ('ecdh_sk_enc',?1)",
            rusqlite::params![enc_sk],
        )?;
        Ok(pk_der)
    }

    /// The device's ECDH public key as **raw 65-byte uncompressed SEC1**
    /// (`0x04‖X‖Y`), hex-encoded — the exact form authserver's `EncryptECIES`
    /// parses via `ecdh.P256().NewPublicKey` and the golden vector locks
    /// (`docs/standards/PUSH_ECIES_CONTRACT.md`). This is what the device POSTs
    /// as `device_public_key` to `/auth/device/register`, NOT the SPKI/DER that
    /// `get_or_create_ecdh_public_key` returns: `dispatchToNativeDevices` passes
    /// the stored bytes straight to `EncryptECIES` with no DER→raw65 conversion,
    /// so a DER registration would fail the server's key parse. Lazily creates +
    /// persists the keypair on first call (delegates to the getter above, so
    /// both encodings describe the same persisted private key).
    pub fn push_registration_public_key_hex(&self) -> Result<String, GuardError> {
        use p256::elliptic_curve::sec1::ToSec1Point;
        use p256::pkcs8::DecodePublicKey;
        let der = self.get_or_create_ecdh_public_key()?;
        let pk = p256::PublicKey::from_public_key_der(&der)
            .map_err(|e| GuardError::Crypto(e.to_string()))?;
        Ok(hex::encode(pk.to_sec1_point(false).as_bytes()))
    }

    pub fn decrypt_push_challenge(&self, encrypted_payload: Vec<u8>) -> Result<String, GuardError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GuardError::Database("lock".into()))?;
        let enc_sk: Vec<u8> = conn
            .query_row("SELECT value FROM meta WHERE key='ecdh_sk_enc'", [], |r| {
                r.get(0)
            })
            .map_err(|_| {
                GuardError::Crypto("no ECDH key — call get_or_create_ecdh_public_key first".into())
            })?;
        let sk_der = db::store::decrypt(&self.key, &enc_sk)?;
        let plain = ecdh::decrypt_ecies(&sk_der, &encrypted_payload)?;
        String::from_utf8(plain).map_err(|e| GuardError::Crypto(e.to_string()))
    }

    /// Build and sign the closed push-approval assertion. The caller supplies
    /// values from the ECIES-authenticated native notification; it cannot ask
    /// this API to sign an arbitrary byte string or another protocol envelope.
    pub fn sign_push_approval(
        &self,
        assertion: PushApprovalAssertion,
    ) -> Result<String, GuardError> {
        let mut envelope = BTreeMap::new();
        envelope.insert("code", serde_json::json!(assertion.code));
        envelope.insert("decision", serde_json::json!("approve"));
        envelope.insert("device_id", serde_json::json!(assertion.device_id));
        envelope.insert("expires_at", serde_json::json!(assertion.expires_at));
        envelope.insert("issued_at", serde_json::json!(assertion.issued_at));
        envelope.insert("nonce", serde_json::json!(assertion.nonce));
        envelope.insert("protocol", serde_json::json!("setjoin.push-approval.v1"));
        envelope.insert("session_id", serde_json::json!(assertion.session_id));
        envelope.insert("user_id", serde_json::json!(assertion.user_id));
        let canonical =
            serde_json::to_vec(&envelope).map_err(|e| GuardError::Crypto(e.to_string()))?;
        let conn = self
            .conn
            .lock()
            .map_err(|_| GuardError::Database("lock".into()))?;
        let enc_sk: Vec<u8> = conn
            .query_row("SELECT value FROM meta WHERE key='ecdh_sk_enc'", [], |r| {
                r.get(0)
            })
            .map_err(|_| GuardError::Crypto("no push device key is registered".into()))?;
        let private_key = db::store::decrypt(&self.key, &enc_sk)?;
        let signature = ecdh::sign_push_approval(&private_key, &canonical)?;
        Ok(URL_SAFE_NO_PAD.encode(signature))
    }

    /// Secure key/value get — returns the decrypted value, or `None` if absent.
    /// Backs the desktop/mobile `secureStore` bridge: small tokens persisted
    /// AES-256-GCM-encrypted in the vault, readable only while unlocked.
    pub fn meta_get(&self, key: String) -> Result<Option<String>, GuardError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GuardError::Database("lock".into()))?;
        db::store::meta_get(&conn, &self.key, &key)
    }

    /// Secure key/value set — encrypts and persists the value, overwriting any prior entry.
    pub fn meta_set(&self, key: String, value: String) -> Result<(), GuardError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GuardError::Database("lock".into()))?;
        db::store::meta_set(&conn, &self.key, &key, &value)
    }

    /// Secure key/value remove — deletes the value if present.
    pub fn meta_delete(&self, key: String) -> Result<(), GuardError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GuardError::Database("lock".into()))?;
        db::store::meta_delete(&conn, &key)
    }
}

// ── Device / MAM state + vault wipe (non-UniFFI) ────────────────────────
//
// In-memory state for the C2 `mam.rs` lifecycle. guard-core only caches
// these values; the device checkin / policy fetch that produces them is
// HTTP owned by the platform bridge, not this crate.

impl GuardCore {
    /// Provision a per-store SQLCipher key for `app_key` ('mail', 'drive', …),
    /// scoped so distinct apps get distinct keys. Biometric-gated upstream; the
    /// 32 bytes are consumed IN-PROCESS by offline-core's PRAGMA key and NEVER
    /// returned to JS or over the bridge.
    ///
    /// ponytail: not in the #[uniffi::export] block — intentional; key must not
    /// cross the bridge as a UniFFI return value. offline-core calls this in-process.
    pub fn provision_store_key(&self, app_key: &str) -> Result<[u8; 32], GuardError> {
        // self.key is the vault key derived from passphrase (Argon2id) or
        // unwrapped from the platform secure element (Secure Enclave / StrongBox
        // / HUKS / freedesktop Secret Service) under a biometric gate.
        // Derive a per-appKey subkey via HKDF-SHA256 so 'mail' and 'drive' are
        // independently keyed and neither reveals the vault root.
        Ok(derive_subkey(&self.key, app_key.as_bytes()))
    }

    /// Stable per-vault id (random, persisted in meta on first read) — the
    /// SecureStore alias. NOT hash(db_path): container paths move on restore.
    pub fn vault_alias(&self) -> Result<String, GuardError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GuardError::Database("lock".into()))?;
        if let Ok(v) = conn.query_row("SELECT value FROM meta WHERE key='vault_id'", [], |r| {
            r.get::<_, String>(0)
        }) {
            return Ok(v);
        }
        use rand::Rng;
        let mut b = [0u8; 16];
        rand::rng().fill_bytes(&mut b); // vault_id is a public random id, not key material
        let id = hex::encode(b);
        conn.execute(
            "INSERT OR REPLACE INTO meta (key,value) VALUES ('vault_id',?1)",
            rusqlite::params![id],
        )?;
        Ok(id)
    }

    /// Construct with a key obtained OUT-OF-BAND (keystore unwrap), skipping the
    /// passphrase KDF. Refuses on the wipe latch. NOT #[uniffi::export].
    pub fn new_with_key(db_path: String, key: [u8; 32]) -> Result<Arc<Self>, GuardError> {
        let conn = Connection::open(&db_path)?;
        db::schema::apply_migrations(&conn)?;
        if conn
            .query_row("SELECT value FROM meta WHERE key='wiped'", [], |r| {
                r.get::<_, String>(0)
            })
            .ok()
            .as_deref()
            == Some("1")
        {
            return Err(GuardError::Wiped); // wiped latch blocks keystore open — recover via reprovision() (Task 5b), NOT NotFound (#7)
        }
        Ok(Arc::new(Self {
            conn: Mutex::new(conn),
            key: Zeroizing::new(key),
            state: Mutex::new(DeviceState {
                device_id: None,
                mam_policy: None,
                wipe_requested: false,
                took_device_fallback: false,
            }),
        }))
    }

    /// Model M default open (design B). First run: random key → device-unlock wrap
    /// (`kek_wrapped`, ALWAYS the recovery root) + tier tag + RAW encrypted sentinel.
    /// Reopen: try the active tier's wrap; on biometric Invalidated/Unavailable fall
    /// back to `kek_wrapped`, drop the dead bio wrap, record tier=device, flag it.
    /// NOT #[uniffi::export].
    pub fn new_with_keystore(
        db_path: String,
        store: &dyn SecureStore,
        reason: &str,
    ) -> Result<Arc<Self>, GuardError> {
        use crate::securestore::SecureStoreError as S;
        // Single peek: latch + tier + ALL THREE wraps + alias, one connection (DRY, #10).
        let peek = {
            let conn = Connection::open(&db_path)?;
            db::schema::apply_migrations(&conn)?;
            if conn
                .query_row("SELECT value FROM meta WHERE key='wiped'", [], |r| {
                    r.get::<_, String>(0)
                })
                .ok()
                .as_deref()
                == Some("1")
            {
                return Err(GuardError::Wiped); // recover via reprovision() (Task 5b)
            }
            let g = |k: &str| {
                conn.query_row(
                    &format!("SELECT value FROM meta WHERE key='{k}'"),
                    [],
                    |r| r.get::<_, String>(0),
                )
                .ok()
            };
            (
                g("kek_wrapped"),
                g("kek_bio_wrapped"),
                g("kek_domain_wrapped"),
                g("kek_tier"),
                g("vault_id"),
            )
        };
        let (device_hex, bio_hex, domain_hex, tier_tag, alias) = peek;

        // Re-open path: ANY wrap present ⇒ provisioned (a domain switch removes kek_wrapped,
        // so keying on device_hex alone would wrongly fall into first-run re-keying — #1 BLOCKER).
        if let (Some(tag), Some(alias)) = (tier_tag, alias) {
            if device_hex.is_some() || bio_hex.is_some() || domain_hex.is_some() {
                let tier = KeyTier::from_tag(&tag)
                    .ok_or_else(|| GuardError::Crypto("bad kek_tier".into()))?;
                let decode =
                    |h: &str| hex::decode(h).map_err(|e| GuardError::Crypto(e.to_string()));
                let mut fell_back = false;
                let key = match tier {
                    KeyTier::Biometric => match bio_hex {
                        // biometric wrap present: try it, fall back to the always-present device wrap
                        Some(bio) => {
                            match store.unwrap(&alias, &decode(&bio)?, KeyTier::Biometric, reason) {
                                Ok(k) => Zeroizing::new(k),
                                Err(S::Invalidated) | Err(S::Unavailable) => {
                                    // design B: device-unlock fallback
                                    fell_back = true;
                                    let dev = device_hex.as_ref().ok_or_else(|| {
                                        GuardError::Crypto("no device recovery wrap".into())
                                    })?;
                                    Zeroizing::new(store.unwrap(
                                        &alias,
                                        &decode(dev)?,
                                        KeyTier::DeviceUnlock,
                                        reason,
                                    )?)
                                }
                                Err(e) => return Err(e.into()), // Cancelled → BiometricCancelled
                            }
                        }
                        // tier says biometric but the bio wrap is gone: recover via the device wrap (#8)
                        None => {
                            fell_back = true;
                            let dev = device_hex.as_ref().ok_or_else(|| {
                                GuardError::Crypto("no device recovery wrap".into())
                            })?;
                            Zeroizing::new(store.unwrap(
                                &alias,
                                &decode(dev)?,
                                KeyTier::DeviceUnlock,
                                reason,
                            )?)
                        }
                    },
                    KeyTier::DomainSso => {
                        // domain wrap ONLY — no device fallback (off-domain lockout is the point)
                        let dom = domain_hex.as_ref().ok_or_else(|| {
                            GuardError::Crypto("domain tier without domain wrap".into())
                        })?;
                        Zeroizing::new(store.unwrap(
                            &alias,
                            &decode(dom)?,
                            KeyTier::DomainSso,
                            reason,
                        )?) // Unavailable off-domain → SecureStoreUnavailable, NOT re-provision
                    }
                    KeyTier::DeviceUnlock => {
                        let dev = device_hex
                            .as_ref()
                            .ok_or_else(|| GuardError::Crypto("no device wrap".into()))?;
                        Zeroizing::new(store.unwrap(
                            &alias,
                            &decode(dev)?,
                            KeyTier::DeviceUnlock,
                            reason,
                        )?)
                    }
                };
                let guard = Self::new_with_key(db_path, *key)?;
                // fail-fast: raw sentinel must decrypt under the unwrapped key.
                match guard.read_sentinel() {
                    Ok(true) => {}
                    Ok(false) | Err(GuardError::WrongPassphrase) => {
                        return Err(GuardError::Crypto("keystore key mismatch".into()))
                    } // #8: dec failure surfaces as WrongPassphrase
                    Err(e) => return Err(e),
                }
                if fell_back {
                    // drop the dead bio wrap + record device tier (inline — no forward dep on Task 6's set_unlock_tier, #4)
                    guard.drop_bio_wrap_to_device()?;
                    guard
                        .state
                        .lock()
                        .map_err(|_| GuardError::Database("lock".into()))?
                        .took_device_fallback = true;
                }
                return Ok(guard);
            }
        }

        // First-run provisioning: random key, device-unlock wrap.
        use rand::Rng;
        let mut key = Zeroizing::new([0u8; 32]); // SR5
        rand::rng().fill_bytes(&mut *key);
        let guard = Self::new_with_key(db_path, *key)?;
        guard.write_sentinel()?; // write sentinel BEFORE the wrap (#11: absent sentinel on reopen ⇒ provision-incomplete)
        guard.persist_wrapped_key(store, KeyTier::DeviceUnlock)?;
        Ok(guard)
    }

    pub fn took_device_fallback(&self) -> bool {
        self.state
            .lock()
            .map(|s| s.took_device_fallback)
            .unwrap_or(false)
    }

    /// Wrap self.key at `tier` into the tier's OWN slot + set the active-tier tag.
    /// EXPLICIT 3-arm match (no `_` catch-all) so a domain wrap can never land in the
    /// device slot and masquerade as the recovery root (#5). `kek_wrapped` is never
    /// touched by a Biometric call (design B: biometric ADDS kek_bio_wrapped); the
    /// device/domain replace-vs-keep policy lives in set_unlock_tier (Task 6).
    fn persist_wrapped_key(
        &self,
        store: &dyn SecureStore,
        tier: KeyTier,
    ) -> Result<(), GuardError> {
        let alias = self.vault_alias()?;
        let blob = store.wrap(&alias, &self.key, tier)?;
        let slot = match tier {
            KeyTier::DeviceUnlock => "kek_wrapped",
            KeyTier::Biometric => "kek_bio_wrapped",
            KeyTier::DomainSso => "kek_domain_wrapped",
        };
        let conn = self
            .conn
            .lock()
            .map_err(|_| GuardError::Database("lock".into()))?;
        conn.execute(
            &format!("INSERT OR REPLACE INTO meta (key,value) VALUES ('{slot}',?1)"),
            rusqlite::params![hex::encode(&blob)],
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO meta (key,value) VALUES ('kek_tier',?1)",
            rusqlite::params![tier.as_tag()],
        )?;
        Ok(())
    }

    /// Invalidation fallback: the device wrap already recovered self.key, so just drop
    /// the dead bio wrap and record device tier. No re-wrap, no forward dep on Task 6 (#4).
    fn drop_bio_wrap_to_device(&self) -> Result<(), GuardError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GuardError::Database("lock".into()))?;
        conn.execute("DELETE FROM meta WHERE key='kek_bio_wrapped'", [])?;
        conn.execute(
            "INSERT OR REPLACE INTO meta (key,value) VALUES ('kek_tier','device')",
            [],
        )?;
        Ok(())
    }

    /// Raw sentinel OUTSIDE the ss: KV namespace (#4). enc_text/dec_text are the same
    /// AEAD helpers meta_set uses, but the row key is a bare 'kek_check' a bridge can't reach.
    fn write_sentinel(&self) -> Result<(), GuardError> {
        let ct = crate::db::store::enc_text(&self.key, "ok")?;
        let conn = self
            .conn
            .lock()
            .map_err(|_| GuardError::Database("lock".into()))?;
        conn.execute(
            "INSERT OR REPLACE INTO meta (key,value) VALUES ('kek_check',?1)",
            rusqlite::params![ct],
        )?;
        Ok(())
    }
    fn read_sentinel(&self) -> Result<bool, GuardError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GuardError::Database("lock".into()))?;
        let ct: String =
            match conn.query_row("SELECT value FROM meta WHERE key='kek_check'", [], |r| {
                r.get(0)
            }) {
                Ok(v) => v,
                Err(_) => return Ok(false), // absent ⇒ provision-incomplete / mismatch
            };
        Ok(crate::db::store::dec_text(&self.key, &ct)? == "ok") // dec failure → WrongPassphrase, caught by caller (#8)
    }

    #[cfg(test)]
    pub(crate) fn exported_key_for_test(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn store_device_id(&self, device_id: String) {
        self.state.lock().unwrap().device_id = Some(device_id);
    }

    pub fn store_mam_policy(&self, policy: MamPolicy) {
        self.state.lock().unwrap().mam_policy = Some(policy);
    }

    pub fn get_mam_policy(&self) -> Option<MamPolicy> {
        self.state.lock().unwrap().mam_policy.clone()
    }

    /// Remote wipe: irreversibly destroy every secret in the vault and latch the
    /// device closed DURABLY. Deletes all TOTP seeds, vault items, the ECDH push
    /// secret key, and every secure-store entry; only the non-secret KDF salt and
    /// the wiped latch survive. The latch is persisted (`meta.wiped`), so a
    /// force-quit + relaunch cannot resurrect access — `new()` reads it back and
    /// `is_wiped()` stays true until `clear_wiped()` on a successful re-enrolment.
    pub fn mark_wiped(&self) -> Result<(), GuardError> {
        {
            let conn = self
                .conn
                .lock()
                .map_err(|_| GuardError::Database("lock".into()))?;
            conn.execute("DELETE FROM totp_accounts", [])?;
            conn.execute("DELETE FROM vault_items", [])?;
            conn.execute("DELETE FROM meta WHERE key <> 'kdf_params'", [])?;
            conn.execute(
                "INSERT OR REPLACE INTO meta (key,value) VALUES ('wiped','1')",
                [],
            )?;
            // secure_delete (set at open) zeroed the freed rows; VACUUM rebuilds the
            // file so no stale ciphertext lingers on the free list, and the WAL
            // checkpoint(TRUNCATE) drops the -wal frames that held the deletes — so
            // the ciphertext is gone from disk, not just logically deleted.
            conn.execute_batch("VACUUM; PRAGMA wal_checkpoint(TRUNCATE);")?;
        }
        self.state
            .lock()
            .map_err(|_| GuardError::Database("lock".into()))?
            .wipe_requested = true;
        Ok(())
    }

    pub fn is_wiped(&self) -> bool {
        self.state.lock().map(|s| s.wipe_requested).unwrap_or(true)
    }

    /// mark_wiped + best-effort clear of the hardware KEK. The meta-wipe (which
    /// deletes kek_wrapped/kek_tier) is authoritative and runs first; clear is best-effort.
    pub fn mark_wiped_with_store(&self, store: &dyn SecureStore) -> Result<(), GuardError> {
        let alias = self.vault_alias().ok();
        self.mark_wiped()?; // authoritative: deletes all meta except kdf_params + sets latch
        if let Some(a) = alias {
            let _ = store.clear(&a);
        }
        Ok(())
    }

    /// Recovery for a wiped or domain-orphaned vault: clear the latch, drop stale
    /// wraps, generate a fresh random key, wrap device-unlock. Caller re-syncs the
    /// (now empty) offline cache + re-enrols server-side secrets. NOT #[uniffi::export].
    pub fn reprovision(db_path: String, store: &dyn SecureStore) -> Result<Arc<Self>, GuardError> {
        {
            let conn = Connection::open(&db_path)?;
            db::schema::apply_migrations(&conn)?;
            // best-effort clear the OLD hardware KEK before we drop its alias (else the domain-orphan
            // path orphans a keystore entry — harmless since its blobs are gone, but tidy).
            if let Ok(old_alias) =
                conn.query_row("SELECT value FROM meta WHERE key='vault_id'", [], |r| {
                    r.get::<_, String>(0)
                })
            {
                let _ = store.clear(&old_alias);
            }
            // Purge ALL old-key state, not just kek_* — in the domain-orphan (non-wiped)
            // path the stale ciphertext (ecdh_sk_enc, ss:* rows, TOTP seeds, vault items)
            // is encrypted under the DEAD key and would poison get_or_create_ecdh_public_key /
            // TOTP forever (#3). Mirror mark_wiped's data purge, minus setting the latch.
            conn.execute("DELETE FROM totp_accounts", [])?;
            conn.execute("DELETE FROM vault_items", [])?;
            conn.execute("DELETE FROM meta WHERE key <> 'kdf_params'", [])?; // also clears 'wiped' latch + vault_id (fresh id follows)
        }
        use rand::Rng;
        let mut key = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(&mut *key);
        let guard = Self::new_with_key(db_path, *key)?; // latch now clear ⇒ succeeds
        guard
            .state
            .lock()
            .map_err(|_| GuardError::Database("lock".into()))?
            .wipe_requested = false;
        guard.write_sentinel()?;
        guard.persist_wrapped_key(store, KeyTier::DeviceUnlock)?;
        Ok(guard)
    }

    /// Re-wrap self.key at `tier` (design B). Caller must already be unlocked.
    ///   Biometric  → ADD kek_bio_wrapped (device recovery wrap kept)
    ///   DeviceUnlock → DELETE kek_bio_wrapped (device wrap kept), tier=device
    ///   DomainSso  → REPLACE: write kek_domain_wrapped, DELETE kek_wrapped + kek_bio_wrapped (off-domain lockout, no fallback)
    pub fn set_unlock_tier(
        &self,
        store: &dyn SecureStore,
        tier: KeyTier,
    ) -> Result<(), GuardError> {
        if !store.available(tier) {
            return Err(GuardError::SecureStoreUnavailable);
        }
        match tier {
            KeyTier::Biometric => self.persist_wrapped_key(store, KeyTier::Biometric)?, // adds kek_bio_wrapped + tier tag
            KeyTier::DeviceUnlock => {
                // ensure a device wrap exists (it always should), then drop the bio wrap
                self.persist_wrapped_key(store, KeyTier::DeviceUnlock)?;
                let conn = self
                    .conn
                    .lock()
                    .map_err(|_| GuardError::Database("lock".into()))?;
                conn.execute("DELETE FROM meta WHERE key='kek_bio_wrapped'", [])?;
            }
            KeyTier::DomainSso => {
                self.persist_wrapped_key(store, KeyTier::DomainSso)?; // writes kek_domain_wrapped + tier=domain (single write path, #5)
                let conn = self
                    .conn
                    .lock()
                    .map_err(|_| GuardError::Database("lock".into()))?;
                conn.execute(
                    "DELETE FROM meta WHERE key IN ('kek_wrapped','kek_bio_wrapped')",
                    [],
                )?; // REPLACE: off-domain lockout
            }
        }
        Ok(())
    }

    /// Clear the wipe latch after a successful re-enrolment (a fresh device
    /// checkin with valid credentials). Without this a wiped device would be
    /// permanently bricked even for its legitimate owner.
    pub fn clear_wiped(&self) -> Result<(), GuardError> {
        {
            let conn = self
                .conn
                .lock()
                .map_err(|_| GuardError::Database("lock".into()))?;
            conn.execute("DELETE FROM meta WHERE key='wiped'", [])?;
        }
        self.state
            .lock()
            .map_err(|_| GuardError::Database("lock".into()))?
            .wipe_requested = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_alias_is_stable_and_random() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("guard.db").to_string_lossy().to_string();
        let g = GuardCore::new(db.clone(), "pw".into()).unwrap();
        let a1 = g.vault_alias().unwrap();
        let a2 = g.vault_alias().unwrap();
        assert_eq!(a1, a2, "alias stable within a vault");
        assert!(a1.len() >= 16, "alias is a real random id, not a path");
    }

    #[test]
    fn new_with_key_opens_same_vault_as_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("guard.db").to_string_lossy().to_string();
        let g = GuardCore::new(db.clone(), "pw".into()).unwrap();
        g.meta_set("probe".into(), "hi".into()).unwrap();
        let key = *g.exported_key_for_test(); // test-only accessor, see Step 2
        drop(g);
        let g2 = GuardCore::new_with_key(db, key).unwrap();
        assert_eq!(g2.meta_get("probe".into()).unwrap().as_deref(), Some("hi"));
    }

    #[test]
    fn new_rejects_wrong_passphrase_right_one_still_unlocks() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("guard.db").to_string_lossy().to_string();
        {
            // first run: provisions under "right-pw"
            let g = GuardCore::new(db.clone(), "right-pw".into()).unwrap();
            g.meta_set("probe".into(), "hi".into()).unwrap();
        }
        // A2/#5: new() must verify the KEK sentinel like new_with_keystore does —
        // a wrong passphrase derives a wrong key and must NOT "unlock" anyway.
        assert!(
            matches!(
                GuardCore::new(db.clone(), "wrong-pw".into()),
                Err(GuardError::WrongPassphrase)
            ),
            "wrong passphrase must be rejected, not silently accepted"
        );
        // right passphrase still opens the same vault
        let g2 = GuardCore::new(db, "right-pw".into()).unwrap();
        assert_eq!(g2.meta_get("probe".into()).unwrap().as_deref(), Some("hi"));
    }

    #[test]
    fn legacy_vault_without_sentinel_rejects_wrong_passphrase_and_preserves_right_one() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("guard.db").to_string_lossy().to_string();
        {
            // simulate a pre-A2 build's vault: real ciphertext under "right-pw",
            // but no kek_check row — that sentinel didn't exist before A2.
            let g = GuardCore::new(db.clone(), "right-pw".into()).unwrap();
            g.get_or_create_ecdh_public_key().unwrap(); // real ciphertext under "right-pw"
            let conn = g.conn.lock().unwrap();
            conn.execute("DELETE FROM meta WHERE key='kek_check'", [])
                .unwrap();
        }
        // Blocker repro: a wrong passphrase must be rejected even with no
        // sentinel row present — the vault already holds ciphertext
        // (ecdh_sk_enc) proving what the real key is. Pre-fix this returned
        // Ok and provisioned kek_check under the WRONG key.
        assert!(
            matches!(
                GuardCore::new(db.clone(), "wrong-pw".into()),
                Err(GuardError::WrongPassphrase)
            ),
            "wrong passphrase on a sentinel-less legacy vault must not be accepted"
        );
        // And the legitimate owner must still be able to open it afterward —
        // no permanent lockout from the wrong-passphrase attempt above.
        let g2 = GuardCore::new(db, "right-pw".into()).unwrap();
        assert!(g2.get_or_create_ecdh_public_key().is_ok());
    }

    #[test]
    fn pre_a2_totp_only_vault_rejects_wrong_passphrase_and_never_provisions_sentinel() {
        // D-CLIENTS-RUST-GUARD-CORE-P1-001 exact repro: a sentinel-less pre-A2
        // vault whose ONLY ciphertext is totp_accounts (seed_enc/uri_enc), with
        // no metadata_enc flag (migrate_plaintext_metadata never ran) and label
        // still legacy cleartext, so no pre-existing probe could verify the key.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("guard.db").to_string_lossy().to_string();
        {
            let g = GuardCore::new(db.clone(), "right-pw".into()).unwrap();
            g.add_totp_account("otpauth://totp/x?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".into())
                .unwrap();
            let conn = g.conn.lock().unwrap();
            // Strip back to the pre-A2 shape: cleartext label, no sentinel, no
            // migration flag.
            conn.execute("UPDATE totp_accounts SET label='GitHub', issuer=''", [])
                .unwrap();
            conn.execute(
                "DELETE FROM meta WHERE key IN ('kek_check','metadata_enc')",
                [],
            )
            .unwrap();
        }
        // Pre-fix this returned Ok(()) unchecked and provisioned kek_check under
        // the WRONG key — every later open with the right passphrase failed.
        assert!(
            matches!(
                GuardCore::new(db.clone(), "wrong-pw".into()),
                Err(GuardError::WrongPassphrase)
            ),
            "wrong passphrase on a TOTP-only sentinel-less vault must be rejected"
        );
        // The rejected attempt must never write the sentinel.
        {
            let conn = Connection::open(&db).unwrap();
            assert!(
                conn.query_row("SELECT value FROM meta WHERE key='kek_check'", [], |r| {
                    r.get::<_, String>(0)
                })
                .is_err(),
                "a failed wrong-passphrase open must not provision kek_check"
            );
        }
        // The rightful owner still opens the vault, and the data is intact.
        let g2 = GuardCore::new(db, "right-pw".into()).unwrap();
        let accounts = g2.list_accounts().unwrap();
        assert_eq!(accounts.len(), 1, "TOTP data survives the wrong-pw attempt");
        assert!(g2.generate_totp(accounts[0].id.clone()).is_ok());
    }

    #[test]
    fn pre_a2_vault_items_only_vault_rejects_wrong_passphrase_and_never_provisions_sentinel() {
        // Same P1 shape with vault_items.data_enc as the only ciphertext: the
        // blob column is raw AES-256-GCM from the row's first write even while
        // `kind` is still legacy cleartext, so it must verify the key.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("guard.db").to_string_lossy().to_string();
        {
            let g = GuardCore::new(db.clone(), "right-pw".into()).unwrap();
            let key = *g.exported_key_for_test();
            let conn = g.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO vault_items (id,kind,data_enc) VALUES ('i1','note',?1)",
                rusqlite::params![db::store::encrypt(&key, b"secret note").unwrap()],
            )
            .unwrap();
            conn.execute(
                "DELETE FROM meta WHERE key IN ('kek_check','metadata_enc')",
                [],
            )
            .unwrap();
        }
        assert!(
            matches!(
                GuardCore::new(db.clone(), "wrong-pw".into()),
                Err(GuardError::WrongPassphrase)
            ),
            "wrong passphrase on a vault-items-only sentinel-less vault must be rejected"
        );
        {
            let conn = Connection::open(&db).unwrap();
            assert!(
                conn.query_row("SELECT value FROM meta WHERE key='kek_check'", [], |r| {
                    r.get::<_, String>(0)
                })
                .is_err(),
                "a failed wrong-passphrase open must not provision kek_check"
            );
        }
        // Right passphrase opens; the sentinel is (re)provisioned under it.
        let g2 = GuardCore::new(db, "right-pw".into()).unwrap();
        let conn = g2.conn.lock().unwrap();
        assert!(
            conn.query_row("SELECT value FROM meta WHERE key='kek_check'", [], |r| {
                r.get::<_, String>(0)
            })
            .is_ok(),
            "right passphrase provisions the sentinel"
        );
    }

    #[test]
    fn genuinely_empty_vault_keeps_first_run_sentinel_provisioning() {
        // A proven-empty vault (zero ciphertext rows anywhere) still initializes
        // on first run and provisions kek_check under the passphrase given —
        // the empty-vault arm the unlock gate must keep open.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("guard.db").to_string_lossy().to_string();
        {
            let g = GuardCore::new(db.clone(), "first-pw".into()).unwrap();
            let conn = g.conn.lock().unwrap();
            assert!(
                conn.query_row("SELECT value FROM meta WHERE key='kek_check'", [], |r| {
                    r.get::<_, String>(0)
                })
                .is_ok(),
                "first run provisions the sentinel"
            );
            let ciphertext_shapes: i64 = conn
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM totp_accounts)
                     + (SELECT COUNT(*) FROM vault_items)
                     + (SELECT COUNT(*) FROM meta WHERE key='ecdh_sk_enc' OR key LIKE 'ss:%')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                ciphertext_shapes, 0,
                "fixture must be a genuinely empty, ciphertext-free vault"
            );
        }
        assert!(
            GuardCore::new(db.clone(), "first-pw".into()).is_ok(),
            "same passphrase reopens the first-run vault"
        );
        assert!(matches!(
            GuardCore::new(db, "second-pw".into()),
            Err(GuardError::WrongPassphrase)
        ));
    }

    #[test]
    fn sentinel_less_vault_fails_closed_for_every_a2_named_ciphertext_shape() {
        // Migration-path regression: the A2 comment names the ciphertext shapes a
        // sentinel-less pre-A2 vault may hold — ecdh_sk_enc / totp seeds /
        // vault items / ss: secure-store rows — plus label/kind once migrated.
        // For EACH shape a wrong passphrase must fail closed and the right one
        // must still open and provision the sentinel.
        let shapes = [
            "ecdh_sk_enc",
            "ss_row",
            "totp_seed",
            "vault_item",
            "migrated_totp",
            "migrated_vault_item",
        ];
        for shape in shapes {
            let dir = tempfile::tempdir().unwrap();
            let db = dir.path().join("guard.db").to_string_lossy().to_string();
            {
                let g = GuardCore::new(db.clone(), "right-pw".into()).unwrap();
                let key = *g.exported_key_for_test();
                // Public-API writes run BEFORE the conn lock is taken: they lock
                // the same (non-reentrant) mutex internally, so holding the guard
                // across them deadlocks the test.
                if matches!(shape, "totp_seed" | "migrated_totp") {
                    g.add_totp_account(
                        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".into(),
                    )
                    .unwrap();
                }
                let conn = g.conn.lock().unwrap();
                match shape {
                    "ecdh_sk_enc" => {
                        conn.execute(
                            "INSERT OR REPLACE INTO meta (key,value) VALUES ('ecdh_sk_enc',?1)",
                            rusqlite::params![db::store::encrypt(&key, b"sk-der").unwrap()],
                        )
                        .unwrap();
                        conn.execute("DELETE FROM meta WHERE key='metadata_enc'", [])
                            .unwrap();
                    }
                    "ss_row" => {
                        conn.execute(
                            "INSERT OR REPLACE INTO meta (key,value) VALUES ('ss:device-token',?1)",
                            rusqlite::params![db::store::enc_text(&key, "token").unwrap()],
                        )
                        .unwrap();
                        conn.execute("DELETE FROM meta WHERE key='metadata_enc'", [])
                            .unwrap();
                    }
                    "totp_seed" => {
                        // Reset label/issuer to the legacy cleartext form so the
                        // seed blob is the only valid probe (pre-migration shape).
                        conn.execute("UPDATE totp_accounts SET label='svc', issuer=''", [])
                            .unwrap();
                        conn.execute("DELETE FROM meta WHERE key='metadata_enc'", [])
                            .unwrap();
                    }
                    "vault_item" => {
                        conn.execute(
                            "INSERT INTO vault_items (id,kind,data_enc) VALUES ('i1','note',?1)",
                            rusqlite::params![db::store::encrypt(&key, b"note").unwrap()],
                        )
                        .unwrap();
                        conn.execute("DELETE FROM meta WHERE key='metadata_enc'", [])
                            .unwrap();
                    }
                    "migrated_totp" => {
                        // metadata_enc='1' stays set (new() ran the migration); the
                        // label/seed ciphertext comes from the real write path.
                    }
                    "migrated_vault_item" => {
                        conn.execute(
                            "INSERT INTO vault_items (id,kind,data_enc) VALUES ('i2',?1,?2)",
                            rusqlite::params![
                                db::store::enc_text(&key, "note").unwrap(),
                                db::store::encrypt(&key, b"note body").unwrap()
                            ],
                        )
                        .unwrap();
                    }
                    other => unreachable!("unlisted shape {other}"),
                }
                conn.execute("DELETE FROM meta WHERE key='kek_check'", [])
                    .unwrap();
            }
            assert!(
                matches!(
                    GuardCore::new(db.clone(), "wrong-pw".into()),
                    Err(GuardError::WrongPassphrase)
                ),
                "shape {shape}: wrong passphrase must be rejected, not provision a sentinel"
            );
            let g2 = GuardCore::new(db, "right-pw".into()).unwrap();
            let conn = g2.conn.lock().unwrap();
            assert!(
                conn.query_row("SELECT value FROM meta WHERE key='kek_check'", [], |r| {
                    r.get::<_, String>(0)
                })
                .is_ok(),
                "shape {shape}: right passphrase opens and re-provisions the sentinel"
            );
        }
    }

    #[test]
    fn keystore_provisions_then_reopens_silently() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("guard.db").to_string_lossy().to_string();
        let store = crate::securestore::fake::FakeSecureStore::new();
        {
            // first run: provisions a random key at device-unlock tier
            let g = GuardCore::new_with_keystore(db.clone(), &store, "open").unwrap();
            g.meta_set("probe".into(), "hi".into()).unwrap();
            let conn = g.conn.lock().unwrap();
            let tier: String = conn
                .query_row("SELECT value FROM meta WHERE key='kek_tier'", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(tier, "device");
            assert!(conn
                .query_row("SELECT value FROM meta WHERE key='kek_wrapped'", [], |r| {
                    r.get::<_, String>(0)
                })
                .is_ok());
            // sentinel is NOT in the ss: KV namespace (a raw meta row), so a bridge meta_delete can't reach it (#4)
            assert!(conn
                .query_row("SELECT value FROM meta WHERE key='kek_check'", [], |r| {
                    r.get::<_, String>(0)
                })
                .is_ok());
            assert!(conn
                .query_row("SELECT value FROM meta WHERE key='ss:kek_check'", [], |r| r
                    .get::<_, String>(0))
                .is_err());
        }
        let g2 = GuardCore::new_with_keystore(db, &store, "open").unwrap();
        assert_eq!(g2.meta_get("probe".into()).unwrap().as_deref(), Some("hi"));
        assert!(
            !g2.took_device_fallback(),
            "clean device reopen is not a fallback"
        );
    }

    #[test]
    fn keystore_generated_key_is_random_not_passphrase_derived() {
        let dir = tempfile::tempdir().unwrap();
        let db1 = dir.path().join("a.db").to_string_lossy().to_string();
        let db2 = dir.path().join("b.db").to_string_lossy().to_string();
        let store = crate::securestore::fake::FakeSecureStore::new();
        let g1 = GuardCore::new_with_keystore(db1, &store, "open").unwrap();
        let g2 = GuardCore::new_with_keystore(db2, &store, "open").unwrap();
        assert_ne!(
            g1.exported_key_for_test(),
            g2.exported_key_for_test(),
            "each vault gets an independent random key"
        );
    }

    #[test]
    fn reprovision_recovers_a_wiped_vault_with_a_fresh_key() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("guard.db").to_string_lossy().to_string();
        let store = crate::securestore::fake::FakeSecureStore::new();
        let old_key = {
            let g = GuardCore::new_with_keystore(db.clone(), &store, "open").unwrap();
            let k = *g.exported_key_for_test();
            // ponytail: Task 7's mark_wiped_with_store doesn't exist yet — mark_wiped()
            // sets the same durable 'wiped' latch this test needs; upgrade when T7 lands.
            g.mark_wiped().unwrap(); // remote wipe
            k
        };
        // normal open is refused
        assert!(matches!(
            GuardCore::new_with_keystore(db.clone(), &store, "x"),
            Err(GuardError::Wiped)
        ));
        // reprovision recovers with a NEW random key
        let g2 = GuardCore::reprovision(db, &store).unwrap();
        assert!(!g2.is_wiped());
        assert_ne!(
            g2.exported_key_for_test(),
            &old_key,
            "reprovision generates a fresh key"
        );
    }

    #[test]
    fn upgrade_to_biometric_then_reopen_uses_biometric_tier() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("guard.db").to_string_lossy().to_string();
        let store = crate::securestore::fake::FakeSecureStore::new();
        {
            let g = GuardCore::new_with_keystore(db.clone(), &store, "open").unwrap();
            g.meta_set("probe".into(), "hi".into()).unwrap();
            g.set_unlock_tier(&store, KeyTier::Biometric).unwrap();
            let conn = g.conn.lock().unwrap();
            assert_eq!(
                conn.query_row("SELECT value FROM meta WHERE key='kek_tier'", [], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap(),
                "biometric"
            );
            // design B: the device recovery wrap is STILL present alongside the bio wrap
            assert!(conn
                .query_row("SELECT value FROM meta WHERE key='kek_wrapped'", [], |r| {
                    r.get::<_, String>(0)
                })
                .is_ok());
            assert!(conn
                .query_row(
                    "SELECT value FROM meta WHERE key='kek_bio_wrapped'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .is_ok());
        }
        let g2 = GuardCore::new_with_keystore(db, &store, "unlock").unwrap();
        assert_eq!(g2.meta_get("probe".into()).unwrap().as_deref(), Some("hi"));
    }

    #[test]
    fn biometric_invalidation_falls_back_to_device_and_reverts_tier() {
        // THE design-B path: enter biometric tier, invalidate the biometric KEK, reopen.
        // Open must SUCCEED via the device wrap (no data loss), revert to device tier, and flag it.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("guard.db").to_string_lossy().to_string();
        let store = crate::securestore::fake::FakeSecureStore::new();
        {
            let g = GuardCore::new_with_keystore(db.clone(), &store, "open").unwrap();
            g.meta_set("probe".into(), "hi".into()).unwrap();
            g.set_unlock_tier(&store, KeyTier::Biometric).unwrap();
        }
        store.invalidate(); // user added a fingerprint → biometric KEK dead
        let g2 = GuardCore::new_with_keystore(db.clone(), &store, "unlock").unwrap();
        assert_eq!(
            g2.meta_get("probe".into()).unwrap().as_deref(),
            Some("hi"),
            "no data loss — device wrap recovered self.key"
        );
        assert!(g2.took_device_fallback(), "UI is told to offer re-enrol");
        // tier reverted to device + the dead bio wrap was dropped
        let conn = g2.conn.lock().unwrap();
        assert_eq!(
            conn.query_row("SELECT value FROM meta WHERE key='kek_tier'", [], |r| {
                r.get::<_, String>(0)
            })
            .unwrap(),
            "device"
        );
        assert!(conn
            .query_row(
                "SELECT value FROM meta WHERE key='kek_bio_wrapped'",
                [],
                |r| r.get::<_, String>(0)
            )
            .is_err());
    }

    #[test]
    fn domain_tier_replaces_device_wrap() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("guard.db").to_string_lossy().to_string();
        let store = crate::securestore::fake::FakeSecureStore::new();
        let g = GuardCore::new_with_keystore(db, &store, "open").unwrap();
        g.set_unlock_tier(&store, KeyTier::DomainSso).unwrap();
        let conn = g.conn.lock().unwrap();
        assert_eq!(
            conn.query_row("SELECT value FROM meta WHERE key='kek_tier'", [], |r| {
                r.get::<_, String>(0)
            })
            .unwrap(),
            "domain"
        );
        assert!(conn
            .query_row(
                "SELECT value FROM meta WHERE key='kek_domain_wrapped'",
                [],
                |r| r.get::<_, String>(0)
            )
            .is_ok());
        assert!(
            conn.query_row("SELECT value FROM meta WHERE key='kek_wrapped'", [], |r| {
                r.get::<_, String>(0)
            })
            .is_err(),
            "domain replaces device (no fallback — off-domain lockout)"
        );
    }

    #[test]
    fn domain_tier_reopen_uses_domain_wrap_not_reprovision() {
        // #1 regression: after a domain switch, kek_wrapped is gone; reopen MUST unwrap the
        // domain wrap and preserve data — NOT fall through to first-run re-keying.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("guard.db").to_string_lossy().to_string();
        let store = crate::securestore::fake::FakeSecureStore::new();
        let key0 = {
            let g = GuardCore::new_with_keystore(db.clone(), &store, "open").unwrap();
            g.meta_set("probe".into(), "hi".into()).unwrap();
            g.set_unlock_tier(&store, KeyTier::DomainSso).unwrap();
            *g.exported_key_for_test()
        };
        let g2 = GuardCore::new_with_keystore(db.clone(), &store, "open").unwrap();
        assert_eq!(
            g2.exported_key_for_test(),
            &key0,
            "same key recovered via domain wrap, NOT a fresh re-provision"
        );
        assert_eq!(
            g2.meta_get("probe".into()).unwrap().as_deref(),
            Some("hi"),
            "no data loss"
        );
        // off-domain: domain unwrap unavailable → error, still NOT a silent re-provision
        store.set_available(KeyTier::DomainSso, false);
        assert!(matches!(
            GuardCore::new_with_keystore(db, &store, "open"),
            Err(GuardError::SecureStoreUnavailable)
        ));
    }

    #[test]
    fn reopen_wrong_key_fails_fast_with_mismatch_not_wrongpassphrase() {
        struct BadStore;
        impl crate::securestore::SecureStore for BadStore {
            fn wrap(
                &self,
                _a: &str,
                _k: &[u8; 32],
                _t: crate::securestore::KeyTier,
            ) -> Result<Vec<u8>, crate::securestore::SecureStoreError> {
                Ok(vec![1])
            }
            fn unwrap(
                &self,
                _a: &str,
                _b: &[u8],
                _t: crate::securestore::KeyTier,
                _r: &str,
            ) -> Result<[u8; 32], crate::securestore::SecureStoreError> {
                Ok([9u8; 32])
            }
            fn clear(&self, _a: &str) -> Result<(), crate::securestore::SecureStoreError> {
                Ok(())
            }
            fn available(&self, _t: crate::securestore::KeyTier) -> bool {
                true
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("guard.db").to_string_lossy().to_string();
        {
            let _ = GuardCore::new_with_keystore(
                db.clone(),
                &crate::securestore::fake::FakeSecureStore::new(),
                "open",
            )
            .unwrap();
        }
        // garbage key → sentinel dec fails (WrongPassphrase internally) → surfaced as the mismatch Crypto error, not WrongPassphrase (#8)
        // ponytail: .err().unwrap() not .unwrap_err() — GuardCore isn't Debug (holds a
        // rusqlite::Connection), so unwrap_err()'s Ok-side Debug bound won't compile.
        let e = GuardCore::new_with_keystore(db, &BadStore, "x")
            .err()
            .unwrap();
        assert!(
            matches!(e, GuardError::Crypto(ref m) if m.contains("mismatch")),
            "wrong key must fail-fast as key-mismatch, got {e:?}"
        );
    }

    #[test]
    fn reprovision_of_a_non_wiped_vault_purges_stale_old_key_ciphertext() {
        // domain-orphan path: NO wipe preceded, so old-key rows (TOTP/ECDH/ss:*) exist.
        // reprovision must clear them, else get_or_create_ecdh_public_key errors forever (#3).
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("guard.db").to_string_lossy().to_string();
        let store = crate::securestore::fake::FakeSecureStore::new();
        {
            let g = GuardCore::new_with_keystore(db.clone(), &store, "open").unwrap();
            // ponytail: plan's demo secret (JBSWY3DPEHPK3PXP, 80 bits) is rejected by the
            // totp-rs 128-bit-minimum check this repo's parser enforces; doubled to 160 bits.
            g.add_totp_account("otpauth://totp/x?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".into())
                .unwrap();
            g.get_or_create_ecdh_public_key().unwrap(); // writes ecdh_sk_enc under the OLD key
        }
        // reprovision WITHOUT a prior wipe (simulates leaving the domain)
        let g2 = GuardCore::reprovision(db, &store).unwrap();
        assert!(g2.list_accounts().unwrap().is_empty(), "stale TOTP purged");
        // regeneration works: the old ecdh_sk_enc is gone, so this creates a fresh one under the new key
        assert!(
            g2.get_or_create_ecdh_public_key().is_ok(),
            "no stale-ciphertext poison"
        );
    }

    #[test]
    fn wipe_removes_wrapped_key_and_blocks_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("guard.db").to_string_lossy().to_string();
        let store = crate::securestore::fake::FakeSecureStore::new();
        let g = GuardCore::new_with_keystore(db.clone(), &store, "open").unwrap();
        g.mark_wiped_with_store(&store).unwrap();
        assert!(g.is_wiped());
        // reopen refused by the durable latch → Wiped (NOT NotFound — the bridge 'wiped' discriminant, #2/#7)
        assert!(matches!(
            GuardCore::new_with_keystore(db, &store, "x"),
            Err(GuardError::Wiped)
        ));
    }

    #[test]
    fn wipe_still_succeeds_when_clear_errors() {
        struct ErrClear;
        impl SecureStore for ErrClear {
            fn wrap(
                &self,
                _a: &str,
                _k: &[u8; 32],
                _t: KeyTier,
            ) -> Result<Vec<u8>, SecureStoreError> {
                Ok(vec![1])
            }
            fn unwrap(
                &self,
                _a: &str,
                _b: &[u8],
                _t: KeyTier,
                _r: &str,
            ) -> Result<[u8; 32], SecureStoreError> {
                Ok([0u8; 32])
            }
            fn clear(&self, _a: &str) -> Result<(), SecureStoreError> {
                Err(SecureStoreError::Failed("keystore down".into()))
            }
            fn available(&self, _t: KeyTier) -> bool {
                true
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("guard.db").to_string_lossy().to_string();
        let g = GuardCore::new(db, "pw".into()).unwrap(); // legacy ctor is fine; key source is irrelevant to wipe
        g.mark_wiped_with_store(&ErrClear).unwrap(); // clear errs, wipe still succeeds
        assert!(g.is_wiped());
    }

    #[test]
    fn errors_never_contain_key_bytes() {
        // Both the GuardError conversion AND SecureStoreError's own Debug must not embed key bytes.
        let inner = SecureStoreError::Failed(format!("{:?}", [0xABu8; 32]));
        let converted = GuardError::from(SecureStoreError::Failed(format!("{:?}", [0xABu8; 32])));
        let s = format!("{inner:?} {converted} {converted:?}"); // SecureStoreError Debug is hand-written (Task 1) == Display → checks the raw type too (#12)
        assert!(
            !s.contains("171, 171"),
            "error text must not carry key bytes"
        );
        assert!(!s.to_lowercase().contains("ab, ab"));
        // the GuardError conversion drops the inner string entirely (Display + Debug are the static variant text)
        assert!(!format!("{converted} {converted:?}").contains("171"));
    }
}
