//! EK01 column envelope (frozen Go `shared/cryptokey`): 13-byte header
//! (`EK01`, algorithm, key length u32 BE, two zero bytes, nonce length u16 BE),
//! then the nonce, then ciphertext plus the 16-byte GCM tag.
//!
//! The column key is `HKDF-SHA256(secret = master, salt =
//! "mailserver-db-encryption-v1", info = empty)`, 32 bytes for AES-256-GCM and 16 for
//! SM4-GCM (the ticket text calls the domain string "info"; Go passes it as the salt).
//! Error text mirrors Go so callers can compare classes; it never contains key bytes.

use crate::sm4;
use ring::{aead, hkdf, rand::SecureRandom};
use std::fmt;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"EK01";
const HEADER_LEN: usize = 13;
const HKDF_SALT: &[u8] = b"mailserver-db-encryption-v1";
/// HKDF-SHA256 cannot expand beyond 255 blocks; Go reports this as an entropy limit.
const HKDF_MAX: usize = 255 * 32;

/// Crypto profile (`CRYPTO_ALGORITHM_PROFILE`). `Hybrid` seals with AES like `Standard`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoProfile {
    Standard,
    Smx,
    Hybrid,
}

impl CryptoProfile {
    /// Like Go's `ParseCryptoProfile`: anything but `smx`/`hybrid` is `standard`.
    pub fn parse(raw: &str) -> Self {
        match raw {
            "smx" => Self::Smx,
            "hybrid" => Self::Hybrid,
            _ => Self::Standard,
        }
    }

    pub(crate) fn key_len(self) -> usize {
        if self == Self::Smx {
            16
        } else {
            32
        }
    }

    fn algorithm(self) -> u8 {
        if self == Self::Smx {
            1
        } else {
            0
        }
    }
}

/// A Go-compatible envelope failure; `Display` is the frozen Go message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeError(pub(crate) String);

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for EnvelopeError {}

fn err<T>(msg: impl Into<String>) -> Result<T, EnvelopeError> {
    Err(EnvelopeError(msg.into()))
}

struct Len(usize);
impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn derive(master: &[u8], len: usize) -> Option<Zeroizing<Vec<u8>>> {
    if len > HKDF_MAX {
        return None;
    }
    // Go: hkdf.New(sha256.New, secret, salt = "mailserver-db-encryption-v1", info = nil).
    // The domain string is the HKDF *salt*; the info input is empty.
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, HKDF_SALT).extract(master);
    let okm = prk.expand(&[], Len(len)).ok()?;
    let mut out = Zeroizing::new(vec![0u8; len]);
    okm.fill(&mut out).ok()?;
    Some(out)
}

/// `%q` of the four magic bytes as Go prints them.
fn quote_bytes(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    let mut rest = bytes;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                push_escaped(&mut out, s);
                break;
            }
            Err(e) => {
                let (good, bad) = rest.split_at(e.valid_up_to());
                push_escaped(&mut out, std::str::from_utf8(good).unwrap_or(""));
                let skip = e.error_len().unwrap_or(bad.len());
                for b in &bad[..skip] {
                    out.push_str(&format!("\\x{b:02x}"));
                }
                rest = &bad[skip..];
            }
        }
    }
    out.push('"');
    out
}

/// Go `strconv.Quote` body for valid UTF-8.
pub(crate) fn push_escaped(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\x0b' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c if c.is_control() => {
                if (c as u32) < 0x10000 {
                    out.push_str(&format!("\\u{:04x}", c as u32))
                } else {
                    out.push_str(&format!("\\U{:08x}", c as u32))
                }
            }
            c => out.push(c),
        }
    }
}

/// Seal with a fresh random 12-byte nonce.
pub(crate) fn seal(
    profile: CryptoProfile,
    master: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let mut nonce = [0u8; 12];
    ring::rand::SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| EnvelopeError("envelope: nonce generation failed".into()))?;
    seal_with_nonce(profile, master, &nonce, plaintext, aad)
}

pub(crate) fn seal_with_nonce(
    profile: CryptoProfile,
    master: &[u8],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    let key_len = profile.key_len();
    let key = derive(master, key_len)
        .ok_or_else(|| EnvelopeError("cryptokey: key derivation failed".into()))?;
    let algo = profile.algorithm();
    let sealed = if algo == 1 {
        let cipher = sm4::Sm4::new(&key)
            .ok_or_else(|| EnvelopeError("envelope: cipher init failed".into()))?;
        sm4::seal(&cipher, nonce, plaintext, aad)
    } else {
        let mut buf = plaintext.to_vec();
        let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &key)
            .map_err(|_| EnvelopeError("envelope: cipher init failed".into()))?;
        aead::LessSafeKey::new(unbound)
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(*nonce),
                aead::Aad::from(aad),
                &mut buf,
            )
            .map_err(|_| EnvelopeError("envelope: encryption failed".into()))?;
        buf
    };
    let mut out = Vec::with_capacity(HEADER_LEN + 12 + sealed.len());
    out.extend_from_slice(MAGIC);
    out.push(algo);
    out.extend_from_slice(&(key_len as u32).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&12u16.to_be_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Go `DecryptColumnWithAAD`: the header names the algorithm and key length, and
/// the column key is re-derived from the master secret at that length.
pub(crate) fn open(envelope: &[u8], master: &[u8], aad: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    if envelope.len() < HEADER_LEN {
        return err(format!(
            "cryptokey: column ciphertext too short ({} bytes)",
            envelope.len()
        ));
    }
    let key_len = u32::from_be_bytes([envelope[5], envelope[6], envelope[7], envelope[8]]) as usize;
    // Go allocates key_len bytes before HKDF rejects it; refuse oversize first.
    let key = derive(master, key_len).ok_or_else(|| {
        EnvelopeError("cryptokey: key derivation failed: hkdf: entropy limit reached".into())
    })?;
    if &envelope[0..4] != MAGIC {
        return err(format!(
            "envelope: bad magic {}",
            quote_bytes(&envelope[0..4])
        ));
    }
    if envelope[9] != 0 || envelope[10] != 0 {
        return err("envelope: reserved bytes must be zero");
    }
    let nonce_len = u16::from_be_bytes([envelope[11], envelope[12]]) as usize;
    let algo = envelope[4];
    enum Cipher {
        Aes(aead::LessSafeKey),
        Sm4(sm4::Sm4),
    }
    let cipher = match algo {
        0 => {
            let algorithm = match key.len() {
                32 => &aead::AES_256_GCM,
                16 => &aead::AES_128_GCM,
                // Go also accepts AES-192 here, but only a hand-built envelope has
                // one: Go's own writer never seals with a 24-byte key. Fail closed.
                24 => {
                    return err("envelope: cipher init failed: crypto/aes: unsupported key size 24")
                }
                n => {
                    return err(format!(
                        "envelope: cipher init failed: crypto/aes: invalid key size {n}"
                    ))
                }
            };
            let unbound = aead::UnboundKey::new(algorithm, &key)
                .map_err(|_| EnvelopeError("envelope: cipher init failed".into()))?;
            Cipher::Aes(aead::LessSafeKey::new(unbound))
        }
        1 => match sm4::Sm4::new(&key) {
            Some(c) => Cipher::Sm4(c),
            None => {
                return err(format!(
                    "envelope: cipher init failed: sm4: invalid key size {}",
                    key.len()
                ))
            }
        },
        n => return err(format!("envelope: unknown algorithm tag {n}")),
    };
    if nonce_len != 12 {
        return err(format!("envelope: nonce length {nonce_len} != required 12"));
    }
    if envelope.len() < HEADER_LEN + nonce_len + sm4::TAG_LEN {
        return err("envelope: ciphertext is shorter than authentication tag");
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&envelope[HEADER_LEN..HEADER_LEN + 12]);
    let sealed = &envelope[HEADER_LEN + 12..];
    let auth_failed = || {
        EnvelopeError("envelope: decryption failed: cipher: message authentication failed".into())
    };
    match cipher {
        Cipher::Aes(key) => {
            let mut buf = sealed.to_vec();
            let plain = key
                .open_in_place(
                    aead::Nonce::assume_unique_for_key(nonce),
                    aead::Aad::from(aad),
                    &mut buf,
                )
                .map_err(|_| auth_failed())?;
            Ok(plain.to_vec())
        }
        Cipher::Sm4(c) => sm4::open(&c, &nonce, sealed, aad).ok_or_else(auth_failed),
    }
}
