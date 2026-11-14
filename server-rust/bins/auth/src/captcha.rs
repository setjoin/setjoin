//! CAPTCHA token codec. Go shape (shared/threat interceptor.go captchaToken /
//! verifyCaptcha): base64url(exp "." base64url(HMAC-SHA256(key, message))).
//! #349 divergence captcha-token-bound-single-use: the message also binds the
//! source IP, route and username, and a verified token is claimed once.
//! The key default is authserverd's (config.go:271-273). ring supplies HMAC/HKDF/RNG.
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, URL_SAFE};
use base64::engine::DecodePaddingMode;
use base64::{alphabet, Engine as _};
use setjoin_config_secret::CryptoProfile;

/// Bound used-set size; a full set refuses new claims (fail closed).
const USED_CAPACITY: usize = 65_536;

/// What a challenge was issued for. A token verifies only for the same values.
pub(crate) struct Binding<'a> {
    pub(crate) ip: &'a str,
    pub(crate) route: &'a str,
    pub(crate) username: &'a str,
}

/// `answer|exp|ip|route|username`. Answer and exp are ASCII digits (checked), the
/// IP and route never contain `|`, and the username is last, so the encoding is injective.
fn message(answer: &[u8], exp: &[u8], binding: &Binding) -> Vec<u8> {
    let mut out = answer.to_vec();
    for part in [
        exp,
        binding.ip.as_bytes(),
        binding.route.as_bytes(),
        binding.username.as_bytes(),
    ] {
        out.push(b'|');
        out.extend_from_slice(part);
    }
    out
}

/// Go `base64.URLEncoding.DecodeString` (non-strict): padded URL alphabet,
/// CR/LF ignored, non-zero trailing bits accepted.
fn go_url_decode(raw: &[u8]) -> Option<Vec<u8>> {
    let lenient = GeneralPurpose::new(
        &alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
    );
    let cleaned: Vec<u8> = raw
        .iter()
        .copied()
        .filter(|b| !matches!(b, b'\r' | b'\n'))
        .collect();
    lenient.decode(cleaned).ok()
}

pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn mint(secret: &[u8], answer: &str, exp: i64, binding: &Binding) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let exp = exp.to_string();
    let mac = ring::hmac::sign(&key, &message(answer.as_bytes(), exp.as_bytes(), binding));
    URL_SAFE.encode(format!("{exp}.{}", URL_SAFE.encode(mac.as_ref())))
}

/// `Some((mac, exp))` when the token is a live, untampered challenge for this
/// answer and binding. Empty token, answer or key fails (Go); a non-digit answer
/// or exp fails (only server-minted digits are valid). Constant-time MAC check.
pub(crate) fn verify(
    secret: &[u8],
    token: &[u8],
    answer: &[u8],
    binding: &Binding,
    now: i64,
) -> Option<(Vec<u8>, i64)> {
    if token.is_empty()
        || answer.is_empty()
        || secret.is_empty()
        || !answer.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let data = go_url_decode(token)?;
    let dot = data.iter().position(|b| *b == b'.')?;
    let (exp, mac) = (&data[..dot], &data[dot + 1..]);
    if exp.is_empty() || !exp.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mac = go_url_decode(mac)?;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    ring::hmac::verify(&key, &message(answer, exp, binding), &mac).ok()?;
    let exp: i64 = std::str::from_utf8(exp).ok()?.parse().ok()?;
    (now <= exp).then_some((mac, exp))
}

/// Tokens already accepted by this process, until their own expiry.
#[derive(Default)]
pub(crate) struct UsedSet(std::sync::Mutex<std::collections::HashMap<Vec<u8>, i64>>);

impl UsedSet {
    /// `true` exactly once per live token MAC.
    pub(crate) fn claim(&self, mac: &[u8], exp: i64, now: i64) -> bool {
        let mut used = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        used.retain(|_, until| *until >= now);
        if used.contains_key(mac) || used.len() >= USED_CAPACITY {
            return false;
        }
        used.insert(mac.to_vec(), exp);
        true
    }
}

/// Go writeResult's `rand.IntN(20)+1` operands. `None` only if the OS RNG fails.
pub(crate) fn operands() -> Option<(u32, u32)> {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let pick = || -> Option<u32> {
        loop {
            let mut byte = [0u8; 1];
            rng.fill(&mut byte).ok()?;
            // Rejection sampling keeps 1..=20 uniform.
            if byte[0] < 240 {
                return Some(u32::from(byte[0] % 20) + 1);
            }
        }
    };
    Some((pick()?, pick()?))
}

struct Len(usize);
impl ring::hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, salt).extract(ikm);
    let mut out = vec![0u8; len];
    let info = [info];
    // Go's cryptokey panics on the same impossible condition (len > 255 blocks).
    prk.expand(&info, Len(len))
        .and_then(|okm| okm.fill(&mut out))
        .expect("HKDF-SHA256 output length");
    out
}

/// Go `cryptokey.DeriveEncryptionKey(JWT_SECRET, "mailserver-captcha-token-v1", profile)`:
/// HKDF-SHA256 with the purpose as SALT and empty info; 16 bytes for smx, else 32.
/// Callers never derive from an empty secret (F7): that key would be public.
pub(crate) fn derive_secret(jwt_secret: &[u8], profile: CryptoProfile) -> Vec<u8> {
    let len = if profile == CryptoProfile::Smx {
        16
    } else {
        32
    };
    hkdf_sha256(jwt_secret, b"mailserver-captcha-token-v1", &[], len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const B: Binding<'static> = Binding {
        ip: "192.0.2.1",
        route: "/auth/login",
        username: "a@x",
    };

    #[test]
    fn hkdf_matches_rfc5869_vectors() {
        let ikm = [0x0b_u8; 22];
        assert_eq!(
            hkdf_sha256(&ikm, &hex("000102030405060708090a0b0c"), &hex("f0f1f2f3f4f5f6f7f8f9"), 42),
            hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        );
        assert_eq!(
            hkdf_sha256(&ikm, &[], &[], 42),
            hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
        );
    }

    #[test]
    fn captcha_key_is_gos_salted_hkdf_and_restart_stable() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let standard = derive_secret(secret, CryptoProfile::Standard);
        assert_eq!(
            standard,
            hkdf_sha256(secret, b"mailserver-captcha-token-v1", &[], 32)
        );
        assert_eq!(standard, derive_secret(secret, CryptoProfile::Standard));
        assert_eq!(derive_secret(secret, CryptoProfile::Hybrid), standard);
        assert_eq!(
            derive_secret(secret, CryptoProfile::Smx),
            standard[..16].to_vec()
        );
        assert_ne!(
            standard,
            hkdf_sha256(secret, &[], b"mailserver-captcha-token-v1", 32)
        );
    }

    #[test]
    fn tokens_verify_only_for_their_binding() {
        let token = mint(b"k", "7", 1000, &B);
        assert_eq!(
            verify(b"k", token.as_bytes(), b"7", &B, 1000).map(|(_, e)| e),
            Some(1000)
        );
        assert!(
            verify(b"k", token.as_bytes(), b"7", &B, 1001).is_none(),
            "expired"
        );
        assert!(
            verify(b"k", token.as_bytes(), b"8", &B, 999).is_none(),
            "wrong answer"
        );
        assert!(
            verify(b"k", token.as_bytes(), b"7 ", &B, 999).is_none(),
            "non-digit answer"
        );
        assert!(
            verify(b"other", token.as_bytes(), b"7", &B, 999).is_none(),
            "other key"
        );
        assert!(
            verify(b"", token.as_bytes(), b"7", &B, 999).is_none(),
            "empty key"
        );
        assert!(verify(b"k", b"", b"7", &B, 999).is_none(), "empty token");
        for other in [
            Binding {
                ip: "192.0.2.2",
                ..B
            },
            Binding {
                route: "/auth/forgot-password/begin",
                ..B
            },
            Binding {
                username: "b@x",
                ..B
            },
        ] {
            assert!(verify(b"k", token.as_bytes(), b"7", &other, 999).is_none());
        }
        let mut wrapped = token.clone();
        wrapped.insert_str(4, "\r\n");
        assert!(
            verify(b"k", wrapped.as_bytes(), b"7", &B, 999).is_some(),
            "Go skips CR/LF"
        );
        let unpadded = token.trim_end_matches('=');
        assert_ne!(unpadded.len(), token.len());
        assert!(
            verify(b"k", unpadded.as_bytes(), b"7", &B, 999).is_none(),
            "padding required"
        );
        // Go's unbound message (`answer|exp`) is not accepted.
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"k");
        let go = URL_SAFE.encode(format!(
            "1000.{}",
            URL_SAFE.encode(ring::hmac::sign(&key, b"7|1000").as_ref())
        ));
        assert!(verify(b"k", go.as_bytes(), b"7", &B, 999).is_none());
    }

    #[test]
    fn used_set_claims_each_token_once() {
        let used = UsedSet::default();
        assert!(used.claim(b"m1", 100, 50));
        assert!(!used.claim(b"m1", 100, 60), "replay");
        assert!(used.claim(b"m2", 100, 60));
        assert!(used.claim(b"m1", 200, 101), "expired entries are pruned");
    }

    #[test]
    fn operands_stay_in_go_range() {
        for _ in 0..500 {
            let (a, b) = operands().unwrap();
            assert!((1..=20).contains(&a) && (1..=20).contains(&b));
        }
    }
}
