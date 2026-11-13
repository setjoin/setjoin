//! Frozen Go stored password formats. Cryptographic operations are delegated
//! to bcrypt and RustCrypto PBKDF2/SM3; no protocol-specific crypto lives here.
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use subtle::ConstantTimeEq;

pub fn verify(hash: &str, password: &str) -> bool {
    if hash.starts_with("$sm3$") {
        let fields = hash.split('$').collect::<Vec<_>>();
        if fields.len() != 5 {
            return false;
        }
        let Ok(rounds) = fields[2].parse::<u32>() else {
            return false;
        };
        if rounds == 0 {
            return false;
        }
        let clean = |value: &str| value.replace(['\r', '\n'], "");
        let (Ok(salt), Ok(expected)) = (
            STANDARD_NO_PAD.decode(clean(fields[3])),
            STANDARD_NO_PAD.decode(clean(fields[4])),
        ) else {
            return false;
        };
        if salt.is_empty() || expected.is_empty() {
            return false;
        }
        let mut actual = vec![0; expected.len()];
        pbkdf2::pbkdf2_hmac::<sm3::Sm3>(password.as_bytes(), &salt, rounds, &mut actual);
        bool::from(actual.ct_eq(&expected))
    } else {
        bcrypt::verify(password, hash).unwrap_or(false)
    }
}

/// Best-effort standard-profile self-heal, after verification. No stored salt
/// or random output is reconstructed by the oracle; it compares the upgrade
/// and successful repeated authentication, as frozen Go does.
pub fn standard_upgrade(hash: &str, password: &str) -> Option<String> {
    let below_floor = if hash.starts_with("$sm3$") {
        hash.split('$').nth(2)?.parse::<i64>().ok()? < 100_000
    } else {
        bcrypt::HashParts::from_str(hash).ok()?.get_cost() < 10
    };
    if !below_floor {
        return None;
    }
    if password.len() > 72 {
        return None;
    }
    bcrypt::hash_with_result(password, 10)
        .ok()
        .map(|parts| parts.format_for_version(bcrypt::Version::TwoA))
}
use std::str::FromStr;

/// Frozen HashPasswordWithProfile writer: bcrypt 2a/10, or PBKDF2-HMAC-SM3.
/// RNG/KDF/hash operations stay in audited ring, RustCrypto and bcrypt crates.
pub fn hash(
    password: &str,
    profile: setjoin_config_secret::CryptoProfile,
) -> Result<String, &'static str> {
    if password.len() > 72 {
        return Err("password exceeds 72 bytes");
    }
    if matches!(
        profile,
        setjoin_config_secret::CryptoProfile::Smx | setjoin_config_secret::CryptoProfile::Hybrid
    ) {
        use ring::rand::SecureRandom;
        let mut salt = [0u8; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut salt)
            .map_err(|_| "password salt")?;
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sm3::Sm3>(password.as_bytes(), &salt, 100_000, &mut key);
        Ok(format!(
            "$sm3$100000${}${}",
            STANDARD_NO_PAD.encode(salt),
            STANDARD_NO_PAD.encode(key)
        ))
    } else {
        bcrypt::hash_with_result(password, 10)
            .map(|p| p.format_for_version(bcrypt::Version::TwoA))
            .map_err(|_| "password hash")
    }
}
