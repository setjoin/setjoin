//! Parity with frozen Go: the `cryptokey` column vectors (#262) and the `configsecret`
//! vectors recorded from `mailserver/internal/admin` (#379), plus codec behaviour.

use super::*;
use crate::envelope;
use serde_json::json;
use setjoin_conformance::shared_vectors::load_vectors;

fn golden(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/shared-vectors/goldens")
        .join(format!("{name}.json"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn unhex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    assert!(s.len() % 2 == 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn keyring(v: &Value) -> ConfigSecretKeyring {
    let mut retiring = BTreeMap::new();
    if let Some(map) = v["retiring_keys"].as_object() {
        for (version, key) in map {
            retiring.insert(
                version.parse().unwrap(),
                key.as_str().unwrap().as_bytes().to_vec(),
            );
        }
    }
    ConfigSecretKeyring {
        deployment_id: v["deployment_id"].as_str().unwrap().into(),
        active_version: v["active_version"].as_u64().unwrap() as u32,
        active_key: v["active_key"].as_str().unwrap().as_bytes().to_vec(),
        active_profile: CryptoProfile::parse(v["profile"].as_str().unwrap()),
        retiring_keys: retiring,
    }
}

#[test]
fn column_vectors_match_go_byte_for_byte() {
    let cases = load_vectors(&golden("cryptokey"), "cryptokey").unwrap();
    let mut seen = 0;
    for case in &cases {
        let master = |c: &setjoin_conformance::shared_vectors::VectorCase| {
            unhex(&c.input["master_secret_hex"])
        };
        match case.name.as_str() {
            "aes_column_envelope" | "sm4_column_envelope" => {
                let profile = CryptoProfile::parse(case.input["profile"].as_str().unwrap());
                let nonce: [u8; 12] = unhex(&case.input["nonce_hex"]).try_into().unwrap();
                let aad = unhex(&case.input["aad_hex"]);
                let plain = unhex(&case.input["plaintext_hex"]);
                let sealed =
                    envelope::seal_with_nonce(profile, &master(case), &nonce, &plain, &aad)
                        .unwrap();
                assert_eq!(
                    hex(&sealed),
                    case.output["envelope_hex"],
                    "{} seal",
                    case.name
                );
                let opened = envelope::open(&sealed, &master(case), &aad).unwrap();
                assert_eq!(
                    hex(&opened),
                    case.output["opened_hex"],
                    "{} open",
                    case.name
                );
                seen += 1;
            }
            "aes_column_envelope_wrong_aad" | "sm4_column_envelope_wrong_aad" => {
                let sealed = unhex(&case.input["envelope_hex"]);
                let e = envelope::open(&sealed, &master(case), &unhex(&case.input["aad_hex"]))
                    .unwrap_err();
                assert_eq!(
                    e.to_string(),
                    case.output["error"].as_str().unwrap(),
                    "{}",
                    case.name
                );
                seen += 1;
            }
            "truncated_column" => {
                let sealed = unhex(&case.input["envelope_hex"]);
                let e = envelope::open(&sealed, &master(case), b"").unwrap_err();
                assert_eq!(e.to_string(), case.output["error"].as_str().unwrap());
                seen += 1;
            }
            _ => {}
        }
    }
    assert_eq!(seen, 5);
}

/// Cases where Go's message carries a Go-library error text we do not reproduce
/// (JSON decoder or base64 detail), compared up to the stable prefix.
fn same_error(got: &str, want: &str) -> bool {
    for marker in ["is not an envelope: ", "invalid ciphertext encoding: "] {
        if let Some(at) = want.find(marker) {
            let end = at + marker.len();
            return got.starts_with(&want[..end]);
        }
    }
    got == want
}

/// Go accepts a hand-built AES-192 envelope header and then fails authentication
/// (the key it derives does not match); Rust refuses at cipher setup. Both fail closed.
const KNOWN_CLASS_DIFFERENCES: &[&str] = &["key_length_24_with_aes_tag"];

#[test]
fn config_secret_vectors_match_go() {
    let cases = load_vectors(&golden("configsecret"), "configsecret").unwrap();
    let (mut seals, mut decrypts, mut keyrings, mut retirings) = (0, 0, 0, 0);
    for case in &cases {
        let want_error = case.output["error"].as_str().unwrap();
        let check = |got: Result<String, String>| match got {
            Ok(_) => assert_eq!(want_error, "", "{}: Go failed, Rust succeeded", case.name),
            Err(msg) => {
                if KNOWN_CLASS_DIFFERENCES.contains(&case.name.as_str()) {
                    assert!(!want_error.is_empty(), "{}", case.name);
                } else {
                    assert!(
                        same_error(&msg, want_error),
                        "{}: rust {msg:?} vs go {want_error:?}",
                        case.name
                    );
                }
                for secret in [
                    "fixture-config-secret-key",
                    "other-config-secret-key",
                    "retiring-config-secret-key",
                ] {
                    assert!(
                        !msg.contains(secret),
                        "{}: key material in error",
                        case.name
                    );
                }
            }
        };
        match case.input["op"].as_str().unwrap() {
            "seal" => {
                let codec = ConfigSecretCodec::new(keyring(&case.input["keyring"])).unwrap();
                let config_key = case.input["config_key"].as_str().unwrap();
                let nonce: [u8; 12] = unhex(&case.input["nonce_hex"]).try_into().unwrap();
                let plain = unhex(&case.input["plaintext_hex"]);
                let stored = codec.encrypt_with_nonce(config_key, &nonce, &plain);
                assert_eq!(
                    String::from_utf8(stored.clone()).unwrap(),
                    case.output["stored"].as_str().unwrap(),
                    "{}: Rust seal differs from Go bytes",
                    case.name
                );
                let opened = codec.decrypt(config_key, &stored).unwrap();
                assert_eq!(hex(&opened), case.output["plaintext_hex"], "{}", case.name);
                seals += 1;
            }
            "decrypt" => {
                let codec = ConfigSecretCodec::new(keyring(&case.input["keyring"])).unwrap();
                let got = codec.decrypt(
                    case.input["config_key"].as_str().unwrap(),
                    case.input["stored"].as_str().unwrap().as_bytes(),
                );
                if let Ok(plain) = &got {
                    assert_eq!(hex(plain), case.output["plaintext_hex"], "{}", case.name);
                }
                check(got.map(|p| hex(&p)).map_err(|e| e.to_string()));
                decrypts += 1;
            }
            "keyring" => {
                check(
                    ConfigSecretCodec::new(keyring(&case.input["keyring"]))
                        .map(|_| String::new())
                        .map_err(|e| e.to_string()),
                );
                keyrings += 1;
            }
            "retiring_keys" => {
                let got = parse_retiring_keys(case.input["raw"].as_str().unwrap());
                if let Ok(map) = &got {
                    let rendered: BTreeMap<String, String> = map
                        .iter()
                        .map(|(v, k)| (v.to_string(), String::from_utf8(k.clone()).unwrap()))
                        .collect();
                    let want: BTreeMap<String, String> =
                        serde_json::from_value(case.output["keys"].clone()).unwrap();
                    assert_eq!(rendered, want, "{}", case.name);
                }
                check(got.map(|_| String::new()).map_err(|e| e.to_string()));
                retirings += 1;
            }
            other => panic!("unknown op {other}"),
        }
    }
    // Both profiles are exercised by seal (standard, smx, hybrid) and decrypt cases.
    assert!(
        seals >= 18 && decrypts >= 40 && keyrings >= 12 && retirings >= 16,
        "{seals} {decrypts} {keyrings} {retirings}"
    );
}

fn codec(profile: CryptoProfile, version: u32, key: &str) -> ConfigSecretCodec {
    ConfigSecretCodec::new(ConfigSecretKeyring {
        deployment_id: "dep-1".into(),
        active_version: version,
        active_key: key.as_bytes().to_vec(),
        active_profile: profile,
        retiring_keys: BTreeMap::new(),
    })
    .unwrap()
}

const KEY: &str = "0123456789abcdef0123456789abcdef";

#[test]
fn random_nonce_round_trip_both_profiles_and_unique_nonces() {
    for profile in [
        CryptoProfile::Standard,
        CryptoProfile::Smx,
        CryptoProfile::Hybrid,
    ] {
        let c = codec(profile, 2, KEY);
        let a = c.encrypt("ad_sync_bind_password_enc", br#""pw""#).unwrap();
        let b = c.encrypt("ad_sync_bind_password_enc", br#""pw""#).unwrap();
        assert_ne!(a, b, "nonce must be fresh per seal");
        assert_eq!(
            c.decrypt("ad_sync_bind_password_enc", &a).unwrap(),
            br#""pw""#
        );
        assert!(is_config_secret_envelope(&a));
        let record: Value = serde_json::from_slice(&a).unwrap();
        assert_eq!(record["keyVersion"], 2);
        assert_eq!(record["sourceKey"], "legacy:ad");
        assert!(!String::from_utf8(a).unwrap().contains("pw\""));
    }
}

#[test]
fn decrypt_fails_closed_on_every_truncation() {
    let c = codec(CryptoProfile::Smx, 1, KEY);
    let stored = c.encrypt("tls_key", br#"{"k":"v"}"#).unwrap();
    let record: Value = serde_json::from_slice(&stored).unwrap();
    let sealed = RAW_URL
        .decode(record["ciphertext"].as_str().unwrap())
        .unwrap();
    for cut in 0..sealed.len() {
        let mut m = record.clone();
        m["ciphertext"] = json!(RAW_URL.encode(&sealed[..cut]));
        assert!(
            c.decrypt("tls_key", m.to_string().as_bytes()).is_err(),
            "cut {cut}"
        );
    }
    for at in 0..sealed.len() {
        let mut bad = sealed.clone();
        bad[at] ^= 1;
        let mut m = record.clone();
        m["ciphertext"] = json!(RAW_URL.encode(&bad));
        assert!(
            c.decrypt("tls_key", m.to_string().as_bytes()).is_err(),
            "flip {at}"
        );
    }
}

#[test]
fn config_key_and_deployment_are_bound() {
    let c = codec(CryptoProfile::Standard, 1, KEY);
    let stored = c.encrypt("identity_source.a", b"\"x\"").unwrap();
    assert!(c.decrypt("identity_source.b", &stored).is_err());
    let other = ConfigSecretCodec::new(ConfigSecretKeyring {
        deployment_id: "dep-2".into(),
        active_version: 1,
        active_key: KEY.as_bytes().to_vec(),
        active_profile: CryptoProfile::Standard,
        retiring_keys: BTreeMap::new(),
    })
    .unwrap();
    assert!(matches!(
        other.decrypt("identity_source.a", &stored),
        Err(ConfigSecretError::Decrypt { .. })
    ));
}

#[test]
fn source_keys_follow_go_prefix_rules() {
    assert_eq!(source_key("ad_sync_x"), "legacy:ad");
    assert_eq!(source_key("ldap_sync_x"), "legacy:ldap");
    assert_eq!(source_key("tls_x"), "legacy:tls");
    assert_eq!(source_key("identity_source.abc"), "abc");
    assert_eq!(source_key("identity_source."), "");
    assert_eq!(source_key("assist.api_key"), "legacy:system");
}

#[test]
fn debug_output_never_shows_keys() {
    let k = ConfigSecretKeyring {
        deployment_id: "d".into(),
        active_version: 1,
        active_key: b"super-secret-key-material-0123456789".to_vec(),
        active_profile: CryptoProfile::Standard,
        retiring_keys: BTreeMap::from([(7, b"retiring-secret-material-0123".to_vec())]),
    };
    let text = format!("{k:?}");
    assert!(!text.contains("secret"), "{text}");
    let c = ConfigSecretCodec::new(k).unwrap();
    assert!(!format!("{c:?}").contains("secret"));
}

#[test]
fn deployment_is_trimmed_like_go() {
    let a = codec(CryptoProfile::Standard, 1, KEY);
    let padded = ConfigSecretCodec::new(ConfigSecretKeyring {
        deployment_id: "  dep-1\t".into(),
        active_version: 1,
        active_key: KEY.as_bytes().to_vec(),
        active_profile: CryptoProfile::Standard,
        retiring_keys: BTreeMap::new(),
    })
    .unwrap();
    let stored = a.encrypt("tls_x", b"1").unwrap();
    assert_eq!(padded.decrypt("tls_x", &stored).unwrap(), b"1");
}

#[test]
fn keyring_from_lookup_mirrors_go_startup_config() {
    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    };
    // Falls back to DB_ENCRYPTION_KEY, version 1, standard profile.
    let k = keyring_from_lookup("dep", env(&[("DB_ENCRYPTION_KEY", KEY)])).unwrap();
    assert_eq!(k.active_version, 1);
    assert_eq!(k.active_key, KEY.as_bytes());
    assert_eq!(k.active_profile, CryptoProfile::Standard);
    // A dedicated key and version win; the profile is read.
    let k = keyring_from_lookup(
        "dep",
        env(&[
            ("DB_ENCRYPTION_KEY", "ignored-ignored-ignored-ignored-0"),
            ("IDENTITY_CONFIG_SECRET_KEY", "0123456789abcdef"),
            ("IDENTITY_CONFIG_SECRET_KEY_VERSION", "4"),
            ("CRYPTO_ALGORITHM_PROFILE", "smx"),
            (
                "IDENTITY_CONFIG_SECRET_RETIRING_KEYS",
                r#"{"3":"retiring-config-secret-key-v3"}"#,
            ),
        ]),
    )
    .unwrap();
    assert_eq!(
        (k.active_version, k.active_key.as_slice()),
        (4, &b"0123456789abcdef"[..])
    );
    assert_eq!(k.active_profile, CryptoProfile::Smx);
    assert!(k.retiring_keys.contains_key(&3));
    // Bad versions fail closed with Go's message.
    for bad in [
        "0",
        "-1",
        "abc",
        "",
        "1.5",
        "0x1",
        "010",
        "4294967296",
        " 1",
    ] {
        let got = keyring_from_lookup("dep", |name| match name {
            "IDENTITY_CONFIG_SECRET_KEY_VERSION" => Some(bad.to_owned()),
            "DB_ENCRYPTION_KEY" => Some(KEY.to_owned()),
            _ => None,
        });
        assert_eq!(
            got.unwrap_err().to_string(),
            "identity connector secret key version must be positive",
            "{bad:?}"
        );
    }
    assert!(
        keyring_from_lookup("dep", |n| (n == "CRYPTO_ALGORITHM_PROFILE")
            .then(|| "bogus".to_owned()))
        .is_err()
    );
    let e = keyring_from_lookup("dep", |n| match n {
        "DB_ENCRYPTION_KEY" => Some(KEY.to_owned()),
        "IDENTITY_CONFIG_SECRET_RETIRING_KEYS" => Some("{".to_owned()),
        _ => None,
    })
    .unwrap_err();
    assert_eq!(
        e.to_string(),
        "parse identity connector retiring keyring: identity config secret retiring keys must be a JSON object"
    );
    // No key at all is refused by the codec (too short), never accepted.
    let none = keyring_from_lookup("dep", |_| None).unwrap();
    assert!(ConfigSecretCodec::new(none).is_err());
}

#[test]
fn duplicate_retiring_version_spellings_are_refused() {
    assert!(
        parse_retiring_keys(r#"{"1":"aaaaaaaaaaaaaaaaaaaa","01":"bbbbbbbbbbbbbbbbbbbb"}"#).is_err()
    );
}

/// With SETJOIN_RUST_SEALED_FILE set, writes values sealed with random nonces so the
/// Go test `TestOpenRustSealedConfigSecrets` can prove Go opens what Rust seals.
#[test]
fn rust_sealed_values_for_go() {
    let Some(path) = std::env::var_os("SETJOIN_RUST_SEALED_FILE") else {
        return;
    };
    let mut items = Vec::new();
    for (profile, name) in [
        (CryptoProfile::Standard, "standard"),
        (CryptoProfile::Smx, "smx"),
        (CryptoProfile::Hybrid, "hybrid"),
    ] {
        let c = codec(profile, 5, "rust-sealed-config-secret-key-0123456789");
        for (config_key, plaintext) in [
            ("ad_sync_bind_password_enc", r#""rust-ad""#),
            ("ldap_sync_bind_password_enc", r#"{"p":"x"}"#),
            ("tls_private_key", r#""line1\nline2""#),
            ("identity_source.a&b<c>", r#"[1,2,3]"#),
            ("assist.api_key", r#""sk-rust""#),
        ] {
            let stored = c.encrypt(config_key, plaintext.as_bytes()).unwrap();
            items.push(json!({
                "keyring": {"deployment_id": "dep-1", "active_version": 5,
                    "active_key": "rust-sealed-config-secret-key-0123456789",
                    "profile": name, "retiring_keys": {}},
                "config_key": config_key,
                "stored": String::from_utf8(stored).unwrap(),
                "plaintext_hex": hex(plaintext.as_bytes()),
            }));
        }
    }
    std::fs::write(path, serde_json::to_vec(&items).unwrap()).unwrap();
}

#[test]
fn public_column_wrappers_round_trip_and_reject_wrong_master() {
    for profile in [CryptoProfile::Standard, CryptoProfile::Smx] {
        let sealed = crate::seal_column(b"hook-secret", b"master-a", profile).unwrap();
        assert_eq!(&sealed[..4], b"EK01");
        assert_eq!(
            crate::open_column(&sealed, b"master-a").unwrap(),
            b"hook-secret"
        );
        assert!(crate::open_column(&sealed, b"master-b").is_err());
        assert_ne!(
            sealed,
            crate::seal_column(b"hook-secret", b"master-a", profile).unwrap()
        );
    }
}
