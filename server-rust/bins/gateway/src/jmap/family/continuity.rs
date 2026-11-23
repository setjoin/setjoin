//! #377 Continuity/get and Continuity/present (frozen Go continuity.go + shared/continuity).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use super::args::{self, Kind};
use super::seam::{resolve, write, write_sql, ContinuitySigner, Scope, Type};
use super::{always, go_compact, go_map, Answer, Cx, Gate, Method, MethodError, Reply};

const CAPABILITY: &str = "urn:ietf:params:jmap:mail";
const FEATURE_FLAG: &str = "feature.client_recovery_receipts";

const VERSION: i64 = 1;
const MAX_COMPACT_BYTES: usize = 16 << 10;
const CLOCK_SKEW_SECS: i64 = 5 * 60;
const MAX_AGE_SECS: i64 = 180 * 24 * 60 * 60;
const ED25519_SIG_BYTES: usize = 64;

pub(super) const METHODS: &[Method] = &[
    Method {
        name: "Continuity/get",
        capability: CAPABILITY,
        app: "",
        gate: Gate::Read,
        account: true,
        mutator: true,
        state: false,
        ready: always,
        run: get,
    },
    Method {
        name: "Continuity/present",
        capability: CAPABILITY,
        app: "",
        gate: Gate::Read,
        account: true,
        mutator: true,
        state: false,
        ready: always,
        run: present,
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenClaims {
    v: i64,
    #[serde(rename = "installationId")]
    installation_id: String,
    #[serde(rename = "accountId")]
    account_id: String,
    #[serde(rename = "timelineGeneration")]
    timeline_generation: String,
    #[serde(rename = "stateWatermark")]
    state_watermark: String,
    #[serde(rename = "issuedAt")]
    issued_at: String,
    #[serde(rename = "bootEpoch")]
    boot_epoch: String,
    #[serde(rename = "keyId")]
    key_id: String,
}

#[derive(Debug, Deserialize)]
struct ContinuityContext {
    #[serde(rename = "installationId")]
    installation_id: String,
    #[serde(rename = "timelineGeneration")]
    timeline_generation: String,
    #[serde(rename = "stateWatermark")]
    state_watermark: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifyError {
    Malformed,
    UnknownKey,
    InvalidSignature,
    Expired,
    Scope,
}

fn valid_decimal(value: &str) -> bool {
    if value == "0" {
        return true;
    }
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 19
        || !(b'1'..=b'9').contains(&bytes[0])
        || !bytes[1..].iter().all(|b| b.is_ascii_digit())
    {
        return false;
    }
    value.parse::<i64>().is_ok()
}

fn valid_identifier(value: &str, min: usize, max: usize) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= min
        && bytes.len() <= max
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn is_valid_uuid(value: &str) -> bool {
    let s = match value.len() {
        36 => value,
        32 => return value.bytes().all(|b| b.is_ascii_hexdigit()),
        45 => {
            if value
                .get(..9)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("urn:uuid:"))
            {
                &value[9..]
            } else {
                return false;
            }
        }
        38 => match value
            .strip_prefix('{')
            .and_then(|rest| rest.strip_suffix('}'))
        {
            Some(rest) => rest,
            None => return false,
        },
        _ => return false,
    };
    let bytes = s.as_bytes();
    bytes.len() == 36
        && bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 8 | 13 | 18 | 23) || byte.is_ascii_hexdigit())
}

fn validate_token_claims(claims: &TokenClaims) -> Option<DateTime<Utc>> {
    if claims.v != VERSION
        || !is_valid_uuid(&claims.installation_id)
        || !is_valid_uuid(&claims.boot_epoch)
        || !valid_decimal(&claims.account_id)
        || claims.account_id == "0"
        || !valid_decimal(&claims.timeline_generation)
        || claims.timeline_generation == "0"
        || !valid_decimal(&claims.state_watermark)
        || !valid_identifier(&claims.key_id, 1, 64)
    {
        return None;
    }
    let parsed = DateTime::parse_from_rfc3339(&claims.issued_at).ok()?;
    let utc = parsed.with_timezone(&Utc);
    if claims.issued_at != utc.to_rfc3339_opts(SecondsFormat::Secs, true) {
        return None;
    }
    Some(utc)
}

fn sign_token(
    installation_id: &str,
    account_id: &str,
    generation: &str,
    watermark: &str,
    boot_epoch: &str,
    now: DateTime<Utc>,
    signer: &ContinuitySigner,
) -> Option<String> {
    if !valid_identifier(signer.key_id(), 1, 64) {
        return None;
    }
    let claims = TokenClaims {
        v: VERSION,
        installation_id: installation_id.to_owned(),
        account_id: account_id.to_owned(),
        timeline_generation: generation.to_owned(),
        state_watermark: watermark.to_owned(),
        issued_at: now.to_rfc3339_opts(SecondsFormat::Secs, true),
        boot_epoch: boot_epoch.to_owned(),
        key_id: signer.key_id().to_owned(),
    };
    validate_token_claims(&claims)?;
    let payload = serde_json::to_vec(&claims).ok()?;
    let signature = signer.sign(&payload);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
    let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);
    let mut compact = String::with_capacity(payload_b64.len() + 1 + sig_b64.len());
    compact.push_str(&payload_b64);
    compact.push('.');
    compact.push_str(&sig_b64);
    if compact.len() > MAX_COMPACT_BYTES {
        return None;
    }
    Some(compact)
}

fn decode_compact_parts(
    compact: &str,
) -> Result<(Vec<u8>, Vec<u8>, TokenClaims, DateTime<Utc>), VerifyError> {
    if compact.is_empty() || compact.len() > MAX_COMPACT_BYTES {
        return Err(VerifyError::Malformed);
    }
    let (payload_b64, sig_b64) = compact.split_once('.').ok_or(VerifyError::Malformed)?;
    if sig_b64.contains('.') {
        return Err(VerifyError::Malformed);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| VerifyError::Malformed)?;
    if payload.is_empty() || payload.len() > MAX_COMPACT_BYTES {
        return Err(VerifyError::Malformed);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| VerifyError::Malformed)?;
    if signature.len() != ED25519_SIG_BYTES {
        return Err(VerifyError::Malformed);
    }
    let claims: TokenClaims =
        serde_json::from_slice(&payload).map_err(|_| VerifyError::Malformed)?;
    let issued_at = validate_token_claims(&claims).ok_or(VerifyError::Malformed)?;
    Ok((payload, signature, claims, issued_at))
}

fn verify_token(
    compact: &str,
    signer: &ContinuitySigner,
    now: DateTime<Utc>,
    expected_installation_id: &str,
    expected_account_id: &str,
) -> Result<(TokenClaims, DateTime<Utc>), VerifyError> {
    let (payload, signature, claims, issued_at) = decode_compact_parts(compact)?;
    if claims.key_id != signer.key_id() {
        return Err(VerifyError::UnknownKey);
    }
    let skew = Duration::seconds(CLOCK_SKEW_SECS);
    let max_age = Duration::seconds(MAX_AGE_SECS);
    if issued_at > now + skew {
        return Err(VerifyError::Expired);
    }
    if !signer.verify(&payload, &signature) {
        return Err(VerifyError::InvalidSignature);
    }
    if issued_at < now - max_age - skew {
        return Err(VerifyError::Expired);
    }
    if claims.installation_id != expected_installation_id
        || claims.account_id != expected_account_id
    {
        return Err(VerifyError::Scope);
    }
    Ok((claims, issued_at))
}

async fn context(
    cx: &Cx<'_>,
    scope: &Scope,
    boot_epoch: &str,
) -> Result<ContinuityContext, MethodError> {
    let raw = write(
        cx,
        scope,
        "continuity.context",
        write_sql!("SELECT continuity_context_issue($1,$4::text::uuid)::text"),
        &[(&boot_epoch, Type::TEXT)],
    )
    .await?;
    serde_json::from_str::<ContinuityContext>(&raw)
        .map_err(|_| MethodError::new("serverFail", "invalid continuity context"))
}

fn get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let (signer, boot_epoch) = cx.continuity().ok_or_else(|| {
            MethodError::new("forbidden", "client continuity receipts are disabled")
        })?;
        if cx.toggle(FEATURE_FLAG).await != Some(true) {
            return Err(MethodError::new(
                "forbidden",
                "client continuity receipts are disabled",
            ));
        }
        const FIELDS: &[(&str, Kind)] = &[("accountId", Kind::Str)];
        let args = args::decode(cx.args(), "continuityGetArgs", FIELDS)
            .map_err(|_| MethodError::new("invalidArguments", "invalid continuity request"))?;
        let account_id = args.str("accountId");
        let scope = resolve(cx, account_id).await?;
        let current = context(cx, &scope, boot_epoch).await?;
        let token = sign_token(
            &current.installation_id,
            account_id,
            &current.timeline_generation,
            &current.state_watermark,
            boot_epoch,
            Utc::now(),
            signer,
        )
        .ok_or_else(|| MethodError::new("serverFail", "continuity token signing failed"))?;
        Ok(Answer {
            name: "Continuity/get",
            args: go_map(vec![
                ("accountId", Value::String(account_id.to_owned())),
                ("token", Value::String(token)),
                (
                    "timelineGeneration",
                    Value::String(current.timeline_generation),
                ),
                ("stateWatermark", Value::String(current.state_watermark)),
                ("bootEpoch", Value::String(boot_epoch.to_owned())),
            ]),
        })
    })
}

fn present<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let (signer, boot_epoch) = cx.continuity().ok_or_else(|| {
            MethodError::new("forbidden", "client continuity receipts are disabled")
        })?;
        if cx.toggle(FEATURE_FLAG).await != Some(true) {
            return Err(MethodError::new(
                "forbidden",
                "client continuity receipts are disabled",
            ));
        }
        const FIELDS: &[(&str, Kind)] = &[("accountId", Kind::Str), ("token", Kind::Str)];
        let args = args::decode(cx.args(), "continuityPresentArgs", FIELDS)
            .map_err(|_| MethodError::new("invalidArguments", "invalid continuity witness"))?;
        let account_id = args.str("accountId");
        let token = args.str("token");
        if token.is_empty() {
            return Err(MethodError::new(
                "invalidArguments",
                "invalid continuity witness",
            ));
        }
        let scope = resolve(cx, account_id).await?;
        let current = context(cx, &scope, boot_epoch).await?;
        let (claims, _) = match verify_token(
            token,
            signer,
            Utc::now(),
            &current.installation_id,
            account_id,
        ) {
            Ok(verified) => verified,
            Err(error) => {
                let status = match error {
                    VerifyError::UnknownKey | VerifyError::Expired => "unverifiable",
                    VerifyError::Malformed | VerifyError::InvalidSignature | VerifyError::Scope => {
                        "invalid"
                    }
                };
                return Ok(Answer {
                    name: "Continuity/present",
                    args: go_map(vec![
                        ("accountId", Value::String(account_id.to_owned())),
                        ("verificationStatus", Value::String(status.to_owned())),
                        ("signalClass", Value::String("none".to_owned())),
                        ("recoveryIntakeAllowed", Value::Bool(false)),
                    ]),
                });
            }
        };
        let generation: i64 = claims
            .timeline_generation
            .parse()
            .map_err(|_| MethodError::new("invalidArguments", "invalid continuity witness"))?;
        let watermark: i64 = claims
            .state_watermark
            .parse()
            .map_err(|_| MethodError::new("invalidArguments", "invalid continuity witness"))?;
        let mut digest = String::with_capacity(64);
        for byte in Sha256::digest(token.as_bytes()) {
            let _ = write!(digest, "{byte:02x}");
        }
        let raw = write(
            cx,
            &scope,
            "continuity.witness",
            write_sql!("SELECT continuity_client_witness_record($1,$4,$5::text::uuid,$6,$7,$8::text::timestamptz,$9::text::uuid)::text"),
            &[
                (&digest, Type::TEXT),
                (&claims.installation_id, Type::TEXT),
                (&generation, Type::INT8),
                (&watermark, Type::INT8),
                (&claims.issued_at, Type::TEXT),
                (&claims.boot_epoch, Type::TEXT),
            ],
        )
        .await?;
        let mut response: BTreeMap<String, Value> = serde_json::from_str(&raw)
            .map_err(|_| MethodError::new("serverFail", "invalid continuity result"))?;
        response.insert("accountId".to_owned(), Value::String(account_id.to_owned()));
        response.insert(
            "verificationStatus".to_owned(),
            Value::String("verified".to_owned()),
        );
        response.insert("recoveryIntakeAllowed".to_owned(), Value::Bool(false));
        let serialized = serde_json::to_string(&response)
            .ok()
            .and_then(|json| go_compact(&json))
            .ok_or_else(|| MethodError::new("serverFail", "invalid continuity result"))?;
        Ok(Answer {
            name: "Continuity/present",
            args: serialized,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_claims() -> TokenClaims {
        TokenClaims {
            v: 1,
            installation_id: "4ff38daa-7eaf-4d6f-8dc6-b238fa2c7ef2".to_owned(),
            account_id: "42".to_owned(),
            timeline_generation: "7".to_owned(),
            state_watermark: "0".to_owned(),
            issued_at: "2026-08-02T03:04:05Z".to_owned(),
            boot_epoch: "9eb2f490-f539-4f23-9d5e-4107ec63a048".to_owned(),
            key_id: "continuity-2026-08".to_owned(),
        }
    }

    #[test]
    fn methods_always_claim_and_use_read_gate() {
        use super::super::Ready;
        assert_eq!(METHODS.len(), 2);
        for method in METHODS {
            assert_eq!(method.capability, CAPABILITY);
            assert_eq!(method.gate, Gate::Read);
            assert!(method.account);
            assert!(method.mutator);
            assert!(!method.state);
            assert!((method.ready)(Ready { continuity: false }));
            assert!((method.ready)(Ready { continuity: true }));
        }
    }

    #[test]
    fn decimal_and_uuid_validation_match_go() {
        for ok in ["0", "1", "42", "9223372036854775807"] {
            assert!(valid_decimal(ok), "{ok}");
        }
        for bad in ["", "00", "01", "-1", "+1", "18446744073709551615", "abc"] {
            assert!(!valid_decimal(bad), "{bad}");
        }
        for ok in [
            "4ff38daa-7eaf-4d6f-8dc6-b238fa2c7ef2",
            "4ff38daa7eaf4d6f8dc6b238fa2c7ef2",
            "urn:uuid:4ff38daa-7eaf-4d6f-8dc6-b238fa2c7ef2",
            "{4ff38daa-7eaf-4d6f-8dc6-b238fa2c7ef2}",
        ] {
            assert!(is_valid_uuid(ok), "{ok}");
        }
        for bad in [
            "",
            "not-a-uuid",
            "4ff38daa-7eaf-4d6f-8dc6-b238fa2c7ef",
            "4ff38daa_7eaf_4d6f_8dc6_b238fa2c7ef2",
        ] {
            assert!(!is_valid_uuid(bad), "{bad}");
        }
        assert!(valid_identifier("continuity-v1", 1, 64));
        assert!(!valid_identifier("-bad", 1, 64));
        assert!(!valid_identifier(&"a".repeat(65), 1, 64));
    }

    #[test]
    fn token_claims_require_strict_rfc3339_utc_seconds() {
        assert!(validate_token_claims(&valid_claims()).is_some());
        for account in ["0", "01", "+42", "-1"] {
            let mut c = valid_claims();
            c.account_id = account.to_owned();
            assert!(validate_token_claims(&c).is_none(), "{account}");
        }
        for ts in [
            "2026-08-02T03:04:05.123Z",
            "2026-08-02T03:04:05+00:00",
            "2026-08-02 03:04:05Z",
        ] {
            let mut c = valid_claims();
            c.issued_at = ts.to_owned();
            assert!(validate_token_claims(&c).is_none(), "{ts}");
        }
    }

    #[test]
    fn compact_token_parser_rejects_malformed_inputs() {
        let payload = serde_json::to_vec(&valid_claims()).expect("claims json");
        let sig = [0x11u8; ED25519_SIG_BYTES];
        let mut good = URL_SAFE_NO_PAD.encode(&payload);
        good.push('.');
        good.push_str(&URL_SAFE_NO_PAD.encode(sig));
        assert!(decode_compact_parts(&good).is_ok());

        assert_eq!(
            decode_compact_parts("").unwrap_err(),
            VerifyError::Malformed
        );
        assert_eq!(
            decode_compact_parts("abc").unwrap_err(),
            VerifyError::Malformed
        );
        assert_eq!(
            decode_compact_parts("a.b.c").unwrap_err(),
            VerifyError::Malformed
        );
        let mut oversized = String::with_capacity(MAX_COMPACT_BYTES + 1);
        for _ in 0..=MAX_COMPACT_BYTES {
            oversized.push('a');
        }
        assert_eq!(
            decode_compact_parts(&oversized).unwrap_err(),
            VerifyError::Malformed
        );

        let extra_field = br#"{"v":1,"installationId":"4ff38daa-7eaf-4d6f-8dc6-b238fa2c7ef2","accountId":"42","timelineGeneration":"7","stateWatermark":"0","issuedAt":"2026-08-02T03:04:05Z","bootEpoch":"9eb2f490-f539-4f23-9d5e-4107ec63a048","keyId":"k","extra":1}"#;
        let mut with_extra = URL_SAFE_NO_PAD.encode(extra_field);
        with_extra.push('.');
        with_extra.push_str(&URL_SAFE_NO_PAD.encode(sig));
        assert_eq!(
            decode_compact_parts(&with_extra).unwrap_err(),
            VerifyError::Malformed
        );
    }
}
