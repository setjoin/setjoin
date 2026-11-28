//! Outbound S/MIME signing/encryption and inbound decrypt-on-read helpers.
//!
//! Uses OpenSSL CMS/X509/RSA primitives directly (`#![forbid(unsafe_code)]` at
//! crate root). Decryption maps `CMS_R_TYPE_NOT_ENVELOPED_DATA` / `CMS_R_NO_CONTENT`
//! and DER parse errors to [`DecryptError::MalformedCms`], and collapses every
//! matched-key RSA unwrap, padding, AEAD, or recipient mismatch failure into
//! [`DecryptError::WrongKey`] alongside OpenSSL 3.x RSA implicit rejection so
//! modified ciphertexts leak no PKCS#1 v1.5 padding oracle.

use base64::Engine as _;
pub use openssl::x509::X509;
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    cms::{CMSOptions, CmsContentInfo},
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rand::rand_bytes,
    rsa::Rsa,
    sha::sha256,
    stack::Stack,
    symm::Cipher,
    x509::{
        extension::{ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        store::X509StoreBuilder,
        X509Builder, X509NameBuilder,
    },
};
use x509_parser::extensions::{GeneralName, ParsedExtension};

pub const REASON_NO_CERT: &str = "smime_no_cert";
pub const REASON_NO_MATCHING_CERT: &str = "smime_no_matching_cert";
pub const REASON_SIGN_FAILED: &str = "smime_sign_failed";
pub const REASON_ENCRYPT_NO_CERT: &str = "smime_encrypt_no_cert";
pub const REASON_ENCRYPT_NO_SENDER_CERT: &str = "smime_encrypt_no_sender_cert";
pub const REASON_ENCRYPT_NO_JOURNAL_CERT: &str = "smime_encrypt_no_journal_cert";

pub const DECRYPT_STATE_DECRYPTED: &str = "decrypted";
pub const DECRYPT_STATE_NO_KEY: &str = "no_key";
pub const DECRYPT_STATE_WRONG_KEY: &str = "wrong_key";
pub const DECRYPT_STATE_ERROR: &str = "error";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptAlgorithm {
    Aes256Gcm,
    Aes256Cbc,
}

impl EncryptAlgorithm {
    pub fn from_env() -> Self {
        match std::env::var("SMIME_ENCRYPT_ALGORITHM").as_deref() {
            Ok("aes-256-cbc") => Self::Aes256Cbc,
            _ => Self::Aes256Gcm,
        }
    }

    fn cipher(self) -> Cipher {
        match self {
            Self::Aes256Gcm => Cipher::aes_256_gcm(),
            Self::Aes256Cbc => Cipher::aes_256_cbc(),
        }
    }

    fn smime_type(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "authEnveloped-data",
            Self::Aes256Cbc => "enveloped-data",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SignCandidate {
    pub cert_pem: String,
    pub key_pem: String,
    pub is_default: bool,
}

#[derive(Clone)]
pub struct DecryptKey {
    pub cert: X509,
    pub key: PKey<Private>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecryptError {
    MalformedCms,
    WrongKey,
}

/// Parses a PEM-encoded X.509 certificate.
pub fn parse_cert_pem(pem: &str) -> Result<X509, String> {
    X509::from_pem(pem.as_bytes()).map_err(|e| e.to_string())
}

/// Computes the lowercase-hex SHA-256 fingerprint of a certificate's DER bytes.
pub fn cert_fingerprint_hex(cert: &X509) -> Result<String, String> {
    let der = cert.to_der().map_err(|e| e.to_string())?;
    let digest = sha256(&der);
    Ok(hex_lower(&digest))
}

/// Extracts `(not_before_unix, not_after_unix)` from an X.509 certificate.
pub fn cert_validity_unix(cert: &X509) -> Result<(i64, i64), String> {
    let der = cert.to_der().map_err(|e| e.to_string())?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&der).map_err(|e| e.to_string())?;
    let v = parsed.validity();
    Ok((v.not_before.timestamp(), v.not_after.timestamp()))
}

/// Reports whether `cert` is RSA-backed and permitted for `keyEncipherment`
/// (either KeyUsage absent or `KeyUsage.keyEncipherment` set, matching Go
/// `smime.IsEncryptionCapable`).
pub fn is_encryption_capable(cert: &X509) -> bool {
    let Ok(pub_key) = cert.public_key() else {
        return false;
    };
    if pub_key.rsa().is_err() {
        return false;
    }
    let Ok(der) = cert.to_der() else {
        return false;
    };
    let Ok((_, parsed)) = x509_parser::parse_x509_certificate(&der) else {
        return false;
    };
    match parsed.key_usage() {
        Ok(None) => true,
        Ok(Some(ext)) => ext.value.flags == 0 || ext.value.key_encipherment(),
        Err(_) => false,
    }
}

/// Reports whether `cert` binds `email` via SAN `rfc822Name` or Subject
/// `emailAddress` OID (`1.2.840.113549.1.9.1`), case-insensitively.
pub fn cert_matches_email(cert: &X509, email: &str) -> bool {
    let target = email.trim();
    if target.is_empty() {
        return false;
    }
    let Ok(der) = cert.to_der() else {
        return false;
    };
    let Ok((_, parsed)) = x509_parser::parse_x509_certificate(&der) else {
        return false;
    };
    for ext in parsed.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::RFC822Name(addr) = name {
                    if addr.trim().eq_ignore_ascii_case(target) {
                        return true;
                    }
                }
            }
        }
    }
    for attr in parsed.subject().iter_attributes() {
        if attr.attr_type().to_id_string() == "1.2.840.113549.1.9.1" {
            if let Ok(addr) = attr.as_str() {
                if addr.trim().eq_ignore_ascii_case(target) {
                    return true;
                }
            }
        }
    }
    false
}

/// Validates and parses an RSA cert/key PEM pair for `Email/get` decrypt-on-read.
/// Skips unparseable or non-RSA entries, returning `None`.
pub fn parse_decrypt_candidate(cert_pem: &str, key_pem: &str) -> Option<DecryptKey> {
    if cert_pem.trim().is_empty() || key_pem.trim().is_empty() {
        return None;
    }
    let cert = X509::from_pem(cert_pem.as_bytes()).ok()?;
    let key = PKey::private_key_from_pem(key_pem.as_bytes()).ok()?;
    if key.rsa().is_err() {
        return None;
    }
    Some(DecryptKey { cert, key })
}

/// Reports whether `raw` is already an S/MIME signed message (`multipart/signed`
/// or `application/pkcs7-mime; smime-type=signed-data`), matching Go's
/// `smime.IsSignedMessage`.
pub fn is_signed_message(raw: &[u8]) -> bool {
    let headers = match split_headers_body(raw) {
        Some((h, _)) => h,
        None => raw,
    };
    let Some(ct) = extract_header_value(headers, "Content-Type") else {
        return false;
    };
    let lower = ct.to_ascii_lowercase();
    if lower.contains("multipart/signed") {
        return true;
    }
    (lower.contains("application/pkcs7-mime") || lower.contains("application/x-pkcs7-mime"))
        && lower.contains("signed-data")
}

/// Returns `Ok(true)` only if `raw` already carries an S/MIME signature that
/// verifies cryptographically against at least one `from_addr`-matching active
/// candidate certificate (`resolve_and_sign` precedence for missing/mismatched certs).
pub fn is_validly_signed_by(
    candidates: &[SignCandidate],
    from_addr: &str,
    raw: &[u8],
) -> Result<bool, &'static str> {
    if candidates.is_empty() {
        return Err(REASON_NO_CERT);
    }
    let matched: Vec<&SignCandidate> = candidates
        .iter()
        .filter(|cand| {
            parse_cert_pem(&cand.cert_pem)
                .map(|cert| cert_matches_email(&cert, from_addr))
                .unwrap_or(false)
        })
        .collect();
    if matched.is_empty() {
        return Err(REASON_NO_MATCHING_CERT);
    }
    if !is_signed_message(raw) {
        return Ok(false);
    }
    Ok(matched
        .iter()
        .any(|cand| verify_multipart_signed_with_cert(raw, &cand.cert_pem).is_ok()))
}

/// Resolves an active, `from_addr`-matching signing certificate from `candidates`
/// (preferring `is_default`, matching Go's `smime.ResolveAndSign`) and signs `raw`
/// into an S/MIME `multipart/signed` message.
pub fn resolve_and_sign(
    candidates: &[SignCandidate],
    from_addr: &str,
    raw: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if candidates.is_empty() {
        return Err(REASON_NO_CERT);
    }

    let mut matched: Vec<&SignCandidate> = Vec::new();
    for cand in candidates {
        let Ok(cert) = parse_cert_pem(&cand.cert_pem) else {
            continue;
        };
        if cert_matches_email(&cert, from_addr) {
            matched.push(cand);
        }
    }
    if matched.is_empty() {
        return Err(REASON_NO_MATCHING_CERT);
    }

    // Prefer is_default first (preserving DB ordering within tier).
    matched.sort_by_key(|c| if c.is_default { 0u8 } else { 1u8 });

    for cand in matched {
        let Ok(cert) = parse_cert_pem(&cand.cert_pem) else {
            continue;
        };
        let Ok(pkey) = PKey::private_key_from_pem(cand.key_pem.as_bytes()) else {
            continue;
        };
        if pkey.rsa().is_err() {
            continue;
        }
        if let Ok(signed) = sign_message(raw, &cert, &pkey) {
            return Ok(signed);
        }
    }

    Err(REASON_SIGN_FAILED)
}

/// Wraps `raw` RFC 5322 message as an S/MIME `multipart/signed` message using
/// detached CMS `SignedData` (`CMSOptions::DETACHED | CMSOptions::BINARY`).
pub fn sign_message(raw: &[u8], cert: &X509, pkey: &PKey<Private>) -> Result<Vec<u8>, String> {
    let (headers_bytes, body_bytes) = split_headers_body(raw)
        .ok_or_else(|| "message missing header/body separator".to_owned())?;

    let mut outer_headers = Vec::new();
    let mut inner_content_type: Option<Vec<u8>> = None;
    let mut inner_cte: Option<Vec<u8>> = None;

    for hdr in split_unfolded_headers(headers_bytes) {
        let Some(colon) = hdr.iter().position(|b| *b == b':') else {
            continue;
        };
        let name = hdr[..colon].trim_ascii();
        if name.eq_ignore_ascii_case(b"Content-Type") {
            if inner_content_type.is_none() {
                inner_content_type = Some(hdr);
            }
        } else if name.eq_ignore_ascii_case(b"Content-Transfer-Encoding") {
            if inner_cte.is_none() {
                inner_cte = Some(hdr);
            }
        } else if name.eq_ignore_ascii_case(b"MIME-Version")
            || name.eq_ignore_ascii_case(b"DKIM-Signature")
        {
            continue;
        } else {
            outer_headers.push(hdr);
        }
    }

    let mut signed_entity = Vec::new();
    match inner_content_type {
        Some(ct) => {
            signed_entity.extend_from_slice(&canonicalize_crlf(&ct));
            signed_entity.extend_from_slice(b"\r\n");
        }
        None => signed_entity.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n"),
    }
    if let Some(cte) = inner_cte {
        signed_entity.extend_from_slice(&canonicalize_crlf(&cte));
        signed_entity.extend_from_slice(b"\r\n");
    }
    signed_entity.extend_from_slice(b"\r\n");
    signed_entity.extend_from_slice(&canonicalize_crlf(body_bytes));

    let cms = CmsContentInfo::sign(
        Some(cert),
        Some(pkey),
        None,
        Some(&signed_entity),
        CMSOptions::DETACHED | CMSOptions::BINARY,
    )
    .map_err(|e| format!("CMS sign: {e}"))?;
    let sig_der = cms.to_der().map_err(|e| format!("CMS sign DER: {e}"))?;

    let boundary = random_boundary("smime-sign")?;
    let mut out = Vec::with_capacity(raw.len() + sig_der.len() + 512);
    for hdr in outer_headers {
        out.extend_from_slice(&canonicalize_crlf(&hdr));
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"MIME-Version: 1.0\r\n");
    out.extend_from_slice(
        format!(
            "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256; boundary=\"{boundary}\"\r\n\r\n"
        )
        .as_bytes(),
    );
    out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    out.extend_from_slice(&signed_entity);
    out.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
    out.extend_from_slice(
        b"Content-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\n\
          Content-Transfer-Encoding: base64\r\n\
          Content-Disposition: attachment; filename=\"smime.p7s\"\r\n\r\n",
    );
    write_base64_lines(&mut out, &sig_der);
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(out)
}

/// Encrypts `raw` RFC 5322 message for every certificate in `certs` using OpenSSL
/// CMS `EnvelopedData` (CBC) or `AuthEnvelopedData` (GCM, default), preserving
/// outer routing headers and framing the encrypted entity as
/// `application/pkcs7-mime`.
pub fn encrypt_message(
    raw: &[u8],
    certs: &[X509],
    algorithm: EncryptAlgorithm,
) -> Result<Vec<u8>, String> {
    if certs.is_empty() {
        return Err("smime encrypt: at least one recipient certificate is required".into());
    }
    let mut stack = Stack::<X509>::new().map_err(|e| e.to_string())?;
    for cert in certs {
        stack.push(cert.clone()).map_err(|e| e.to_string())?;
    }

    let (outer_headers, inner_entity) = match split_headers_body(raw) {
        Some((headers_bytes, body_bytes)) => {
            let mut outer = Vec::new();
            let mut inner_ct: Option<Vec<u8>> = None;
            let mut inner_cte: Option<Vec<u8>> = None;
            for hdr in split_unfolded_headers(headers_bytes) {
                let Some(colon) = hdr.iter().position(|b| *b == b':') else {
                    continue;
                };
                let name = hdr[..colon].trim_ascii();
                if name.eq_ignore_ascii_case(b"Content-Type") {
                    if inner_ct.is_none() {
                        inner_ct = Some(hdr);
                    }
                } else if name.eq_ignore_ascii_case(b"Content-Transfer-Encoding") {
                    if inner_cte.is_none() {
                        inner_cte = Some(hdr);
                    }
                } else if name.eq_ignore_ascii_case(b"MIME-Version")
                    || name.eq_ignore_ascii_case(b"DKIM-Signature")
                {
                    continue;
                } else {
                    outer.push(hdr);
                }
            }
            let mut inner = Vec::new();
            if let Some(ct) = inner_ct {
                inner.extend_from_slice(&canonicalize_crlf(&ct));
                inner.extend_from_slice(b"\r\n");
                if let Some(cte) = inner_cte {
                    inner.extend_from_slice(&canonicalize_crlf(&cte));
                    inner.extend_from_slice(b"\r\n");
                }
                inner.extend_from_slice(b"\r\n");
            }
            inner.extend_from_slice(body_bytes);
            (Some(outer), inner)
        }
        None => (None, raw.to_vec()),
    };

    let cms = CmsContentInfo::encrypt(
        &stack,
        &inner_entity,
        algorithm.cipher(),
        CMSOptions::BINARY,
    )
    .map_err(|e| format!("CMS encrypt: {e}"))?;
    let der = cms.to_der().map_err(|e| format!("CMS encrypt DER: {e}"))?;

    let mut out = Vec::with_capacity(der.len() * 2 + 512);
    if let Some(headers) = outer_headers {
        for hdr in headers {
            out.extend_from_slice(&canonicalize_crlf(&hdr));
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"MIME-Version: 1.0\r\n");
    }
    out.extend_from_slice(
        format!(
            "Content-Type: application/pkcs7-mime; smime-type={}; name=\"smime.p7m\"\r\n\
             Content-Transfer-Encoding: base64\r\n\
             Content-Disposition: attachment; filename=\"smime.p7m\"\r\n\r\n",
            algorithm.smime_type()
        )
        .as_bytes(),
    );
    write_base64_lines(&mut out, &der);
    Ok(out)
}

/// Extracts raw CMS `ContentInfo` DER bytes from an S/MIME enveloped artifact:
/// either bare DER (leading `0x30`) or MIME `application/pkcs7-mime` with
/// base64 body after the first blank line (`\r\n\r\n` or `\n\n`).
pub fn decode_enveloped_der(raw: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let trimmed = trim_ascii_start(raw);
    if trimmed.is_empty() {
        return Err(DecryptError::MalformedCms);
    }
    if trimmed[0] == 0x30 {
        return Ok(trimmed.to_vec());
    }
    let (_, body) = split_headers_body(raw).ok_or(DecryptError::MalformedCms)?;
    let b64: Vec<u8> = body
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if b64.is_empty() {
        return Err(DecryptError::MalformedCms);
    }
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|_| DecryptError::MalformedCms)
}

/// Attempts decryption of a DER `ContentInfo` (`EnvelopedData` or
/// `AuthEnvelopedData`) against all `keys`.
///
/// Structural parse/type/missing-content errors return [`DecryptError::MalformedCms`].
/// Unmatched recipients, wrong keys, bad PKCS#1 v1.5 padding, and AEAD/CBC
/// content failures all collapse into [`DecryptError::WrongKey`].
pub fn decrypt_multi(der: &[u8], keys: &[DecryptKey]) -> Result<Vec<u8>, DecryptError> {
    let cms = CmsContentInfo::from_der(der).map_err(|_| DecryptError::MalformedCms)?;
    if keys.is_empty() {
        return Err(DecryptError::WrongKey);
    }
    for k in keys {
        match cms.decrypt(&k.key, &k.cert) {
            Ok(plain) => return Ok(plain),
            Err(stack) => {
                if is_malformed_cms_error(&stack) {
                    return Err(DecryptError::MalformedCms);
                }
            }
        }
    }
    Err(DecryptError::WrongKey)
}

fn is_malformed_cms_error(stack: &ErrorStack) -> bool {
    const ERR_LIB_CMS: i32 = 46;
    const CMS_R_NO_CONTENT: i32 = 127;
    const CMS_R_TYPE_NOT_ENVELOPED_DATA: i32 = 146;
    stack.errors().iter().any(|e| {
        e.library_code() == ERR_LIB_CMS
            && matches!(
                e.reason_code(),
                CMS_R_NO_CONTENT | CMS_R_TYPE_NOT_ENVELOPED_DATA
            )
    })
}

fn split_headers_body(raw: &[u8]) -> Option<(&[u8], &[u8])> {
    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((&raw[..pos], &raw[pos + 4..]));
    }
    if let Some(pos) = raw.windows(2).position(|w| w == b"\n\n") {
        return Some((&raw[..pos], &raw[pos + 2..]));
    }
    None
}

fn split_unfolded_headers(headers: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur: Option<Vec<u8>> = None;
    for raw_line in headers.split(|b| *b == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        if matches!(line.first(), Some(b' ' | b'\t')) {
            if let Some(buf) = cur.as_mut() {
                buf.extend_from_slice(b"\r\n");
                buf.extend_from_slice(line);
            }
        } else {
            if let Some(prev) = cur.take() {
                out.push(prev);
            }
            cur = Some(line.to_vec());
        }
    }
    if let Some(last) = cur {
        out.push(last);
    }
    out
}

fn extract_header_value(headers: &[u8], name: &str) -> Option<String> {
    let mut raw = Vec::new();
    for hdr in split_unfolded_headers(headers) {
        let Some(colon) = hdr.iter().position(|b| *b == b':') else {
            continue;
        };
        if hdr[..colon]
            .trim_ascii()
            .eq_ignore_ascii_case(name.as_bytes())
        {
            let val = &hdr[colon + 1..];
            for line in val.split(|b| *b == b'\n') {
                let l = line.strip_suffix(b"\r").unwrap_or(line).trim_ascii();
                if !raw.is_empty() && !l.is_empty() {
                    raw.push(b' ');
                }
                raw.extend_from_slice(l);
            }
            return Some(String::from_utf8_lossy(&raw).into_owned());
        }
    }
    None
}

fn canonicalize_crlf(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + bytes.len() / 32);
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' && (i == 0 || bytes[i - 1] != b'\r') {
            out.push(b'\r');
        }
        out.push(b);
    }
    out
}

pub fn random_boundary(prefix: &str) -> Result<String, String> {
    let mut buf = [0u8; 16];
    rand_bytes(&mut buf).map_err(|e| e.to_string())?;
    Ok(format!("{prefix}-{}", hex_lower(&buf)))
}

pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

pub fn write_base64_lines(out: &mut Vec<u8>, der: &[u8]) {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    for chunk in b64.as_bytes().chunks(76) {
        out.extend_from_slice(chunk);
        out.extend_from_slice(b"\r\n");
    }
}

/// Independently verifies a `multipart/signed` S/MIME message against
/// `trust_cert_pem` using OpenSSL CMS verification, returning the verified
/// signed entity bytes on success.
pub fn verify_multipart_signed_with_cert(
    raw_signed: &[u8],
    trust_cert_pem: &str,
) -> Result<Vec<u8>, String> {
    let (headers, body) = split_headers_body(raw_signed)
        .ok_or_else(|| "signed message missing header/body separator".to_owned())?;
    let ct = extract_header_value(headers, "Content-Type")
        .ok_or_else(|| "signed message missing Content-Type".to_owned())?;
    let boundary = extract_boundary(&ct)
        .ok_or_else(|| format!("multipart/signed missing boundary in {ct}"))?;

    let start_marker = format!("--{boundary}\r\n");
    let mid_marker = format!("\r\n--{boundary}\r\n");
    let end_marker = format!("\r\n--{boundary}--");

    let start = body
        .windows(start_marker.len())
        .position(|w| w == start_marker.as_bytes())
        .ok_or_else(|| "missing first multipart boundary".to_owned())?
        + start_marker.len();
    let rest = &body[start..];
    let mid = rest
        .windows(mid_marker.len())
        .position(|w| w == mid_marker.as_bytes())
        .ok_or_else(|| "missing second multipart boundary".to_owned())?;
    let signed_entity = &rest[..mid];
    let part1_plus = &rest[mid + mid_marker.len()..];
    let end = part1_plus
        .windows(end_marker.len())
        .position(|w| w == end_marker.as_bytes())
        .ok_or_else(|| "missing closing multipart boundary".to_owned())?;
    let part1 = &part1_plus[..end];
    let (_, sig_body) = split_headers_body(part1)
        .ok_or_else(|| "signature part missing header/body separator".to_owned())?;
    let b64: Vec<u8> = sig_body
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let sig_der = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| format!("base64 decode signature: {e}"))?;

    let mut cms = CmsContentInfo::from_der(&sig_der).map_err(|e| format!("CMS parse: {e}"))?;
    let trust_cert = parse_cert_pem(trust_cert_pem)?;
    let mut store_builder = X509StoreBuilder::new().map_err(|e| e.to_string())?;
    store_builder
        .add_cert(trust_cert)
        .map_err(|e| e.to_string())?;
    let store = store_builder.build();
    cms.verify(
        None,
        Some(&store),
        Some(signed_entity),
        None,
        CMSOptions::BINARY,
    )
    .map_err(|e| format!("CMS verify: {e}"))?;
    Ok(signed_entity.to_vec())
}

/// Generates a self-signed 2048-bit RSA S/MIME certificate and PKCS#8 private
/// key PEM for tests (`key_encipherment` controls KeyUsage flags).
pub fn generate_rsa_smime_identity(
    email: &str,
    key_encipherment: Option<bool>,
) -> (String, String) {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, email).unwrap();
    let name = name.build();

    let mut serial_bytes = [0u8; 8];
    rand_bytes(&mut serial_bytes).unwrap();
    serial_bytes[0] &= 0x7f;
    serial_bytes[0] |= 1;
    let serial = BigNum::from_slice(&serial_bytes)
        .unwrap()
        .to_asn1_integer()
        .unwrap();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    let nb = Asn1Time::days_from_now(0).unwrap();
    let na = Asn1Time::days_from_now(30).unwrap();
    builder.set_not_before(&nb).unwrap();
    builder.set_not_after(&na).unwrap();

    let ctx = builder.x509v3_context(None, None);
    let san = SubjectAlternativeName::new()
        .email(email)
        .build(&ctx)
        .unwrap();
    builder.append_extension(san).unwrap();

    if let Some(enc) = key_encipherment {
        let mut ku = KeyUsage::new();
        ku.digital_signature();
        if enc {
            ku.key_encipherment();
        }
        let ku = ku.build().unwrap();
        builder.append_extension(ku).unwrap();
        let eku = ExtendedKeyUsage::new().email_protection().build().unwrap();
        builder.append_extension(eku).unwrap();
    }

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert_pem = String::from_utf8(builder.build().to_pem().unwrap()).unwrap();
    let key_pem = String::from_utf8(pkey.private_key_to_pem_pkcs8().unwrap()).unwrap();
    (cert_pem, key_pem)
}

fn extract_boundary(ct: &str) -> Option<String> {
    for param in ct.split(';').skip(1) {
        let trimmed = param.trim();
        if let Some((k, v)) = trimmed.split_once('=') {
            if k.trim().eq_ignore_ascii_case("boundary") {
                return Some(v.trim().trim_matches('"').to_owned());
            }
        }
    }
    None
}

fn trim_ascii_start(mut bytes: &[u8]) -> &[u8] {
    while let Some((&b, rest)) = bytes.split_first() {
        if b.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_test_identity(email: &str, key_encipherment_only: Option<bool>) -> (String, String) {
        generate_rsa_smime_identity(email, key_encipherment_only)
    }

    #[test]
    fn sign_and_encrypt_roundtrip_gcm_and_cbc() {
        let (sender_cert_pem, sender_key_pem) = gen_test_identity("alice@example.com", Some(true));
        let (recip_cert_pem, recip_key_pem) = gen_test_identity("bob@example.com", Some(true));
        let raw = b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Hi\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSecret body line 1\r\nLine 2\r\n";

        let signed = resolve_and_sign(
            &[SignCandidate {
                cert_pem: sender_cert_pem.clone(),
                key_pem: sender_key_pem,
                is_default: true,
            }],
            "alice@example.com",
            raw,
        )
        .expect("sign");
        assert!(is_signed_message(&signed));
        let verified_outer = verify_multipart_signed_with_cert(&signed, &sender_cert_pem)
            .expect("verify outer signed message");
        assert!(String::from_utf8_lossy(&verified_outer).contains("Secret body line 1"));

        let recip_cert = parse_cert_pem(&recip_cert_pem).unwrap();
        let recip_dk = parse_decrypt_candidate(&recip_cert_pem, &recip_key_pem).unwrap();

        for alg in [EncryptAlgorithm::Aes256Gcm, EncryptAlgorithm::Aes256Cbc] {
            let encrypted =
                encrypt_message(&signed, std::slice::from_ref(&recip_cert), alg).expect("encrypt");
            let der = decode_enveloped_der(&encrypted).expect("decode enveloped");
            let plain = decrypt_multi(&der, std::slice::from_ref(&recip_dk)).expect("decrypt");
            let verified_inner = verify_multipart_signed_with_cert(&plain, &sender_cert_pem)
                .expect("verify decrypted signed inner MIME");
            assert!(
                String::from_utf8_lossy(&verified_inner).contains("Secret body line 1"),
                "decrypted verified payload should contain signed body"
            );
        }
    }

    #[test]
    fn signing_only_cert_rejected_for_encryption() {
        let (sign_only_pem, _) = gen_test_identity("signonly@example.com", Some(false));
        let cert = parse_cert_pem(&sign_only_pem).unwrap();
        assert!(!is_encryption_capable(&cert));

        let (no_ku_pem, _) = gen_test_identity("legacy@example.com", None);
        let no_ku_cert = parse_cert_pem(&no_ku_pem).unwrap();
        assert!(is_encryption_capable(&no_ku_cert));
        assert!(cert_matches_email(&no_ku_cert, "LEGACY@example.com"));
        assert!(!cert_matches_email(&no_ku_cert, "other@example.com"));
    }

    #[test]
    fn decrypt_multi_bleichenbacher_padding_oracle_collapses_to_wrong_key() {
        let (cert_a_pem, key_a_pem) = gen_test_identity("a@example.com", Some(true));
        let (cert_b_pem, key_b_pem) = gen_test_identity("b@example.com", Some(true));
        let cert_a = parse_cert_pem(&cert_a_pem).unwrap();
        let dk_a = parse_decrypt_candidate(&cert_a_pem, &key_a_pem).unwrap();
        let dk_b = parse_decrypt_candidate(&cert_b_pem, &key_b_pem).unwrap();

        let encrypted =
            encrypt_message(b"hello world", &[cert_a], EncryptAlgorithm::Aes256Gcm).unwrap();
        let der = decode_enveloped_der(&encrypted).unwrap();

        // Wrong key returns WrongKey.
        assert_eq!(
            decrypt_multi(&der, std::slice::from_ref(&dk_b)),
            Err(DecryptError::WrongKey)
        );

        // Tamper a byte inside the RSA-2048 encryptedKey OCTET STRING (keeps ASN.1
        // DER 100% structurally valid while corrupting PKCS#1 v1.5 padding against dk_a):
        // must collapse strictly to WrongKey (never MalformedCms or padding oracle).
        let enc_key_pos = der
            .windows(4)
            .rposition(|w| w == [0x04, 0x82, 0x01, 0x00])
            .expect("256-byte RSA encryptedKey OCTET STRING in EnvelopedData");
        let mut flipped_key = der.clone();
        flipped_key[enc_key_pos + 4 + 255] ^= 0xff;
        assert_eq!(
            decrypt_multi(&flipped_key, std::slice::from_ref(&dk_a)),
            Err(DecryptError::WrongKey)
        );

        // Tamper AES-GCM encryptedContent/tag byte against matched dk_a -> strictly WrongKey.
        let mut flipped_ct = der.clone();
        let last = flipped_ct.len() - 1;
        flipped_ct[last] ^= 0xff;
        assert_eq!(
            decrypt_multi(&flipped_ct, std::slice::from_ref(&dk_a)),
            Err(DecryptError::WrongKey)
        );

        // Truncated DER -> MalformedCms.
        assert_eq!(
            decrypt_multi(&der[..10], std::slice::from_ref(&dk_a)),
            Err(DecryptError::MalformedCms)
        );

        // Non-EnvelopedData (SignedData) -> MalformedCms even when keys are present.
        let cms_signed = CmsContentInfo::sign(
            Some(&dk_b.cert),
            Some(&dk_b.key),
            None,
            Some(b"hello"),
            CMSOptions::DETACHED | CMSOptions::BINARY,
        )
        .unwrap()
        .to_der()
        .unwrap();
        assert_eq!(
            decrypt_multi(&cms_signed, &[dk_b]),
            Err(DecryptError::MalformedCms)
        );
    }
}
