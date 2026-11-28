//! Shared Go certificate/PEM profile; parsing grants no trust.
pub mod certificate;
pub mod trust;
use base64::Engine as _;
use sha2::{Digest, Sha256};

/// One certificate of an imported bundle (`smime.ParsedAnchorCert`); validity is Unix seconds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedCert {
    pub pem: String,
    pub fingerprint: String,
    pub subject_cn: String,
    pub not_before: i64,
    pub not_after: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChainError {
    /// Go's "not a valid PEM certificate".
    Invalid,
    /// The first certificate is already expired.
    Expired,
}

// ---- Go's encoding/pem ----

struct Block {
    kind: Vec<u8>,
    bytes: Vec<u8>,
}

/// `getLine`: the line without its terminator (trailing spaces and tabs trimmed), the rest,
/// and the bytes consumed.
fn get_line(data: &[u8]) -> (&[u8], &[u8], usize) {
    let (mut end, consumed) = match data.iter().position(|b| *b == b'\n') {
        None => (data.len(), data.len()),
        Some(i) => {
            let end = if i > 0 && data[i - 1] == b'\r' {
                i - 1
            } else {
                i
            };
            (end, i + 1)
        }
    };
    while end > 0 && matches!(data[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    (&data[..end], &data[consumed..], consumed)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).rposition(|w| w == needle)
}

/// Go's `pem.Decode`: the next block and the remainder, or `None` when there is none.
fn pem_decode(data: &[u8]) -> Option<(Block, &[u8])> {
    const START: &[u8] = b"\n-----BEGIN ";
    const END: &[u8] = b"\n-----END ";
    const DASHES: &[u8] = b"-----";
    let mut rest = data;
    let mut end_trailer: isize = 0;
    loop {
        if end_trailer < 0 || end_trailer as usize > rest.len() {
            return None;
        }
        rest = &rest[end_trailer as usize..];
        let end_index = find(rest, END)? as isize;
        end_trailer = end_index + END.len() as isize;
        let begin = match rfind(&rest[..end_index as usize], &START[1..]) {
            Some(b) if b == 0 || rest[b - 1] == b'\n' => b,
            _ => continue,
        };
        let skip = begin + START.len() - 1;
        rest = &rest[skip..];
        let mut end_index = end_index - skip as isize;
        end_trailer -= skip as isize;
        let (type_line, after, consumed) = get_line(rest);
        rest = after;
        end_index -= consumed as isize;
        end_trailer -= consumed as isize;
        if !type_line.ends_with(DASHES) {
            continue;
        }
        let kind = &type_line[..type_line.len() - DASHES.len()];
        let mut headers = 0;
        loop {
            if rest.is_empty() {
                return None;
            }
            let (line, next, consumed) = get_line(rest);
            if !line.contains(&b':') {
                break;
            }
            headers += 1;
            rest = next;
            end_index -= consumed as isize;
            end_trailer -= consumed as isize;
        }
        if headers > 0 && end_index < 0 {
            continue;
        }
        if end_trailer < 0 || end_trailer as usize > rest.len() {
            continue;
        }
        let trailer = &rest[end_trailer as usize..];
        let trailer_len = kind.len() + DASHES.len();
        if trailer.len() < trailer_len {
            continue;
        }
        let (tail, line_rest) = (&trailer[..trailer_len], &trailer[trailer_len..]);
        if !tail.starts_with(kind) || !tail.ends_with(DASHES) {
            continue;
        }
        if !get_line(line_rest).0.is_empty() {
            continue;
        }
        let mut bytes = Vec::new();
        if end_index > 0 {
            let body: Vec<u8> = rest[..end_index as usize]
                .iter()
                .copied()
                .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
                .collect();
            let engine = base64::engine::GeneralPurpose::new(
                &base64::alphabet::STANDARD,
                base64::engine::GeneralPurposeConfig::new()
                    .with_decode_allow_trailing_bits(true)
                    .with_decode_padding_mode(base64::engine::DecodePaddingMode::RequireCanonical),
            );
            match engine.decode(&body) {
                Ok(decoded) => bytes = decoded,
                Err(_) => continue,
            }
        }
        let skip_end = ((end_index + END.len() as isize - 1).max(0) as usize).min(rest.len());
        let (_, after, _) = get_line(&rest[skip_end..]);
        return Some((
            Block {
                kind: kind.to_vec(),
                bytes,
            },
            after,
        ));
    }
}

/// `pem.EncodeToMemory` of a CERTIFICATE block.
fn encode_pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

pub fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Go's user-certificate hint parses only the first PEM block, ignoring its
/// label and trailing input. This is parse-only metadata, never trust admission.
pub fn first_certificate_dates(text: &[u8]) -> Option<(i64, i64)> {
    let (block, _) = pem_decode(text)?;
    let cert = crate::certificate::parse(&block.bytes).ok()?;
    Some((cert.validity().not_before.timestamp(), cert.validity().not_after.timestamp()))
}

/// Frozen-Go recipient eligibility: RSA and keyEncipherment, or zero usage.
/// This parses metadata only; validity and email admission belong to the caller.
pub fn first_certificate_encrypt_capable(text: &[u8]) -> bool {
    let Some((block, _)) = pem_decode(text) else { return false; };
    let Ok(cert) = crate::certificate::parse(&block.bytes) else { return false; };
    cert.public_key().algorithm.algorithm.to_id_string() == "1.2.840.113549.1.1.1"
        && cert.key_usage().ok().flatten().is_none_or(|usage| usage.value.flags == 0 || usage.value.key_encipherment())
}

/// First nonblank SAN rfc822Name, normalized as Go's certFirstEmail.
pub fn first_certificate_email(text: &[u8]) -> Option<String> {
    let (block, _) = pem_decode(text)?;
    let cert = crate::certificate::parse(&block.bytes).ok()?;
    let names = cert.subject_alternative_name().ok().flatten()?;
    names.value.general_names.iter().find_map(|name| match name {
        x509_parser::extensions::GeneralName::RFC822Name(value) if !value.trim().is_empty() => Some(value.trim().to_lowercase()),
        _ => None,
    })
}

/// The same encoding/pem boundary for the independent user private-key parser.
/// No key is interpreted or retained by this helper.
pub fn first_pem_bytes(text: &[u8]) -> Option<Vec<u8>> {
    pem_decode(text).map(|(block, _)| block.bytes)
}

/// `smime.ParseAllCerts` + `ParseAnchorChain`: every PEM block must be a parseable
/// certificate and only whitespace may follow the last one.
pub fn parse_chain(text: &[u8]) -> Result<Vec<ParsedCert>, ChainError> {
    let mut certs = Vec::new();
    let mut rest = text;
    while let Some((block, after)) = pem_decode(rest) {
        // Go does not look at the block type: a key block fails to parse as a certificate.
        let _ = &block.kind;
        let cert = crate::certificate::parse(&block.bytes).map_err(|_| ChainError::Invalid)?;
        let common_name = crate::certificate::common_name(cert.subject());
        certs.push(ParsedCert {
            pem: encode_pem(&block.bytes),
            fingerprint: fingerprint(&block.bytes),
            subject_cn: common_name,
            not_before: cert.validity().not_before.timestamp(),
            not_after: cert.validity().not_after.timestamp(),
        });
        rest = after;
    }
    if certs.is_empty() || !rest.iter().all(|b| b.is_ascii_whitespace() || *b == 0x0b) {
        return Err(ChainError::Invalid);
    }
    Ok(certs)
}

/// `validateAnchorChain`: the first certificate must not already be expired (`now` is Unix
/// seconds).
pub fn validate_chain(text: &[u8], now: i64) -> Result<Vec<ParsedCert>, ChainError> {
    let certs = parse_chain(text)?;
    if now > certs[0].not_after {
        return Err(ChainError::Expired);
    }
    Ok(certs)
}
