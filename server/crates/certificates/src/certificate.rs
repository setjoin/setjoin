//! Go's certificate parsing profile over audited DER/X.509 and curve decoders.
//! Parsing does not verify the certificate signature or enforce validity/trust.
use der::{
    asn1::{AnyRef, BitStringRef, IntRef},
    Decode, Reader, SliceReader, Tag, TagNumber, Tagged,
};
use std::collections::HashSet;
use x509_parser::{certificate::X509Certificate, x509::X509Name};
type Result<T> = std::result::Result<T, ()>;

// RustCrypto der owns tag/length/value decoding and typed primitive reads.
// These helpers describe Go's schema and primitive constraints, not a TLV reader.
fn take<'a>(input: &mut &'a [u8]) -> Result<AnyRef<'a>> {
    let bytes = *input;
    let mut reader = SliceReader::new(bytes).map_err(|_| ())?;
    let value = AnyRef::decode(&mut reader).map_err(|_| ())?;
    if value.tag().number().0 > 30 {
        return Err(());
    }
    let used = usize::try_from(reader.position()).map_err(|_| ())?;
    *input = &bytes[used..];
    Ok(value)
}
fn tagged<'a>(input: &mut &'a [u8], tag: Tag) -> Result<AnyRef<'a>> {
    let value = take(input)?;
    if value.tag() != tag {
        return Err(());
    }
    Ok(value)
}
fn has(input: &[u8], tag: Tag) -> bool {
    SliceReader::new(input)
        .ok()
        .and_then(|r| Tag::peek(&r).ok())
        == Some(tag)
}
fn context(n: u32, constructed: bool) -> Tag {
    Tag::ContextSpecific {
        constructed,
        number: TagNumber(n),
    }
}
fn oid(input: &mut &[u8]) -> Result<String> {
    let value = tagged(input, Tag::ObjectIdentifier)?;
    let oid = der::oid::ObjectIdentifierRef::from_bytes(value.value()).map_err(|_| ())?;
    // cryptobyte.ReadASN1ObjectIdentifier bounds each encoded subidentifier
    // to signed 31 bits on every Go architecture. The first combines arcs 0/1.
    let max = i32::MAX as u32;
    if oid
        .arcs()
        .enumerate()
        .any(|(i, arc)| arc > max || (i == 1 && oid.arc(0) == Some(2) && arc > max - 80))
    {
        return Err(());
    }
    Ok(oid.to_string())
}
// Go's x509.OID policy representation retains arbitrary-width components.
// The audited regex engine checks canonical base-128 primitive grammar without
// converting components into a bounded integer or implementing a DER reader.
fn policy_oid<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
    static CANONICAL: std::sync::OnceLock<regex::bytes::Regex> = std::sync::OnceLock::new();
    let value = tagged(input, Tag::ObjectIdentifier)?.value();
    let pattern = CANONICAL.get_or_init(|| {
        regex::bytes::Regex::new(r"(?-u)\A(?:[\x00-\x7f]|[\x81-\xff][\x80-\xff]*[\x00-\x7f])+\z")
            .expect("canonical OID primitive grammar")
    });
    if !pattern.is_match(value) {
        return Err(());
    }
    Ok(value)
}
fn integer(value: AnyRef<'_>, positive: bool) -> Result<()> {
    value.decode_as::<IntRef>().map_err(|_| ())?;
    if value.value().first().is_some_and(|b| b & 128 != 0)
        || (positive && value.value().iter().all(|b| *b == 0))
    {
        return Err(());
    }
    Ok(())
}
fn signed(value: AnyRef<'_>) -> Result<i64> {
    AnyRef::new(Tag::Integer, value.value())
        .map_err(|_| ())?
        .decode_as::<i64>()
        .map_err(|_| ())
}
fn bits(value: AnyRef<'_>) -> Result<Vec<u8>> {
    let bitstring = value.decode_as::<BitStringRef>().map_err(|_| ())?;
    let unused = bitstring.unused_bits();
    let bytes = bitstring.raw_bytes();
    if unused != 0 && bytes.last().is_some_and(|b| b & ((1 << unused) - 1) != 0) {
        return Err(());
    }
    // Go's BitString.RightAlign on an already decoded, canonical public value.
    if unused == 0 {
        return Ok(bytes.to_vec());
    }
    Ok(bytes
        .iter()
        .enumerate()
        .map(|(i, b)| {
            (b >> unused)
                | if i == 0 {
                    0
                } else {
                    bytes[i - 1] << (8 - unused)
                }
        })
        .collect())
}
fn algorithm(mut input: &[u8]) -> Result<(String, Option<AnyRef<'_>>)> {
    let name = oid(&mut input)?;
    let params = if input.is_empty() {
        None
    } else {
        Some(take(&mut input)?)
    };
    Ok((name, params))
}
fn string(tag: u32, bytes: &[u8]) -> Result<String> {
    match tag {
        12 => std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| ()),
        18 if bytes.iter().all(|b| b.is_ascii_digit() || *b == b' ') => {
            Ok(String::from_utf8(bytes.to_vec()).map_err(|_| ())?)
        }
        19 if bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b" '()+,-./:=?*&".contains(b)) =>
        {
            Ok(String::from_utf8(bytes.to_vec()).map_err(|_| ())?)
        }
        20 => Ok(bytes.iter().map(|b| char::from(*b)).collect()),
        22 if bytes.is_ascii() => Ok(String::from_utf8(bytes.to_vec()).map_err(|_| ())?),
        30 if bytes.len() % 2 == 0 => {
            let mut words: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|v| u16::from_be_bytes([v[0], v[1]]))
                .collect();
            if words.last() == Some(&0) {
                words.pop();
            }
            if words.iter().any(|v| (0xd800..=0xdfff).contains(v)) {
                return Err(());
            }
            String::from_utf16(&words).map_err(|_| ())
        }
        _ => Err(()),
    }
}
fn name(mut input: &[u8]) -> Result<()> {
    while !input.is_empty() {
        let mut set = tagged(&mut input, Tag::Set)?.value();
        while !set.is_empty() {
            let mut attribute = tagged(&mut set, Tag::Sequence)?.value();
            oid(&mut attribute)?;
            let value = take(&mut attribute)?;
            if value.tag().class() != der::Class::Universal || value.tag().is_constructed() {
                return Err(());
            }
            string(value.tag().number().0, value.value())?;
        }
    }
    Ok(())
}
pub fn common_name(name: &X509Name<'_>) -> String {
    name.iter_common_name()
        .last()
        .and_then(|a| {
            let value = a.attr_value();
            string(value.tag().0, value.data).ok()
        })
        .unwrap_or_default()
}
fn public_key(mut input: &[u8]) -> Result<()> {
    let (algorithm, params) = algorithm(tagged(&mut input, Tag::Sequence)?.value())?;
    let key = bits(tagged(&mut input, Tag::BitString)?)?;
    match algorithm.as_str() {
        "1.2.840.113549.1.1.1" => {
            if params.is_none_or(|p| p.tag() != Tag::Null || !p.value().is_empty()) {
                return Err(());
            }
            let mut data = key.as_slice();
            let mut fields = tagged(&mut data, Tag::Sequence)?.value();
            integer(tagged(&mut fields, Tag::Integer)?, true)?;
            if signed(tagged(&mut fields, Tag::Integer)?)? <= 0 {
                return Err(());
            }
        }
        "1.2.840.10045.2.1" => {
            let params = params.ok_or(())?;
            if params.tag() != Tag::ObjectIdentifier {
                return Err(());
            }
            let curve = der::oid::ObjectIdentifierRef::from_bytes(params.value())
                .map_err(|_| ())?
                .to_string();
            if key.first() != Some(&4) {
                return Err(());
            }
            let valid = match curve.as_str() {
                "1.3.132.0.33" => p224::PublicKey::from_sec1_bytes(&key).is_ok(),
                "1.2.840.10045.3.1.7" => p256::PublicKey::from_sec1_bytes(&key).is_ok(),
                "1.3.132.0.34" => p384::PublicKey::from_sec1_bytes(&key).is_ok(),
                "1.3.132.0.35" => p521::PublicKey::from_sec1_bytes(&key).is_ok(),
                _ => false,
            };
            if !valid {
                return Err(());
            }
        }
        "1.3.101.112" | "1.3.101.110" => {
            if params.is_some() || key.len() != 32 {
                return Err(());
            }
        }
        "1.2.840.10040.4.1" => {
            let mut value = key.as_slice();
            integer(tagged(&mut value, Tag::Integer)?, true)?;
            let p = params.ok_or(())?;
            if p.tag() != Tag::Sequence {
                return Err(());
            }
            let mut values = p.value();
            for _ in 0..3 {
                integer(tagged(&mut values, Tag::Integer)?, true)?;
            }
        }
        // Unknown public-key algorithms are opaque in Go's ParseCertificate.
        _ => {}
    }
    Ok(())
}
fn domain(s: &str, constraint: bool) -> bool {
    if s.is_empty() {
        return true;
    }
    let s = if constraint {
        s.strip_prefix('.').unwrap_or(s)
    } else {
        s
    };
    !s.ends_with('.')
        && s.bytes().all(|b| (33..=126).contains(&b))
        && s.split('.').all(|s| !s.is_empty())
}
fn uri(value: &str) -> Result<()> {
    let parsed = setjoin_authz::go_url::go_url_parse(value)?;
    // The shared helper's opaque-path fast return predates fragment checking.
    // Validate that component through its non-opaque fragment path as well.
    if let Some((_, fragment)) = value.split_once('#') {
        setjoin_authz::go_url::go_url_parse(&format!("/#{fragment}"))?;
    }
    if !domain(&parsed.host, false) {
        return Err(());
    }
    Ok(())
}
fn alternatives(mut input: &[u8]) -> Result<()> {
    let mut values = tagged(&mut input, Tag::Sequence)?.value();
    while !values.is_empty() {
        let value = take(&mut values)?;
        match value.tag() {
            t if t == context(1, false) || t == context(2, false) || t == context(6, false) => {
                if !value.value().is_ascii() {
                    return Err(());
                }
                if t == context(6, false) {
                    uri(std::str::from_utf8(value.value()).map_err(|_| ())?)?;
                }
            }
            t if t == context(7, false) => {
                if !matches!(value.value().len(), 4 | 16) {
                    return Err(());
                }
            }
            _ => {}
        }
    }
    Ok(())
}
fn constraint_values(mut input: &[u8]) -> Result<()> {
    while !input.is_empty() {
        let mut subtree = tagged(&mut input, Tag::Sequence)?.value();
        let value = take(&mut subtree)?;
        if value.tag() == context(7, false) {
            if !matches!(value.value().len(), 8 | 32) {
                return Err(());
            }
            let mask = &value.value()[value.value().len() / 2..];
            let mut zero = false;
            for byte in mask {
                for bit in (0..8).rev() {
                    if byte & (1 << bit) == 0 {
                        zero = true;
                    } else if zero {
                        return Err(());
                    }
                }
            }
        } else if [context(1, false), context(2, false), context(6, false)].contains(&value.tag()) {
            if !value.value().is_ascii() {
                return Err(());
            }
            let s = std::str::from_utf8(value.value()).map_err(|_| ())?;
            if value.tag() == context(1, false) && s.contains('@') {
                let (local, host) = s.rsplit_once('@').ok_or(())?;
                if local.is_empty() || !domain(host, false) {
                    return Err(());
                }
                if local.starts_with('"') {
                    if !local.ends_with('"') || setjoin_mime::parse_address(s.as_bytes()).is_err() {
                        return Err(());
                    }
                } else if local.split('.').any(|p| {
                    p.is_empty()
                        || !p.bytes().all(|b| {
                            b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&b)
                        })
                }) {
                    return Err(());
                }
            } else {
                if !domain(s, true)
                    || (value.tag() == context(6, false) && s.parse::<std::net::IpAddr>().is_ok())
                {
                    return Err(());
                }
            }
        }
    }
    Ok(())
}
fn constraints(mut input: &[u8]) -> Result<()> {
    let mut sequence = tagged(&mut input, Tag::Sequence)?.value();
    if !input.is_empty() {
        return Err(());
    }
    let permitted = if has(sequence, context(0, true)) {
        tagged(&mut sequence, context(0, true))?.value()
    } else {
        &[]
    };
    let excluded = if has(sequence, context(1, true)) {
        tagged(&mut sequence, context(1, true))?.value()
    } else {
        &[]
    };
    if !sequence.is_empty() || (permitted.is_empty() && excluded.is_empty()) {
        return Err(());
    }
    constraint_values(permitted)?;
    constraint_values(excluded)
}
fn extension(id: &str, critical: bool, mut input: &[u8]) -> Result<()> {
    match id {
        "2.5.29.14" => {
            if critical {
                return Err(());
            }
            tagged(&mut input, Tag::OctetString)?;
        }
        "2.5.29.35" => {
            if critical {
                return Err(());
            }
            let mut value = tagged(&mut input, Tag::Sequence)?.value();
            if has(value, context(0, false)) {
                tagged(&mut value, context(0, false))?;
            }
        }
        "2.5.29.15" => {
            bits(tagged(&mut input, Tag::BitString)?)?;
        }
        "2.5.29.19" => {
            let mut value = tagged(&mut input, Tag::Sequence)?.value();
            if has(value, Tag::Boolean) {
                take(&mut value)?.decode_as::<bool>().map_err(|_| ())?;
            }
            if has(value, Tag::Integer) {
                let n = take(&mut value)?.decode_as::<u64>().map_err(|_| ())?;
                if n > i64::MAX as u64 {
                    return Err(());
                }
            }
        }
        "2.5.29.17" => alternatives(input)?,
        "2.5.29.30" => constraints(input)?,
        "2.5.29.37" => {
            let mut value = tagged(&mut input, Tag::Sequence)?.value();
            while !value.is_empty() {
                oid(&mut value)?;
            }
        }
        "2.5.29.32" => {
            let mut value = tagged(&mut input, Tag::Sequence)?.value();
            let mut seen = HashSet::new();
            while !value.is_empty() {
                let mut policy = tagged(&mut value, Tag::Sequence)?.value();
                if !seen.insert(policy_oid(&mut policy)?) {
                    return Err(());
                }
            }
        }
        "2.5.29.33" => {
            let mut value = tagged(&mut input, Tag::Sequence)?.value();
            while !value.is_empty() {
                let mut mapping = tagged(&mut value, Tag::Sequence)?.value();
                tagged(&mut mapping, Tag::ObjectIdentifier)?;
                tagged(&mut mapping, Tag::ObjectIdentifier)?;
            }
        }
        "2.5.29.36" => {
            let mut value = tagged(&mut input, Tag::Sequence)?.value();
            for n in 0..2 {
                if has(value, context(n, false)) {
                    signed(take(&mut value)?)?;
                }
            }
        }
        "2.5.29.54" => {
            let v = tagged(&mut input, Tag::Integer)?;
            signed(v)?;
        }
        "1.3.6.1.5.5.7.1.1" => {
            if critical {
                return Err(());
            }
            let mut value = tagged(&mut input, Tag::Sequence)?.value();
            while !value.is_empty() {
                let mut description = tagged(&mut value, Tag::Sequence)?.value();
                oid(&mut description)?;
                if has(description, context(6, false)) {
                    tagged(&mut description, context(6, false))?;
                }
            }
        }
        "2.5.29.31" => {
            let mut value = tagged(&mut input, Tag::Sequence)?.value();
            while !value.is_empty() {
                let mut point = tagged(&mut value, Tag::Sequence)?.value();
                if has(point, context(0, true)) {
                    let mut outer = tagged(&mut point, context(0, true))?.value();
                    let mut full_name = tagged(&mut outer, context(0, true))?.value();
                    while has(full_name, context(6, false)) {
                        tagged(&mut full_name, context(6, false))?;
                    }
                }
            }
        }
        // Unknown extensions, even critical ones, are retained by Go's parser.
        _ => {}
    }
    Ok(())
}
fn profile(der: &[u8]) -> Result<()> {
    let mut input = der;
    let mut certificate = tagged(&mut input, Tag::Sequence)?.value();
    if !input.is_empty() {
        return Err(());
    }
    let mut tbs = tagged(&mut certificate, Tag::Sequence)?.value();
    let outer_algorithm = tagged(&mut certificate, Tag::Sequence)?;
    bits(tagged(&mut certificate, Tag::BitString)?)?;
    let version = if has(tbs, context(0, true)) {
        let mut explicit = tagged(&mut tbs, context(0, true))?.value();
        let version = signed(tagged(&mut explicit, Tag::Integer)?)?;
        if !explicit.is_empty() {
            return Err(());
        }
        version
    } else {
        0
    };
    if !(0..=2).contains(&version) {
        return Err(());
    }
    integer(tagged(&mut tbs, Tag::Integer)?, false)?;
    let inner_algorithm = tagged(&mut tbs, Tag::Sequence)?;
    if inner_algorithm.value() != outer_algorithm.value() {
        return Err(());
    }
    algorithm(inner_algorithm.value())?;
    name(tagged(&mut tbs, Tag::Sequence)?.value())?;
    let mut validity = tagged(&mut tbs, Tag::Sequence)?.value();
    for _ in 0..2 {
        if !matches!(
            take(&mut validity)?.tag(),
            Tag::UtcTime | Tag::GeneralizedTime
        ) {
            return Err(());
        }
    }
    name(tagged(&mut tbs, Tag::Sequence)?.value())?;
    public_key(tagged(&mut tbs, Tag::Sequence)?.value())?;
    if version > 0 {
        for n in 1..=2 {
            if has(tbs, context(n, false)) {
                tagged(&mut tbs, context(n, false))?;
            }
        }
        if version == 2 && has(tbs, context(3, true)) {
            let mut explicit = tagged(&mut tbs, context(3, true))?.value();
            let mut extensions = tagged(&mut explicit, Tag::Sequence)?.value();
            let mut seen = HashSet::new();
            while !extensions.is_empty() {
                let mut fields = tagged(&mut extensions, Tag::Sequence)?.value();
                let id = oid(&mut fields)?;
                if !seen.insert(id.clone()) {
                    return Err(());
                }
                let critical = if has(fields, Tag::Boolean) {
                    take(&mut fields)?.decode_as::<bool>().map_err(|_| ())?
                } else {
                    false
                };
                extension(
                    &id,
                    critical,
                    tagged(&mut fields, Tag::OctetString)?.value(),
                )?;
            }
        }
    }
    Ok(())
}

pub fn parse(der: &[u8]) -> Result<X509Certificate<'_>> {
    profile(der)?;
    let (remaining, certificate) = x509_parser::parse_x509_certificate(der).map_err(|_| ())?;
    if !remaining.is_empty() {
        return Err(());
    }
    Ok(certificate)
}

/// Parse-only Go certificate admission for operator CA bundles. This does not
/// establish trust, verify a signature, or check the validity window.
pub fn accepts_der(der: &[u8]) -> bool {
    parse(der).is_ok()
}
