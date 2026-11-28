//! Bounded canonical wire syntax for synthetic schema simulations only.
//!
//! Parsing and typed construction grant no trust, signature validity, live facts,
//! admission or cryptographic identity. Public records remain untrusted claims.
use schema_assessor::{Identity, Interval, QualifiedProfileClaims};
use std::collections::BTreeMap;

pub const ATTESTATION_TRANSPORT_MAX: usize = 16_384;
pub const ATTESTATION_STRUCTURAL_MAX: usize = 5_362;
pub const SMALL_DESCRIPTOR_TRANSPORT_MAX: usize = 1_024;
pub const SCHEMA_DESCRIPTOR_STRUCTURAL_MAX: usize = 557;
pub const POSTURE_DESCRIPTOR_STRUCTURAL_MAX: usize = 510;
pub const SET_TRANSPORT_MAX: usize = 1_048_576;
pub const SET_STRUCTURAL_MAX: usize = 876_545;
pub const ATTESTATION_DOMAIN: &[u8] = b"setjoin.schema.attestation.v1\0";
pub const SCHEMA_DOMAIN: &[u8] = b"setjoin.schema.descriptor.v1\0";
pub const POSTURE_DOMAIN: &[u8] = b"setjoin.schema.posture.v1\0";
pub const PROFILE_DOMAIN: &[u8] = b"setjoin.schema.profile.v1\0";

const BODY_KEYS: &[&str] = &[
    "format",
    "release_epoch",
    "issuer_release_id",
    "issuer_manifest_sha256",
    "binary_sha256",
    "profile_id",
    "schema_version",
    "schema_identity",
    "posture_identity",
    "read_lower",
    "read_upper",
    "write_lower",
    "write_upper",
    "qualification_sha256",
    "metadata_sequence",
    "trust_generation",
    "not_before",
    "expires_at",
];
const CORE_KEYS: &[&str] = &[
    "release_epoch",
    "binary_sha256",
    "schema_version",
    "schema_identity",
    "posture_identity",
    "read_lower",
    "read_upper",
    "write_lower",
    "write_upper",
];
const SCHEMA_KEYS: &[&str] = &[
    "format",
    "release_epoch",
    "schema_version",
    "baseline_sha256",
    "migration_set_sha256",
    "reducer_set_sha256",
    "catalog_contract_sha256",
];
const POSTURE_KEYS: &[&str] = &[
    "format",
    "release_epoch",
    "postgres_major",
    "role_contract_sha256",
    "registry_mode",
    "registry_sha256",
    "unknown_registry_policy",
    "pool_contract_sha256",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    TransportLimit,
    StructuralLimit,
    DepthLimit,
    FieldLimit,
    Syntax,
    InvalidScalar,
    InvalidInterval,
    SignatureCount,
    SignatureOrder,
    SetCount,
    SetOrder,
}
impl WireError {
    pub fn marker(self) -> &'static str {
        match self {
            Self::TransportLimit => "evidence.syntax.limit.transport",
            Self::StructuralLimit => "evidence.syntax.limit.structural",
            _ => "evidence.syntax.canonical",
        }
    }
}
impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never include attacker-controlled keys or values in diagnostics.
        write!(f, "{}", self.marker())
    }
}
impl std::error::Error for WireError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationSignature {
    pub key_id: String,
    pub algorithm: String,
    pub value: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationAttestation {
    pub fields: BTreeMap<String, String>,
    pub signatures: Vec<SimulationSignature>,
}
impl SimulationAttestation {
    pub fn number(&self, key: &str) -> Result<u64, WireError> {
        number(&self.fields, key)
    }
    pub fn identity(&self, key: &str) -> Result<Identity, WireError> {
        identity(value(&self.fields, key)?)
    }
    pub fn canonical_body(&self) -> Result<Vec<u8>, WireError> {
        validate_body(&self.fields)?;
        encode_fields(&self.fields, BODY_KEYS)
    }
    pub fn profile_core(&self) -> Result<Vec<u8>, WireError> {
        validate_body(&self.fields)?;
        encode_fields(&self.fields, CORE_KEYS)
    }
    /// This produces only assessor claims; no verification or trust is implied.
    pub fn profile_claims(&self) -> Result<QualifiedProfileClaims, WireError> {
        validate_body(&self.fields)?;
        Ok(QualifiedProfileClaims {
            binary: self.identity("binary_sha256")?,
            profile: self.identity("profile_id")?,
            schema_identity: self.identity("schema_identity")?,
            schema_version: self.number("schema_version")?,
            posture: self.identity("posture_identity")?,
            read: Interval {
                lower: self.number("read_lower")?,
                upper: self.number("read_upper")?,
            },
            write: Interval {
                lower: self.number("write_lower")?,
                upper: self.number("write_upper")?,
            },
        })
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WireError> {
        validate_signatures(&self.signatures)?;
        let mut bytes = self.canonical_body()?;
        bytes.pop();
        bytes.extend_from_slice(b",\"signatures\":[");
        for (i, signature) in self.signatures.iter().enumerate() {
            if i != 0 {
                bytes.push(b',');
            }
            bytes.extend_from_slice(b"{\"key_id\":\"");
            bytes.extend_from_slice(signature.key_id.as_bytes());
            bytes.extend_from_slice(b"\",\"algorithm\":\"ed25519\",\"value\":\"");
            bytes.extend_from_slice(signature.value.as_bytes());
            bytes.extend_from_slice(b"\"}");
        }
        bytes.extend_from_slice(b"]}");
        Ok(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationSchemaDescriptor {
    pub fields: BTreeMap<String, String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationPostureDescriptor {
    pub fields: BTreeMap<String, String>,
}
macro_rules! descriptor_methods {
    ($ty:ident, $keys:ident, $validate:ident) => {
        impl $ty {
            pub fn number(&self, key: &str) -> Result<u64, WireError> {
                number(&self.fields, key)
            }
            pub fn identity(&self, key: &str) -> Result<Identity, WireError> {
                identity(value(&self.fields, key)?)
            }
            pub fn canonical_bytes(&self) -> Result<Vec<u8>, WireError> {
                $validate(&self.fields)?;
                encode_fields(&self.fields, $keys)
            }
        }
    };
}
descriptor_methods!(SimulationSchemaDescriptor, SCHEMA_KEYS, validate_schema);
descriptor_methods!(SimulationPostureDescriptor, POSTURE_KEYS, validate_posture);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationSetRecord {
    pub id: String,
    pub sha256: String,
}

// No allocation or recursive parsing occurs before all these bounded scans.
fn preflight(
    bytes: &[u8],
    transport: usize,
    structural: usize,
    max_depth: usize,
    max_fields: usize,
) -> Result<(), WireError> {
    if bytes.len() > transport {
        return Err(WireError::TransportLimit);
    }
    if bytes.len() > structural {
        return Err(WireError::StructuralLimit);
    }
    let mut stack = [0u8; 3];
    let (mut depth, mut fields, mut string_len) = (0usize, 0usize, 0usize);
    let mut quoted = false;
    for &byte in bytes {
        if !(0x21..=0x7e).contains(&byte) || byte == b'\\' {
            return Err(WireError::Syntax);
        }
        if byte == b'"' {
            quoted = !quoted;
            string_len = 0;
        } else if quoted {
            string_len += 1;
            if string_len > 128 {
                return Err(WireError::FieldLimit);
            }
        } else {
            match byte {
                b'{' | b'[' => {
                    if depth >= max_depth || depth >= stack.len() {
                        return Err(WireError::DepthLimit);
                    }
                    stack[depth] = byte;
                    depth += 1;
                }
                b'}' | b']' => {
                    if depth == 0 {
                        return Err(WireError::Syntax);
                    }
                    depth -= 1;
                    if (stack[depth] == b'{') != (byte == b'}') {
                        return Err(WireError::Syntax);
                    }
                }
                b':' => {
                    fields += 1;
                    if fields > max_fields {
                        return Err(WireError::FieldLimit);
                    }
                }
                _ => (),
            }
        }
    }
    if quoted || depth != 0 {
        return Err(WireError::Syntax);
    }
    Ok(())
}
#[cfg(test)]
std::thread_local! {
    static SIMULATION_PARSER_ENTRIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        #[cfg(test)]
        SIMULATION_PARSER_ENTRIES.with(|count| count.set(count.get() + 1));
        Self { bytes, at: 0 }
    }
    fn literal(&mut self, literal: &[u8]) -> Result<(), WireError> {
        if !self.bytes[self.at..].starts_with(literal) {
            return Err(WireError::Syntax);
        }
        self.at += literal.len();
        Ok(())
    }
    fn string(&mut self) -> Result<String, WireError> {
        self.literal(b"\"")?;
        let start = self.at;
        while self.at < self.bytes.len() && self.bytes[self.at] != b'"' {
            self.at += 1;
        }
        if self.at == self.bytes.len() {
            return Err(WireError::Syntax);
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at])
            .map_err(|_| WireError::Syntax)?
            .to_owned();
        self.at += 1;
        Ok(text)
    }
    fn fields(&mut self, keys: &[&str]) -> Result<BTreeMap<String, String>, WireError> {
        let mut result = BTreeMap::new();
        self.literal(b"{")?;
        for (i, &key) in keys.iter().enumerate() {
            if i != 0 {
                self.literal(b",")?;
            }
            self.literal(b"\"")?;
            self.literal(key.as_bytes())?;
            self.literal(b"\":")?;
            result.insert(key.to_owned(), self.string()?);
        }
        Ok(result)
    }
    fn finished(&self) -> Result<(), WireError> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(WireError::Syntax)
        }
    }
}

pub fn parse_attestation(bytes: &[u8]) -> Result<SimulationAttestation, WireError> {
    preflight(
        bytes,
        ATTESTATION_TRANSPORT_MAX,
        ATTESTATION_STRUCTURAL_MAX,
        3,
        70,
    )?;
    let mut cursor = Cursor::new(bytes);
    let fields = cursor.fields(BODY_KEYS)?;
    cursor.literal(b",\"signatures\":[")?;
    let mut signatures = Vec::new();
    if cursor.bytes.get(cursor.at) != Some(&b']') {
        loop {
            if signatures.len() == 16 {
                return Err(WireError::SignatureCount);
            }
            let fields = cursor.fields(&["key_id", "algorithm", "value"])?;
            cursor.literal(b"}")?;
            signatures.push(SimulationSignature {
                key_id: value(&fields, "key_id")?.to_owned(),
                algorithm: value(&fields, "algorithm")?.to_owned(),
                value: value(&fields, "value")?.to_owned(),
            });
            if cursor.bytes.get(cursor.at) != Some(&b',') {
                break;
            }
            cursor.literal(b",")?;
        }
    }
    cursor.literal(b"]}")?;
    cursor.finished()?;
    let parsed = SimulationAttestation { fields, signatures };
    // Re-encoding is required even though the grammar is already literal.
    if parsed.canonical_bytes()? != bytes {
        return Err(WireError::Syntax);
    }
    Ok(parsed)
}
pub fn parse_schema_descriptor(bytes: &[u8]) -> Result<SimulationSchemaDescriptor, WireError> {
    preflight(
        bytes,
        SMALL_DESCRIPTOR_TRANSPORT_MAX,
        SCHEMA_DESCRIPTOR_STRUCTURAL_MAX,
        1,
        7,
    )?;
    let mut cursor = Cursor::new(bytes);
    let fields = cursor.fields(SCHEMA_KEYS)?;
    cursor.literal(b"}")?;
    cursor.finished()?;
    let parsed = SimulationSchemaDescriptor { fields };
    if parsed.canonical_bytes()? != bytes {
        return Err(WireError::Syntax);
    }
    Ok(parsed)
}
pub fn parse_posture_descriptor(bytes: &[u8]) -> Result<SimulationPostureDescriptor, WireError> {
    preflight(
        bytes,
        SMALL_DESCRIPTOR_TRANSPORT_MAX,
        POSTURE_DESCRIPTOR_STRUCTURAL_MAX,
        1,
        8,
    )?;
    let mut cursor = Cursor::new(bytes);
    let fields = cursor.fields(POSTURE_KEYS)?;
    cursor.literal(b"}")?;
    cursor.finished()?;
    let parsed = SimulationPostureDescriptor { fields };
    if parsed.canonical_bytes()? != bytes {
        return Err(WireError::Syntax);
    }
    Ok(parsed)
}
pub fn parse_set_descriptor(bytes: &[u8]) -> Result<Vec<SimulationSetRecord>, WireError> {
    preflight(bytes, SET_TRANSPORT_MAX, SET_STRUCTURAL_MAX, 2, 8194)?;
    let mut cursor = Cursor::new(bytes);
    cursor.literal(b"[")?;
    let mut records: Vec<SimulationSetRecord> = Vec::new();
    if cursor.bytes.get(cursor.at) != Some(&b']') {
        loop {
            if records.len() == 4096 {
                return Err(WireError::SetCount);
            }
            let fields = cursor.fields(&["id", "sha256"])?;
            cursor.literal(b"}")?;
            let id = value(&fields, "id")?;
            identifier(id)?;
            let sha256 = value(&fields, "sha256")?;
            identity(sha256)?;
            if records.last().is_some_and(|prior| prior.id.as_str() >= id) {
                return Err(WireError::SetOrder);
            }
            records.push(SimulationSetRecord {
                id: id.to_owned(),
                sha256: sha256.to_owned(),
            });
            if cursor.bytes.get(cursor.at) != Some(&b',') {
                break;
            }
            cursor.literal(b",")?;
        }
    }
    cursor.literal(b"]")?;
    cursor.finished()?;
    Ok(records)
}
pub fn encode_set_descriptor(records: &[SimulationSetRecord]) -> Result<Vec<u8>, WireError> {
    if records.len() > 4096 {
        return Err(WireError::SetCount);
    }
    let mut bytes = vec![b'['];
    let mut prior: Option<&str> = None;
    for (i, record) in records.iter().enumerate() {
        identifier(&record.id)?;
        identity(&record.sha256)?;
        if prior.is_some_and(|id| id >= record.id.as_str()) {
            return Err(WireError::SetOrder);
        }
        prior = Some(&record.id);
        if i != 0 {
            bytes.push(b',');
        }
        bytes.extend_from_slice(b"{\"id\":\"");
        bytes.extend_from_slice(record.id.as_bytes());
        bytes.extend_from_slice(b"\",\"sha256\":\"");
        bytes.extend_from_slice(record.sha256.as_bytes());
        bytes.extend_from_slice(b"\"}");
    }
    bytes.push(b']');
    Ok(bytes)
}

fn value<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, WireError> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or(WireError::InvalidScalar)
}
fn exact_keys(fields: &BTreeMap<String, String>, keys: &[&str]) -> Result<(), WireError> {
    if fields.len() != keys.len() || keys.iter().any(|key| !fields.contains_key(*key)) {
        return Err(WireError::Syntax);
    }
    Ok(())
}
fn identifier(text: &str) -> Result<(), WireError> {
    let bytes = text.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !bytes[0].is_ascii_alphanumeric()
        || bytes
            .iter()
            .any(|b| !(b.is_ascii_alphanumeric() || matches!(*b, b'.' | b'_' | b'-')))
    {
        return Err(WireError::InvalidScalar);
    }
    Ok(())
}
fn number(fields: &BTreeMap<String, String>, key: &str) -> Result<u64, WireError> {
    let text = value(fields, key)?;
    if text.is_empty()
        || text.len() > 20
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(WireError::InvalidScalar);
    }
    let number = text.parse::<u64>().map_err(|_| WireError::InvalidScalar)?;
    if number == 0 && key != "not_before" && key != "expires_at" {
        return Err(WireError::InvalidScalar);
    }
    Ok(number)
}
fn identity(text: &str) -> Result<Identity, WireError> {
    if text.len() != 64 {
        return Err(WireError::InvalidScalar);
    }
    let mut result = [0u8; 32];
    fn nibble(byte: u8) -> Result<u8, WireError> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(WireError::InvalidScalar),
        }
    }
    for (i, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        result[i] = nibble(pair[0])? * 16 + nibble(pair[1])?;
    }
    if result == [0; 32] {
        return Err(WireError::InvalidScalar);
    }
    Ok(result)
}
fn validate_body(fields: &BTreeMap<String, String>) -> Result<(), WireError> {
    exact_keys(fields, BODY_KEYS)?;
    if value(fields, "format")? != "1" {
        return Err(WireError::InvalidScalar);
    }
    for key in ["release_epoch", "issuer_release_id"] {
        identifier(value(fields, key)?)?;
    }
    for key in [
        "issuer_manifest_sha256",
        "binary_sha256",
        "profile_id",
        "schema_identity",
        "posture_identity",
        "qualification_sha256",
    ] {
        identity(value(fields, key)?)?;
    }
    for key in [
        "schema_version",
        "read_lower",
        "read_upper",
        "write_lower",
        "write_upper",
        "metadata_sequence",
        "trust_generation",
        "not_before",
        "expires_at",
    ] {
        number(fields, key)?;
    }
    let version = number(fields, "schema_version")?;
    for (lower, upper) in [("read_lower", "read_upper"), ("write_lower", "write_upper")] {
        let (lower, upper) = (number(fields, lower)?, number(fields, upper)?);
        if lower > upper || version < lower || version > upper {
            return Err(WireError::InvalidInterval);
        }
    }
    if number(fields, "not_before")? >= number(fields, "expires_at")? {
        return Err(WireError::InvalidInterval);
    }
    Ok(())
}
fn validate_schema(fields: &BTreeMap<String, String>) -> Result<(), WireError> {
    exact_keys(fields, SCHEMA_KEYS)?;
    if value(fields, "format")? != "1" {
        return Err(WireError::InvalidScalar);
    }
    identifier(value(fields, "release_epoch")?)?;
    number(fields, "schema_version")?;
    for key in &SCHEMA_KEYS[3..] {
        identity(value(fields, key)?)?;
    }
    Ok(())
}
fn validate_posture(fields: &BTreeMap<String, String>) -> Result<(), WireError> {
    exact_keys(fields, POSTURE_KEYS)?;
    if value(fields, "format")? != "1" || value(fields, "postgres_major")? != "18" {
        return Err(WireError::InvalidScalar);
    }
    identifier(value(fields, "release_epoch")?)?;
    for key in [
        "role_contract_sha256",
        "registry_sha256",
        "pool_contract_sha256",
    ] {
        identity(value(fields, key)?)?;
    }
    if !matches!(value(fields, "registry_mode")?, "observe" | "enforce")
        || !matches!(
            value(fields, "unknown_registry_policy")?,
            "observe" | "reject"
        )
    {
        return Err(WireError::InvalidScalar);
    }
    Ok(())
}
fn validate_signatures(signatures: &[SimulationSignature]) -> Result<(), WireError> {
    if !(2..=16).contains(&signatures.len()) {
        return Err(WireError::SignatureCount);
    }
    let mut prior: Option<&str> = None;
    for signature in signatures {
        identifier(&signature.key_id)?;
        if prior.is_some_and(|id| id >= signature.key_id.as_str()) {
            return Err(WireError::SignatureOrder);
        }
        prior = Some(&signature.key_id);
        if signature.algorithm != "ed25519" {
            return Err(WireError::InvalidScalar);
        }
        // 64 bytes encode to 85 full sextets followed by 2 data bits and
        // four zero pad bits. This is exactly the unpadded encode/decode image.
        let bytes = signature.value.as_bytes();
        if bytes.len() != 86 {
            return Err(WireError::InvalidScalar);
        }
        for &byte in bytes {
            if !matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/') {
                return Err(WireError::InvalidScalar);
            }
        }
        if !matches!(bytes[85], b'A' | b'Q' | b'g' | b'w') {
            return Err(WireError::InvalidScalar);
        }
    }
    Ok(())
}
fn encode_fields(fields: &BTreeMap<String, String>, keys: &[&str]) -> Result<Vec<u8>, WireError> {
    let mut bytes = vec![b'{'];
    for (i, key) in keys.iter().enumerate() {
        if i != 0 {
            bytes.push(b',');
        }
        bytes.push(b'"');
        bytes.extend_from_slice(key.as_bytes());
        bytes.extend_from_slice(b"\":\"");
        bytes.extend_from_slice(value(fields, key)?.as_bytes());
        bytes.push(b'"');
    }
    bytes.push(b'}');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejected_before_parser<T: std::fmt::Debug>(
        bytes: &[u8],
        parse: fn(&[u8]) -> Result<T, WireError>,
        expected: WireError,
        marker: &str,
        label: &str,
    ) {
        SIMULATION_PARSER_ENTRIES.with(|count| count.set(0));
        let result = parse(bytes);
        let visits = SIMULATION_PARSER_ENTRIES.with(|count| count.get());
        assert_eq!(visits, 0, "{label}: zero-parser-entries");
        let error = result.unwrap_err();
        assert_eq!(error, expected, "{label}: preparse-error-kind");
        assert_eq!(error.marker(), marker, "{label}: preparse-marker");
    }

    #[test]
    fn small_descriptors_are_bounded() {
        for (size, expected, marker, label) in [
            (
                558,
                WireError::StructuralLimit,
                "evidence.syntax.limit.structural",
                "schema558",
            ),
            (
                1024,
                WireError::StructuralLimit,
                "evidence.syntax.limit.structural",
                "schema1024",
            ),
            (
                1025,
                WireError::TransportLimit,
                "evidence.syntax.limit.transport",
                "schema1025",
            ),
        ] {
            rejected_before_parser(
                &vec![b' '; size],
                parse_schema_descriptor,
                expected,
                marker,
                label,
            );
        }
        for (size, expected, marker, label) in [
            (
                511,
                WireError::StructuralLimit,
                "evidence.syntax.limit.structural",
                "posture511",
            ),
            (
                1024,
                WireError::StructuralLimit,
                "evidence.syntax.limit.structural",
                "posture1024",
            ),
            (
                1025,
                WireError::TransportLimit,
                "evidence.syntax.limit.transport",
                "posture1025",
            ),
        ] {
            rejected_before_parser(
                &vec![b' '; size],
                parse_posture_descriptor,
                expected,
                marker,
                label,
            );
        }
        SIMULATION_PARSER_ENTRIES.with(|count| count.set(0));
        let schema = parse_schema_descriptor(include_bytes!(
            "../../fixtures/canonical-schema-maximum.json"
        ))
        .unwrap();
        assert_eq!(
            SIMULATION_PARSER_ENTRIES.with(|count| count.get()),
            1,
            "schema557: restored-parser-entry"
        );
        assert_eq!(schema.number("schema_version"), Ok(u64::MAX));
        SIMULATION_PARSER_ENTRIES.with(|count| count.set(0));
        let posture = parse_posture_descriptor(include_bytes!(
            "../../fixtures/canonical-posture-maximum.json"
        ))
        .unwrap();
        assert_eq!(
            SIMULATION_PARSER_ENTRIES.with(|count| count.get()),
            1,
            "posture510: restored-parser-entry"
        );
        assert_eq!(posture.number("postgres_major"), Ok(18));
        SIMULATION_PARSER_ENTRIES.with(|count| count.set(0));
        assert_eq!(parse_schema_descriptor(b"{}"), Err(WireError::Syntax));
        assert_eq!(
            SIMULATION_PARSER_ENTRIES.with(|count| count.get()),
            1,
            "within-bound-syntax: parser-entry"
        );
    }
}
