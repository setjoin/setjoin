//! Admin identity (F01) slice `idv2-sources`: the identity source document (validation
//! and canonical form, as Go's `validateIdentitySourceDocument`) and the receipted
//! reducer calls that store it or one of its secrets. The stored document and the
//! secrets live in one sealed envelope (`setjoin-config-secret`); the reducers only
//! ever see ciphertext.
use super::idv2::{compact, valid_source_key};
use super::idv2_writes::{members, BODY_MAX};
use super::scope_sets::go_quote;
use super::{deadline, envelope, go_escape, invalid, s, scope};
use serde_json::value::RawValue;
use serde_json::Value;
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ReceiptCommand, ScopedExecutor, StatementFailure, Type};
use std::collections::BTreeMap;

/// A validated source document.
pub struct Document {
    pub key: String,
    pub display_name: String,
    pub source_type: String,
    /// The canonical (compact, HTML-escaped) JSON Go stores and compares.
    pub canonical: String,
}

pub enum Validation {
    Valid(Document),
    /// Go's 400 detail.
    Refuse(String),
    /// Only a document `encoding/json` accepts but this parser cannot read (a lone
    /// surrogate escape, a number out of `f64` range): let Go answer.
    Forward,
}

fn refuse(text: &str) -> Validation {
    Validation::Refuse(text.to_owned())
}

/// Go's `boundedIdentityText`.
pub fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value == value.trim()
        && value.len() <= max
        && value.chars().all(|c| c >= '\u{20}' && c != '\u{7f}')
}

fn allowed_fields(kind: &str) -> Option<&'static [&'static str]> {
    Some(match kind {
        "local" => &[
            "type",
            "capabilities",
            "passwordPolicy",
            "passkeyPolicy",
            "mfaPolicy",
        ],
        "ad" | "ldap" => &[
            "type",
            "capabilities",
            "endpoint",
            "subjectAttribute",
            "baseDN",
            "bindDN",
            "userFilter",
            "groupFilter",
            "mapping",
            "deletionPolicy",
        ],
        "scim" => &[
            "type",
            "capabilities",
            "deletionPolicy",
            "mapping",
            "tokenLabel",
            "tokenExpiry",
        ],
        "saml" => &[
            "type",
            "capabilities",
            "registrationKey",
            "idpEntityId",
            "metadataUrl",
            "ssoUrl",
            "certificateRef",
            "spEntityId",
            "persistentNameId",
            "attributeMapping",
            "groupMapping",
            "jitPolicy",
        ],
        "oidc" => &[
            "type",
            "capabilities",
            "providerKey",
            "issuer",
            "clientId",
            "redirectUri",
            "scopes",
            "claimMapping",
            "subjectClaim",
            "jitPolicy",
        ],
        _ => return None,
    })
}

/// `json.Unmarshal(raw, &string)` of an optional raw member: `None` is a decode error.
fn string_of<T: AsRef<RawValue>>(raw: Option<T>) -> Option<String> {
    match raw {
        None => None,
        Some(raw) => serde_json::from_str::<Option<String>>(raw.as_ref().get())
            .ok()
            .map(Option::unwrap_or_default),
    }
}

fn validate_kind(kind: &str, spec: &BTreeMap<String, Box<RawValue>>) -> Result<(), String> {
    let text = |name: &str, max: usize| -> Result<String, String> {
        match string_of(spec.get(name)) {
            Some(v) if bounded(&v, max) => Ok(v),
            _ => Err(format!(
                "identity source spec.{name} is required and must be bounded text"
            )),
        }
    };
    match kind {
        "ad" | "ldap" => {
            text("baseDN", 2048)?;
            let subject = text("subjectAttribute", 128)?;
            if kind == "ad" && subject != "objectGUID" && subject != "msDS-ConsistencyGuid" {
                return Err(
                    "AD subjectAttribute must be objectGUID or msDS-ConsistencyGuid".into(),
                );
            }
            validate_endpoint(spec.get("endpoint"))?;
        }
        "saml" => {
            text("registrationKey", 255)?;
            text("idpEntityId", 2048)?;
        }
        "oidc" => {
            text("providerKey", 255)?;
            text("issuer", 2048)?;
            text("clientId", 1024)?;
            if string_of(spec.get("subjectClaim")).as_deref() != Some("sub") {
                return Err("OIDC subjectClaim must be sub".into());
            }
        }
        _ => {}
    }
    if let Some(raw) = spec.get("capabilities") {
        let capabilities: Option<BTreeMap<String, Box<RawValue>>> = serde_json::from_str(raw.get())
            .map_err(|_| "identity source capabilities must be an object".to_owned())?;
        let Some(capabilities) = capabilities else {
            return Err("identity source capabilities must be an object".into());
        };
        let allowed = [
            "authenticate",
            "provisionLifecycle",
            "passwordWriteback",
            "profileFields",
            "entitlements",
            "deltaCursor",
            "suspendDelete",
            "immutableSubject",
        ];
        if let Some(key) = capabilities.keys().find(|k| !allowed.contains(&k.as_str())) {
            return Err(format!(
                "unsupported identity source capability {}",
                go_quote(key)
            ));
        }
    }
    Ok(())
}

/// Go's `validateIdentityEndpoint`: strict `{host, port, tls}`.
fn validate_endpoint<T: AsRef<RawValue>>(raw: Option<T>) -> Result<(), String> {
    const FAIL: &str = "identity source endpoint requires bounded host, port, and tls";
    let raw = raw.ok_or(FAIL)?;
    let Ok(Some(object)) =
        serde_json::from_str::<Option<BTreeMap<String, Box<RawValue>>>>(raw.as_ref().get())
    else {
        // `null` decodes to the zero struct, which fails the bounds below as well.
        return Err(FAIL.into());
    };
    let (mut host, mut port, mut tls) = (String::new(), 0i64, String::new());
    for (name, value) in &object {
        match super::fold(name).as_str() {
            "host" => host = string_of(Some(value)).ok_or(FAIL)?,
            "tls" => tls = string_of(Some(value)).ok_or(FAIL)?,
            "port" => {
                let text = value.get();
                if text != "null" {
                    port = text.parse::<i64>().map_err(|_| FAIL.to_owned())?;
                }
            }
            _ => return Err(FAIL.into()),
        }
    }
    if !bounded(&host, 253) || !(1..=65535).contains(&port) || (tls != "ldaps" && tls != "starttls")
    {
        return Err(FAIL.into());
    }
    Ok(())
}

/// The JSON type name `encoding/json` uses in its decode errors, from a value's first byte.
fn json_kind(raw: &str) -> &'static str {
    match raw.trim_start().as_bytes().first() {
        Some(b'{') => "object",
        Some(b'[') => "array",
        Some(b'"') => "string",
        Some(b't' | b'f') => "bool",
        Some(b'n') => "null",
        _ => "number",
    }
}

/// Go's `validateIdentitySourceDocument` over the raw document value.
pub fn validate(raw: &str) -> Validation {
    if raw.is_empty() || raw.len() > BODY_MAX {
        return refuse("identity source document must be 1..65536 bytes");
    }
    // Go's `json.Decoder` keeps the FIRST decode error of the document, so each
    // branch below answers the moment it meets one: an unknown field, or a value of
    // the wrong JSON type (`json: cannot unmarshal <kind> into Go ...`).
    let mismatch = |kind: &str, place: &str, target: &str| {
        Validation::Refuse(format!(
            "invalid identity source document: json: cannot unmarshal {kind} into Go {place}of type {target}"
        ))
    };
    let mut api_version = String::new();
    let mut kind = String::new();
    let (mut key, mut display) = (String::new(), String::new());
    let mut spec_raw: Option<Box<RawValue>> = None;
    match json_kind(raw) {
        "null" => {}
        "object" => {
            let Some(pairs) = members(raw) else {
                return Validation::Forward;
            };
            for (name, value) in pairs {
                let text_of = |value: &RawValue, field: &str| {
                    if value.get() == "null" {
                        return Ok(String::new());
                    }
                    serde_json::from_str::<String>(value.get()).map_err(|_| {
                        mismatch(
                            json_kind(value.get()),
                            &format!("struct field identitySourceDocument.{field} "),
                            "string",
                        )
                    })
                };
                match super::fold(&name).as_str() {
                    "apiversion" => match text_of(&value, "apiVersion") {
                        Ok(v) => api_version = v,
                        Err(refusal) => return refusal,
                    },
                    "kind" => match text_of(&value, "kind") {
                        Ok(v) => kind = v,
                        Err(refusal) => return refusal,
                    },
                    "metadata" => {
                        if value.get() == "null" {
                            continue;
                        }
                        if json_kind(value.get()) != "object" {
                            return mismatch(
                                json_kind(value.get()),
                                "struct field identitySourceDocument.metadata ",
                                "admin.identitySourceMetadata",
                            );
                        }
                        let Some(pairs) = members(value.get()) else {
                            return Validation::Forward;
                        };
                        for (name, value) in pairs {
                            let (slot, field) = match super::fold(&name).as_str() {
                                "sourcekey" => (&mut key, "sourceKey"),
                                "displayname" => (&mut display, "displayName"),
                                _ => {
                                    return Validation::Refuse(format!(
                                        "invalid identity source document: json: unknown field {}",
                                        go_quote(&name)
                                    ))
                                }
                            };
                            if value.get() == "null" {
                                continue;
                            }
                            match serde_json::from_str::<String>(value.get()) {
                                Ok(v) => *slot = v,
                                Err(_) => {
                                    return mismatch(
                                        json_kind(value.get()),
                                        &format!(
                                            "struct field identitySourceMetadata.metadata.{field} "
                                        ),
                                        "string",
                                    )
                                }
                            }
                        }
                    }
                    "spec" => spec_raw = Some(value),
                    _ => {
                        return Validation::Refuse(format!(
                            "invalid identity source document: json: unknown field {}",
                            go_quote(&name)
                        ))
                    }
                }
            }
        }
        other => return mismatch(other, "value ", "admin.identitySourceDocument"),
    }
    if api_version != "setjoin.io/v1" || kind != "IdentitySource" {
        return refuse("unsupported identity source apiVersion or kind");
    }
    if !valid_source_key(&key) || !bounded(&display, 128) {
        return refuse("invalid identity source metadata");
    }
    let spec_text = spec_raw.as_ref().map(|r| r.get()).unwrap_or("");
    let spec: BTreeMap<String, Box<RawValue>> =
        match serde_json::from_str::<Option<BTreeMap<String, Box<RawValue>>>>(spec_text) {
            Ok(Some(map)) => map,
            _ => return refuse("identity source spec must be an object"),
        };
    let Some(source_type) = string_of(spec.get("type")) else {
        return refuse("identity source spec.type is required");
    };
    let Some(allowed) = allowed_fields(&source_type) else {
        return refuse("unsupported identity source type");
    };
    if let Some(name) = spec.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Validation::Refuse(format!(
            "unsupported identity source spec field {}",
            go_quote(name)
        ));
    }
    if let Err(detail) = validate_kind(&source_type, &spec) {
        return Validation::Refuse(detail);
    }
    let canonical = go_escape(&format!(
        "{{\"apiVersion\":\"setjoin.io/v1\",\"kind\":\"IdentitySource\",\"metadata\":{{\"sourceKey\":{},\"displayName\":{}}},\"spec\":{}}}",
        s(&key),
        s(&display),
        compact(spec_text)
    ));
    Validation::Valid(Document {
        key,
        display_name: display,
        source_type,
        canonical,
    })
}

/// `identitySourceCapabilities`: the fixed capability map for a kind (sorted keys).
pub fn capabilities(kind: &str) -> String {
    let authn = matches!(kind, "local" | "saml" | "oidc");
    let provision = matches!(kind, "local" | "ad" | "ldap" | "scim");
    format!(
        "{{\"authenticate\":{authn},\"provision_lifecycle\":{provision},\"stable_immutable_subject\":true}}"
    )
}

/// The sealed plaintext: `{"document":<canonical>,"secrets":{...}}` as `json.Marshal` writes it.
pub fn stored_plaintext(document: &str, secrets: &BTreeMap<String, String>) -> String {
    let items: Vec<String> = secrets
        .iter()
        .map(|(k, v)| format!("{}:{}", s(k), s(v)))
        .collect();
    go_escape(&format!(
        "{{\"document\":{},\"secrets\":{{{}}}}}",
        compact(document),
        items.join(",")
    ))
}

fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: "F01",
        command: name,
    }
}

/// Everything `identity_source_config_apply` takes besides the actor.
pub struct Apply<'a> {
    pub document: &'a Document,
    pub envelope: &'a [u8],
    pub key_version: i64,
    pub expected: Option<i64>,
    pub idempotency: &'a str,
    pub reason: &'a str,
}

/// `POST /sources` and `PUT /sources/{key}`: Go's single `identity_source_config_apply`.
pub async fn apply(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    input: &Apply<'_>,
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    let auth = scope(actor);
    let capabilities = capabilities(&input.document.source_type);
    let mapping: i64 = 1;
    setjoin_pg::run_receipted_command(
        worker,
        command("identity_source_config_apply"),
        &envelope(
            &auth,
            operation,
            &format!("{}:{}:{:?}:{}", input.document.key, input.document.canonical, input.expected, input.idempotency),
        ),
        &auth,
        deadline(),
        "SELECT identity_source_config_apply($2,$4,$5,$6,$7::text::jsonb,$8,$9,$10,$11,$12::text::uuid,$13)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&input.document.key, Type::TEXT),
            (&input.document.display_name, Type::TEXT),
            (&input.document.source_type, Type::TEXT),
            (&capabilities, Type::TEXT),
            (&input.envelope, Type::BYTEA),
            (&input.key_version, Type::INT8),
            (&mapping, Type::INT8),
            (&input.expected, Type::INT8),
            (&input.idempotency, Type::TEXT),
            (&input.reason, Type::TEXT),
        ],
        |rows| {
            rows.first()
                .ok_or_else(invalid)?
                .try_get::<_, Option<String>>(0)
                .map_err(|_| invalid())
        },
    )
    .await
}

/// `PUT .../secrets/{name}` and `POST .../secrets/{name}/rotate`.
#[allow(clippy::too_many_arguments)]
pub async fn set_secret(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    key: &str,
    name: &str,
    envelope_bytes: &[u8],
    key_version: i64,
    expected: i64,
    rotate: bool,
    idempotency: &str,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    let auth = scope(actor);
    let grace: i32 = if rotate { 3600 } else { 0 };
    setjoin_pg::run_receipted_command(
        worker,
        command("identity_source_secret_set"),
        &envelope(&auth, operation, &format!("{key}:{name}:{expected}:{rotate}:{idempotency}")),
        &auth,
        deadline(),
        "SELECT identity_source_secret_set($2,$4,$5,$6,$7,$8,$9,$10,$11::text::uuid,$12)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&key, Type::TEXT),
            (&name, Type::TEXT),
            (&envelope_bytes, Type::BYTEA),
            (&key_version, Type::INT8),
            (&expected, Type::INT8),
            (&rotate, Type::BOOL),
            (&grace, Type::INT4),
            (&idempotency, Type::TEXT),
            (&reason, Type::TEXT),
        ],
        |rows| {
            rows.first()
                .ok_or_else(invalid)?
                .try_get::<_, Option<String>>(0)
                .map_err(|_| invalid())
        },
    )
    .await
}

/// `admin.IdentitySourceRuntimeConfig`: the decrypted runtime projection of an
/// active AD or LDAP source, handed to the directory-sync catalog runtime.
#[derive(Clone, Default)]
pub struct RuntimeConfig {
    pub source_key: String,
    pub kind: String,
    pub host: String,
    pub port: i64,
    pub transport: String,
    pub base_dn: String,
    pub bind_dn: String,
    pub subject_attribute: String,
    pub user_filter: String,
    pub group_filter: String,
    pub password: String,
}

/// Go's `DecodeIdentitySourceRuntime`: open the sealed envelope, revalidate the
/// stored document with the same validator plan/apply uses, and project the
/// connector fields plus the base64 `bindPassword`. Any failure keeps the source
/// out of the runtime; the text is only ever logged.
pub fn decode_runtime(
    codec: Option<&setjoin_config_secret::ConfigSecretCodec>,
    source_key: &str,
    row_kind: &str,
    envelope: &[u8],
) -> Result<RuntimeConfig, String> {
    use base64::Engine;
    let Some(codec) = codec.filter(|_| !envelope.is_empty()) else {
        return Err("identity source secret codec or envelope is unavailable".into());
    };
    let stored = super::idv2_ops::decode_stored(codec, source_key, envelope)
        .ok_or("decrypt identity source runtime: envelope cannot be opened or decoded")?;
    let document = match validate(&stored.raw) {
        Validation::Valid(document) => document,
        Validation::Refuse(detail) => {
            return Err(format!(
                "validate identity source runtime document: {detail}"
            ))
        }
        Validation::Forward => {
            return Err("validate identity source runtime document: invalid document".into())
        }
    };
    if document.key != source_key {
        return Err("identity source runtime key does not match catalog row".into());
    }
    let spec: Value = serde_json::from_str::<Value>(&stored.raw)
        .ok()
        .and_then(|top| {
            top.as_object().and_then(|map| {
                map.iter()
                    .find(|(name, _)| super::fold(name) == "spec")
                    .map(|(_, v)| v.clone())
            })
        })
        .ok_or("decode identity source runtime spec: missing")?;
    let text = |object: &Value, name: &str| -> Result<String, String> {
        match object.get(name) {
            None | Some(Value::Null) => Ok(String::new()),
            Some(Value::String(s)) => Ok(s.clone()),
            Some(_) => Err(format!("decode identity source runtime spec: {name}")),
        }
    };
    let kind = text(&spec, "type")?;
    if kind != row_kind || (kind != "ad" && kind != "ldap") {
        return Err("identity source runtime kind does not match catalog row".into());
    }
    let endpoint = spec.get("endpoint").cloned().unwrap_or(Value::Null);
    let port = match endpoint.get("port") {
        None | Some(Value::Null) => 0,
        Some(v) => v
            .as_i64()
            .ok_or("decode identity source runtime spec: endpoint.port")?,
    };
    let encoded = stored
        .secrets
        .get("bindPassword")
        .filter(|v| !v.is_empty())
        .ok_or("identity source bind password is not configured")?;
    let password = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()
        .filter(|bytes| !bytes.is_empty())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or("identity source bind password encoding is invalid")?;
    Ok(RuntimeConfig {
        source_key: source_key.to_owned(),
        kind,
        host: text(&endpoint, "host")?,
        port,
        transport: text(&endpoint, "tls")?,
        base_dn: text(&spec, "baseDN")?,
        bind_dn: text(&spec, "bindDN")?,
        subject_attribute: text(&spec, "subjectAttribute")?,
        user_filter: text(&spec, "userFilter")?,
        group_filter: text(&spec, "groupFilter")?,
        password,
    })
}
