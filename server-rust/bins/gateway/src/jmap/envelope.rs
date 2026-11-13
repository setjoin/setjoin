//! The JMAP request envelope both commands share: a body that is exactly
//! `{"using": [...], "methodCalls": [[name, args, callId]]}` with the mail
//! capability, one method call of the expected name, and a call id Rust can
//! echo without escaping. Each command's classifier ([`super::seen`],
//! [`super::list`]) starts here and then checks only its own arguments.

use serde_json::{Map, Value};

/// The capability Go requires in `using` for the mail methods.
pub const MAIL_CAPABILITY: &str = "urn:ietf:params:jmap:mail";

/// The single method call of a request body.
pub struct SingleCall {
    pub args: Value,
    /// The call's arguments exactly as written (for values passed on as JSON).
    pub raw_args: String,
    /// The method call id, echoed back in the response.
    pub client_id: String,
}

/// `Some` only when `body` is one call to `method` in the shared envelope.
pub fn single_call(body: &[u8], method: &str) -> Option<SingleCall> {
    single_call_with_capability(body, method, MAIL_CAPABILITY)
}

pub fn single_call_with_capability(
    body: &[u8],
    method: &str,
    required: &str,
) -> Option<SingleCall> {
    let mut root: Value = serde_json::from_slice(body).ok()?;
    exact_keys(&root, &["using", "methodCalls"], &[])?;
    let mut has_required = false;
    for capability in root.get("using")?.as_array()? {
        // Go decodes `using` as []string: a non-string fails the request.
        has_required |= capability.as_str()? == required;
    }
    if !has_required {
        return None;
    }
    let [call] = root.get_mut("methodCalls")?.as_array_mut()?.as_mut_slice() else {
        return None;
    };
    let [name, args, client_id] = call.as_array_mut()?.as_mut_slice() else {
        return None;
    };
    if name.as_str()? != method {
        return None;
    }
    let client_id = client_id.as_str()?;
    if !safe_client_id(client_id) {
        return None;
    }
    let raw_args = raw_args(body)?;
    Some(SingleCall {
        client_id: client_id.to_owned(),
        args: args.take(),
        raw_args,
    })
}

fn raw_args(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Root<'a> {
        #[serde(rename = "methodCalls", borrow)]
        calls: Vec<(String, &'a serde_json::value::RawValue, String)>,
    }
    let root: Root<'_> = serde_json::from_str(std::str::from_utf8(body).ok()?).ok()?;
    let [(_, args, _)] = root.calls.as_slice() else {
        return None;
    };
    Some(args.get().to_owned())
}

/// `v` as an object holding every `required` key, optionally the `optional`
/// ones, and nothing else.
pub(crate) fn exact_keys<'a>(
    v: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Option<&'a Map<String, Value>> {
    let obj = v.as_object()?;
    if !required.iter().all(|k| obj.contains_key(*k)) {
        return None;
    }
    obj.keys()
        .all(|k| required.contains(&k.as_str()) || optional.contains(&k.as_str()))
        .then_some(obj)
}

/// A positive BIGINT in canonical decimal (no sign, no leading zero), so the
/// id Rust acts on is the one the reducer's `::BIGINT` cast would produce and
/// the response echoes it byte-identically.
pub(crate) fn canonical_id(s: &str) -> Option<i64> {
    if s.is_empty() || s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<i64>().ok().filter(|n| *n > 0)
}

/// Client ids Rust echoes without any JSON escaping question.
pub(crate) fn safe_client_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

/// Go struct field names match without ASCII case. Preserve raw field JSON
/// (notably create/update numeric values). Duplicate/non-ASCII struct field
/// names remain with the shared execution/argument engine in #318, before I/O.
pub(crate) fn struct_arguments(
    raw: &str,
    known: &[&str],
) -> Option<std::collections::BTreeMap<String, Box<serde_json::value::RawValue>>> {
    use serde::de::{self, MapAccess, Visitor};
    use serde::Deserializer;
    struct Fields<'a>(&'a [&'a str]);
    impl<'de> Visitor<'de> for Fields<'_> {
        type Value = std::collections::BTreeMap<String, Box<serde_json::value::RawValue>>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a Go struct argument object")
        }
        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(Default::default())
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut fields = std::collections::BTreeMap::new();
            while let Some(key) = map.next_key::<String>()? {
                if !key.is_ascii() {
                    return Err(de::Error::custom("argument field grammar belongs to #318"));
                }
                if let Some(name) = self.0.iter().find(|name| name.eq_ignore_ascii_case(&key)) {
                    let value = map.next_value::<Box<serde_json::value::RawValue>>()?;
                    if fields.insert((*name).to_owned(), value).is_some() {
                        return Err(de::Error::custom("duplicate struct fields belong to #318"));
                    }
                } else {
                    map.next_value::<de::IgnoredAny>()?;
                }
            }
            Ok(fields)
        }
    }
    serde_json::Deserializer::from_str(raw)
        .deserialize_any(Fields(known))
        .ok()
}
