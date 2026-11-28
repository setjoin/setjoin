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

/// Go struct field names match exact or Unicode case-folded (last duplicate wins;
/// unknown/non-ASCII keys ignored).
fn prev_is_mistyped(name: &str, raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed == "null" {
        return false;
    }
    match name {
        "accountId" | "sinceState" | "sinceQueryState" | "ifInState" | "threadId" | "emailId"
        | "fromAccountId" | "toAccountId" => go_string_field(trimmed).is_err(),
        "position" | "limit" | "maxChanges" => go_i64_field(trimmed).is_err(),
        "ids" | "destroy" | "properties" | "hashes" | "typeNames" => {
            go_string_array_field(trimmed).is_err()
        }
        "create" | "update" | "filter" => !trimmed.starts_with('{'),
        "sort" => !trimmed.starts_with('['),
        _ => false,
    }
}

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
            let mut fields: Self::Value = std::collections::BTreeMap::new();
            while let Some(key) = map.next_key::<String>()? {
                let target = self.0.iter().find(|name| **name == key).or_else(|| {
                    let folded = crate::guests_input::fold(&key);
                    self.0
                        .iter()
                        .find(|name| crate::guests_input::fold(name) == folded)
                });
                if let Some(name) = target {
                    let value = map.next_value::<Box<serde_json::value::RawValue>>()?;
                    let scalar_null = value.get().trim() == "null"
                        && matches!(
                            *name,
                            "accountId"
                                | "sinceState"
                                | "sinceQueryState"
                                | "ifInState"
                                | "threadId"
                                | "emailId"
                                | "fromAccountId"
                                | "toAccountId"
                                | "position"
                                | "limit"
                                | "maxChanges"
                        );
                    if let Some(prev) = fields.get(*name) {
                        if scalar_null || prev_is_mistyped(name, prev.get()) {
                            continue;
                        }
                    }
                    fields.insert((*name).to_owned(), value);
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

/// Decode a Go `string` field (`null` -> `None`, JSON string -> `Some(s)`).
pub(crate) fn go_string_field(raw: &str) -> Result<Option<String>, String> {
    let trimmed = raw.trim();
    if trimmed == "null" {
        return Ok(None);
    }
    let bytes = crate::guests_input::go_json_bytes(trimmed.as_bytes());
    serde_json::from_slice::<String>(&bytes)
        .map(Some)
        .map_err(|_| "invalid string argument".to_owned())
}

/// Decode a Go `[]string` field (`null` -> `None`, array elements `null` -> `""`).
pub(crate) fn go_string_array_field(raw: &str) -> Result<Option<Vec<String>>, String> {
    let trimmed = raw.trim();
    if trimmed == "null" {
        return Ok(None);
    }
    let items: Vec<Box<serde_json::value::RawValue>> =
        serde_json::from_str(trimmed).map_err(|_| "invalid string array argument".to_owned())?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(go_string_field(item.get())?.unwrap_or_default());
    }
    Ok(Some(out))
}

/// Decode a Go `int` / `int64` field (`null` -> `None`, integer JSON -> `Some(n)`).
pub(crate) fn go_i64_field(raw: &str) -> Result<Option<i64>, String> {
    let trimmed = raw.trim();
    if trimmed == "null" {
        return Ok(None);
    }
    serde_json::from_str::<i64>(trimmed)
        .map(Some)
        .map_err(|_| "invalid integer argument".to_owned())
}

#[cfg(test)]
mod tests {
    use super::struct_arguments;

    #[test]
    fn struct_arguments_matches_go_duplicate_and_unicode_rules() {
        let fields = struct_arguments(
            r#"{"accountId":"1","accountid":"2","accountId":null,"ignored_é":true}"#,
            &["accountId", "ids"],
        )
        .expect("object");
        assert_eq!(fields["accountId"].get(), r#""2""#);
        let unicode = struct_arguments(r#"{"id\u017f":"ok"}"#, &["ids"]).expect("unicode fold");
        assert_eq!(unicode["ids"].get(), r#""ok""#);
        let bad_first =
            struct_arguments(r#"{"accountId":true,"accountid":"12"}"#, &["accountId"]).unwrap();
        assert_eq!(bad_first["accountId"].get(), "true");
        let bad_arr = struct_arguments(r#"{"ids":[123],"ids":["1"]}"#, &["ids"]).unwrap();
        assert_eq!(bad_arr["ids"].get(), "[123]");
    }
}
