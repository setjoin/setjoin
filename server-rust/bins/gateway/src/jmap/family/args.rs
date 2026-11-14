//! Go `encoding/json` decoding into a handler's request struct: field names
//! match exactly or case-folded, unknown keys are ignored, `null` keeps the
//! zero value (slices become nil, a `json.RawMessage` keeps `null`), the last
//! duplicate wins, and the first type error in document order is the result,
//! worded as Go words it.
use std::fmt;

use serde::de::{MapAccess, Visitor};
use serde_json::value::RawValue;

use super::MethodError;

/// The Go field type of one request struct member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Go `string`.
    Str,
    /// Go `int`.
    Int,
    /// Go `int64`.
    Int64,
    /// Go `bool`.
    Bool,
    /// Go `[]string`.
    Strings,
    /// Go `[]int64`.
    Ints,
    /// Go `json.RawMessage`.
    Raw,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Field {
    Str(String),
    Int(i64),
    Bool(bool),
    Strings(Option<Vec<String>>),
    Ints(Option<Vec<i64>>),
    Raw(String),
}

/// A decoded request struct.
pub(crate) struct Args {
    fields: &'static [(&'static str, Kind)],
    values: Vec<Option<Field>>,
}

impl Args {
    fn get(&self, name: &str) -> Option<&Field> {
        let index = self
            .fields
            .iter()
            .position(|(declared, _)| *declared == name)
            .unwrap_or_else(|| panic!("argument {name} is not declared"));
        self.values[index].as_ref()
    }

    /// Go's string value; `""` when absent or null.
    pub(crate) fn str(&self, name: &str) -> &str {
        match self.get(name) {
            Some(Field::Str(value)) => value,
            _ => "",
        }
    }

    /// Go's int value; `0` when absent or null.
    pub(crate) fn int(&self, name: &str) -> i64 {
        match self.get(name) {
            Some(Field::Int(value)) => *value,
            _ => 0,
        }
    }

    pub(crate) fn bool(&self, name: &str) -> bool {
        matches!(self.get(name), Some(Field::Bool(true)))
    }

    /// `None` when absent or null (Go nil slice).
    pub(crate) fn strings(&self, name: &str) -> Option<&[String]> {
        match self.get(name) {
            Some(Field::Strings(Some(values))) => Some(values),
            _ => None,
        }
    }

    /// `None` when absent or null (Go nil slice).
    pub(crate) fn ints(&self, name: &str) -> Option<&[i64]> {
        match self.get(name) {
            Some(Field::Ints(Some(values))) => Some(values),
            _ => None,
        }
    }

    /// The raw JSON (a literal `null` included); `None` when the key was absent.
    pub(crate) fn raw(&self, name: &str) -> Option<&str> {
        match self.get(name) {
            Some(Field::Raw(value)) => Some(value),
            _ => None,
        }
    }
}

struct Members(Vec<(String, Box<RawValue>)>);

impl<'de> serde::Deserialize<'de> for Members {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Object;
        impl<'de> Visitor<'de> for Object {
            type Value = Members;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object or null")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Members, E> {
                Ok(Members(Vec::new()))
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Members, M::Error> {
                let mut members = Vec::new();
                while let Some(entry) = map.next_entry::<String, Box<RawValue>>()? {
                    members.push(entry);
                }
                Ok(Members(members))
            }
        }
        deserializer.deserialize_any(Object)
    }
}

/// Decode `raw` (a JSON object or `null`) into the struct `owner` (Go's type
/// name, `""` for an anonymous struct) with the declared `fields`.
pub(crate) fn decode(
    raw: &str,
    owner: &str,
    fields: &'static [(&'static str, Kind)],
) -> Result<Args, MethodError> {
    let members: Members = serde_json::from_str(raw)
        .map_err(|_| MethodError::new("invalidArguments", "args must be a JSON object"))?;
    let mut values: Vec<Option<Field>> = vec![None; fields.len()];
    let mut first_error: Option<String> = None;
    for (key, value) in members.0 {
        let Some(index) = position(fields, &key) else {
            continue;
        };
        let (name, kind) = fields[index];
        match field(value.get(), kind) {
            Ok(Some(decoded)) => values[index] = Some(decoded),
            Ok(None) => {}
            Err((what, ty)) => {
                if first_error.is_none() {
                    first_error = Some(format!(
                        "json: cannot unmarshal {what} into Go struct field {owner}.{name} of type {ty}"
                    ));
                }
            }
        }
    }
    match first_error {
        Some(detail) => Err(MethodError::new("invalidArguments", &detail)),
        None => Ok(Args { fields, values }),
    }
}

/// Go prefers an exact field name, then a case-folded one.
fn position(fields: &[(&'static str, Kind)], key: &str) -> Option<usize> {
    fields
        .iter()
        .position(|(name, _)| *name == key)
        .or_else(|| {
            let folded = crate::guests_input::fold(key);
            fields
                .iter()
                .position(|(name, _)| crate::guests_input::fold(name) == folded)
        })
}

fn kind_of(raw: &str) -> &'static str {
    match raw.as_bytes().first() {
        Some(b'"') => "string",
        Some(b'[') => "array",
        Some(b'{') => "object",
        Some(b't' | b'f') => "bool",
        _ => "number",
    }
}

fn string(raw: &str) -> Option<String> {
    if !raw.starts_with('"') {
        return None;
    }
    serde_json::from_slice::<String>(&crate::guests_input::go_json_bytes(raw.as_bytes())).ok()
}

/// Go's integer decoding: the `UnmarshalTypeError` value on failure.
fn integer(raw: &str) -> Result<i64, String> {
    match kind_of(raw) {
        "number" => raw.parse::<i64>().map_err(|_| format!("number {raw}")),
        other => Err(other.to_owned()),
    }
}

type TypeError = (String, &'static str);

fn field(raw: &str, kind: Kind) -> Result<Option<Field>, TypeError> {
    if raw == "null" {
        return Ok(match kind {
            Kind::Strings => Some(Field::Strings(None)),
            Kind::Ints => Some(Field::Ints(None)),
            Kind::Raw => Some(Field::Raw("null".to_owned())),
            Kind::Str | Kind::Int | Kind::Int64 | Kind::Bool => None,
        });
    }
    match kind {
        Kind::Str => string(raw)
            .map(|value| Some(Field::Str(value)))
            .ok_or_else(|| (kind_of(raw).to_owned(), "string")),
        Kind::Int => integer(raw)
            .map(|value| Some(Field::Int(value)))
            .map_err(|what| (what, "int")),
        Kind::Int64 => integer(raw)
            .map(|value| Some(Field::Int(value)))
            .map_err(|what| (what, "int64")),
        Kind::Bool => match raw {
            "true" => Ok(Some(Field::Bool(true))),
            "false" => Ok(Some(Field::Bool(false))),
            _ => Err((kind_of(raw).to_owned(), "bool")),
        },
        Kind::Strings => {
            let items: Vec<Box<RawValue>> =
                serde_json::from_str(raw).map_err(|_| (kind_of(raw).to_owned(), "[]string"))?;
            let mut values = Vec::with_capacity(items.len());
            for item in &items {
                let item = item.get();
                if item == "null" {
                    values.push(String::new());
                    continue;
                }
                values.push(string(item).ok_or_else(|| (kind_of(item).to_owned(), "string"))?);
            }
            Ok(Some(Field::Strings(Some(values))))
        }
        Kind::Ints => {
            let items: Vec<Box<RawValue>> =
                serde_json::from_str(raw).map_err(|_| (kind_of(raw).to_owned(), "[]int64"))?;
            let mut values = Vec::with_capacity(items.len());
            for item in &items {
                let item = item.get();
                if item == "null" {
                    values.push(0);
                    continue;
                }
                values.push(integer(item).map_err(|what| (what, "int64"))?);
            }
            Ok(Some(Field::Ints(Some(values))))
        }
        Kind::Raw => Ok(Some(Field::Raw(raw.to_owned()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &[(&str, Kind)] = &[("accountId", Kind::Str), ("limit", Kind::Int)];

    fn detail(result: Result<Args, MethodError>) -> String {
        let error = result.err().expect("a decode error");
        assert_eq!(error.kind, "invalidArguments");
        error.detail
    }

    #[test]
    fn type_errors_use_go_wording() {
        assert_eq!(
            detail(decode(r#"{"accountId":7}"#, "", ACCOUNT)),
            "json: cannot unmarshal number into Go struct field .accountId of type string"
        );
        assert_eq!(
            detail(decode(r#"{"limit":"5"}"#, "", ACCOUNT)),
            "json: cannot unmarshal string into Go struct field .limit of type int"
        );
        assert_eq!(
            detail(decode(r#"{"limit":1.5}"#, "", ACCOUNT)),
            "json: cannot unmarshal number 1.5 into Go struct field .limit of type int"
        );
        const SET: &[(&str, Kind)] = &[("destroy", Kind::Strings)];
        assert_eq!(
            detail(decode(r#"{"destroy":[1]}"#, "SetRequest", SET)),
            "json: cannot unmarshal number into Go struct field SetRequest.destroy of type string"
        );
        assert_eq!(
            detail(decode(r#"{"accountId":true,"limit":"x"}"#, "", ACCOUNT)),
            "json: cannot unmarshal bool into Go struct field .accountId of type string"
        );
    }

    #[test]
    fn names_fold_and_the_last_duplicate_wins() {
        let args = decode(
            r#"{"accountId":"5","ACCOUNTID":"6","other":1}"#,
            "",
            ACCOUNT,
        )
        .expect("decoded");
        assert_eq!(args.str("accountId"), "6");
        const SINCE: &[(&str, Kind)] = &[("sinceState", Kind::Str), ("keywords", Kind::Raw)];
        let args = decode(
            "{\"\u{17f}inceState\":\"3\",\"\u{212a}eywords\":{\"a\":true}}",
            "",
            SINCE,
        )
        .expect("decoded");
        assert_eq!(args.str("sinceState"), "3");
        assert_eq!(args.raw("keywords"), Some(r#"{"a":true}"#));
    }

    #[test]
    fn null_keeps_zero_values() {
        const ALL: &[(&str, Kind)] = &[
            ("a", Kind::Str),
            ("b", Kind::Int),
            ("c", Kind::Bool),
            ("d", Kind::Strings),
            ("e", Kind::Raw),
            ("f", Kind::Ints),
        ];
        let args = decode("null", "", ALL).expect("null args");
        assert_eq!(
            (args.str("a"), args.int("b"), args.bool("c")),
            ("", 0, false)
        );
        assert!(args.strings("d").is_none() && args.raw("e").is_none() && args.ints("f").is_none());
        let args =
            decode(r#"{"a":null,"d":null,"e":null,"f":[1,null]}"#, "", ALL).expect("decoded");
        assert_eq!(args.str("a"), "");
        assert!(args.strings("d").is_none());
        assert_eq!(args.raw("e"), Some("null"));
        assert_eq!(args.ints("f"), Some(&[1, 0][..]));
    }

    #[test]
    fn undecodable_strings_are_method_errors_not_panics() {
        assert!(decode(r#"{"accountId":"\ud800"}"#, "", ACCOUNT).is_err());
        assert!(decode("[1]", "", ACCOUNT).is_err());
    }
}
