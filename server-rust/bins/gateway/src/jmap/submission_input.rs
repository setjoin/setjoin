//! Go's anonymous EmailSubmission request structs: ordered, case-folded
//! fields, unknown keys ignored, null scalars preserve the prior value.
use serde::de::{MapAccess, Visitor};
use serde_json::value::RawValue;
use std::fmt;

#[derive(Debug)]
pub(crate) struct Failure {
    pub kind: &'static str,
    pub status: u16,
    pub detail: String,
}
impl Failure {
    pub fn invalid(detail: impl Into<String>) -> Self {
        Self {
            kind: "invalidArguments",
            status: 400,
            detail: detail.into(),
        }
    }
    #[allow(dead_code)]
    pub fn account(detail: &str) -> Self {
        Self {
            kind: "accountNotFound",
            status: 400,
            detail: detail.into(),
        }
    }
}
#[derive(Default)]
pub(super) struct Input {
    pub account: String,
    pub email: String,
    pub ids: Option<Vec<String>>,
    pub create: Option<String>,
    pub filter: Option<String>,
    pub position: i64,
    pub limit: i64,
}

struct Fields(Vec<(String, Box<RawValue>)>);
impl<'de> serde::Deserialize<'de> for Fields {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Object;
        impl<'de> Visitor<'de> for Object {
            type Value = Fields;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Fields, E> {
                Ok(Fields(Vec::new()))
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Fields, M::Error> {
                let mut fields = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    fields.push(entry);
                }
                Ok(Fields(fields))
            }
        }
        d.deserialize_any(Object)
    }
}
fn kind(raw: &str) -> &'static str {
    match raw.as_bytes().first() {
        Some(b'"') => "string",
        Some(b'[') => "array",
        Some(b'{') => "object",
        Some(b't' | b'f') => "bool",
        _ => "number",
    }
}
fn type_error(raw: &str, field: &str, ty: &str) -> Failure {
    let value = if ty == "int" && kind(raw) == "number" {
        format!("number {raw}")
    } else {
        kind(raw).into()
    };
    Failure::invalid(format!(
        "json: cannot unmarshal {value} into Go struct field .{field} of type {ty}"
    ))
}
fn string(raw: &str, field: &str) -> Result<Option<String>, Failure> {
    if raw == "null" {
        return Ok(None);
    }
    let bytes = crate::guests_input::go_json_bytes(raw.as_bytes());
    serde_json::from_slice::<String>(&bytes)
        .map(Some)
        .map_err(|_| type_error(raw, field, "string"))
}
fn integer(raw: &str, field: &str) -> Result<Option<i64>, Failure> {
    if raw == "null" {
        return Ok(None);
    }
    raw.parse::<i64>()
        .map(Some)
        .map_err(|_| type_error(raw, field, "int"))
}

pub(super) fn decode(method: &str, raw: &str) -> Result<Input, Failure> {
    let fields: Fields =
        serde_json::from_str(raw).map_err(|_| Failure::invalid("args must be a JSON object"))?;
    let mut input = Input::default();
    for (name, value) in fields.0 {
        let key = crate::guests_input::fold(&name);
        let raw = value.get();
        match key.as_str() {
            "accountid" => {
                if let Some(v) = string(raw, "accountId")? {
                    input.account = v;
                }
            }
            "emailid" if method == "EmailSubmission/cancel" => {
                if let Some(v) = string(raw, "emailId")? {
                    input.email = v;
                }
            }
            "create" if method == "EmailSubmission/set" => input.create = Some(raw.into()),
            "filter" if method == "EmailSubmission/query" => {
                input.filter = (raw != "null").then(|| raw.to_owned())
            }
            "position" if method == "EmailSubmission/query" => {
                if let Some(v) = integer(raw, "position")? {
                    input.position = v;
                }
            }
            "limit" if method == "EmailSubmission/query" => {
                if let Some(v) = integer(raw, "limit")? {
                    input.limit = v;
                }
            }
            "ids" if method == "EmailSubmission/get" => {
                if raw == "null" {
                    input.ids = None;
                    continue;
                }
                let items: Vec<Box<RawValue>> =
                    serde_json::from_str(raw).map_err(|_| type_error(raw, "ids", "[]string"))?;
                let mut ids = Vec::new();
                for item in items {
                    ids.push(string(item.get(), "ids")?.unwrap_or_default());
                }
                input.ids = Some(ids);
            }
            _ => {}
        }
    }
    Ok(input)
}
