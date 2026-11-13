//! Strict, single-value Go struct request decoding for Exchange handlers.
use crate::{guests_input, Body};
use http_body_util::BodyExt;
use hyper::Request;
use serde::{
    de::{MapAccess, Visitor},
    Deserialize,
};
use serde_json::{value::RawValue, Value};
use std::collections::BTreeMap;
#[derive(Clone, Copy)]
pub enum Kind {
    Int,
    Text,
    OptionalText,
    OptionalInt,
    Json,
}
pub struct Fields {
    values: BTreeMap<&'static str, Value>,
    order: Vec<&'static str>,
    raw: BTreeMap<&'static str, String>,
}
impl Fields {
    pub fn raw_json(&self, k: &str) -> Option<&str> {
        self.raw.get(k).map(String::as_str)
    }
    pub fn optional_int(&self, k: &str) -> Option<i64> {
        self.values[k].as_i64()
    }
    pub fn int(&self, k: &str) -> i64 {
        self.values[k].as_i64().unwrap_or(0)
    }
    pub fn text(&self, k: &str) -> &str {
        self.values[k].as_str().unwrap_or("")
    }
    pub fn optional_text(&self, k: &str) -> Option<&str> {
        self.values[k].as_str()
    }
    pub fn canonical(&self) -> String {
        let fields: Vec<_> = self
            .order
            .iter()
            .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), self.values[*k]))
            .collect();
        setjoin_mailboxes::go_escape(&format!("{{{}}}", fields.join(",")))
    }
}
struct Members(Vec<(String, Box<RawValue>)>);
impl<'de> Deserialize<'de> for Members {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Members;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> Result<Members, M::Error> {
                let mut out = vec![];
                while let Some(k) = m.next_key::<String>()? {
                    out.push((k, m.next_value()?));
                }
                Ok(Members(out))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Members, E> {
                Ok(Members(vec![]))
            }
        }
        d.deserialize_any(V)
    }
}
pub async fn read(
    r: &mut Request<Body>,
    schema: &[(&'static str, Kind)],
) -> Result<Fields, String> {
    let mut bytes = vec![];
    while let Some(frame) = r.body_mut().frame().await {
        let frame = frame.map_err(|_| "unexpected EOF")?;
        if let Ok(b) = frame.into_data() {
            if b.len() > (1usize << 20).saturating_sub(bytes.len()) {
                return Err("http: request body too large".into());
            }
            bytes.extend_from_slice(&b);
        }
    }
    let fixed = guests_input::go_json_bytes(&bytes);
    let mut stream = serde_json::Deserializer::from_slice(&fixed).into_iter::<Box<RawValue>>();
    let first = match stream.next() {
        None => return Err("EOF".into()),
        Some(Ok(v)) => v,
        Some(Err(e)) => return Err(syntax_error(&e, &fixed)),
    };
    let members: Members = serde_json::from_str(first.get()).map_err(|_| {
        let value: Value = serde_json::from_str(first.get()).expect("validated JSON value");
        let typ = if value.is_array() {
            "array"
        } else if value.is_boolean() {
            "bool"
        } else if value.is_string() {
            "string"
        } else {
            "number"
        };
        format!(
            "json: cannot unmarshal {typ} into Go value of type {}",
            go_struct(schema)
        )
    })?;
    let mut values = BTreeMap::new();
    let mut order = vec![];
    let mut raw_values = BTreeMap::new();
    for (key, kind) in schema {
        values.insert(
            *key,
            match kind {
                Kind::Int => Value::from(0),
                Kind::Text => Value::from(""),
                Kind::OptionalText | Kind::OptionalInt | Kind::Json => Value::Null,
            },
        );
        order.push(*key);
    }
    for (key, raw) in members.0 {
        let Some((name, kind)) = schema
            .iter()
            .find(|(name, _)| guests_input::fold(name) == guests_input::fold(&key))
        else {
            return Err(format!(
                "json: unknown field {}",
                serde_json::to_string(&key).unwrap()
            ));
        };
        let v: Value = serde_json::from_str(raw.get()).map_err(|_| "invalid JSON")?;
        if matches!(kind, Kind::Json) {
            raw_values.insert(*name, raw.get().to_owned());
        }
        if v.is_null() {
            if matches!(kind, Kind::OptionalText | Kind::OptionalInt | Kind::Json) {
                values.insert(*name, v);
            }
            continue;
        }
        let valid = match kind {
            Kind::Int | Kind::OptionalInt => v.as_i64().is_some(),
            Kind::Text | Kind::OptionalText => v.is_string(),
            Kind::Json => true,
        };
        if !valid {
            let typ = if v.is_string() {
                "string".into()
            } else if v.is_number() {
                format!("number {}", raw.get())
            } else if v.is_array() {
                "array".into()
            } else if v.is_boolean() {
                "bool".into()
            } else {
                "object".into()
            };
            let wanted = if matches!(kind, Kind::Int | Kind::OptionalInt) {
                if matches!(*name, "registryVersion" | "catalogVersion") {
                    "int"
                } else {
                    "int64"
                }
            } else {
                "string"
            };
            return Err(format!(
                "json: cannot unmarshal {typ} into Go struct field .{name} of type {wanted}"
            ));
        }
        values.insert(*name, v);
    }
    if stream.next().is_some() {
        return Err("invalid syntax".into());
    }
    Ok(Fields {
        values,
        order,
        raw: raw_values,
    })
}

// encoding/json reports the offending byte and scanner context. Keep these
// protocol details at the decoder seam; serde remains the JSON parser.
fn syntax_error(e: &serde_json::Error, bytes: &[u8]) -> String {
    if e.is_eof() {
        return "unexpected EOF".into();
    }
    let offset = bytes
        .split(|b| *b == b'\n')
        .take(e.line().saturating_sub(1))
        .map(|s| s.len() + 1)
        .sum::<usize>()
        + e.column().saturating_sub(1);
    let ch = char::from(bytes.get(offset).copied().unwrap_or(b'?'));
    let message = e.to_string();
    let context = if message.starts_with("key must be a string") {
        "looking for beginning of object key string"
    } else if message.starts_with("expected `:`") {
        "after object key"
    } else if message.starts_with("expected `,` or `}`") {
        "after object key:value pair"
    } else if message.starts_with("expected `,` or `]`") {
        "after array element"
    } else if message.starts_with("invalid escape") {
        "in string escape code"
    } else if message.starts_with("control character") {
        "in string literal"
    } else {
        "looking for beginning of value"
    };
    format!("invalid character {ch:?} {context}")
}

fn go_struct(schema: &[(&str, Kind)]) -> String {
    let fields = schema
        .iter()
        .map(|(name, kind)| {
            let field = match *name {
                "domainId" => "DomainID".into(),
                "supportCellId" => "SupportCellID".into(),
                "capabilityId" => "CapabilityID".into(),
                "runId" => "RunID".into(),
                "artifactId" => "ArtifactID".into(),
                _ => format!("{}{}", name[..1].to_ascii_uppercase(), &name[1..]),
            };
            let typ = match kind {
                Kind::Int => {
                    if matches!(*name, "registryVersion" | "catalogVersion") {
                        "int"
                    } else {
                        "int64"
                    }
                }
                Kind::OptionalInt => "*int64",
                Kind::Text => "string",
                Kind::OptionalText => "*string",
                Kind::Json => "json.RawMessage",
            };
            let tag = serde_json::to_string(&format!("json:\"{name}\"")).expect("field tag");
            format!("{field} {typ} {tag}")
        })
        .collect::<Vec<_>>();
    format!("struct {{ {} }}", fields.join("; "))
}
