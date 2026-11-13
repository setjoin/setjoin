//! Adapter for encoding/json field matching; serde remains the JSON parser.
use anyhow::{ensure, Result};
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{Map, Value};
use std::{collections::HashSet, fmt};

pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= crate::MAX_DOCUMENT_BYTES,
        "empty or oversized document"
    );
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = GoValue::deserialize(&mut decoder)?;
    decoder.end()?;
    Ok(serde_json::from_value(value.0)?)
}
struct GoValue(Value);
impl<'de> Deserialize<'de> for GoValue {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        decoder.deserialize_any(GoVisitor)
    }
}
struct GoVisitor;
impl<'de> Visitor<'de> for GoVisitor {
    type Value = GoValue;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value without duplicate keys")
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<GoValue, E> {
        Ok(GoValue(Value::Null))
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<GoValue, E> {
        Ok(GoValue(v.into()))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<GoValue, E> {
        Ok(GoValue(v.into()))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<GoValue, E> {
        Ok(GoValue(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<GoValue, E> {
        Ok(GoValue(v.into()))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<GoValue, E> {
        Ok(GoValue(v.into()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<GoValue, E> {
        Ok(GoValue(v.into()))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<GoValue, A::Error> {
        let mut values = Vec::new();
        while let Some(v) = seq.next_element::<GoValue>()? {
            values.push(v.0);
        }
        Ok(GoValue(Value::Array(values)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<GoValue, A::Error> {
        let mut seen = HashSet::new();
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate JSON key {key:?}")));
            }
            // Go's foldName maps ASCII and the two non-ASCII SimpleFold
            // equivalents of ASCII letters. All schema tags are ASCII.
            let folded: String = key
                .chars()
                .map(|c| match c {
                    'ſ' => 's',
                    'K' => 'k',
                    _ => c.to_ascii_lowercase(),
                })
                .collect();
            let value = map.next_value::<GoValue>()?.0;
            merge_field(&mut values, folded, value);
        }
        Ok(GoValue(Value::Object(values)))
    }
}

// The Go decoder writes into the existing struct when differently cased keys
// address the same field. Arrays/pointers reset on null; value fields ignore it.
fn merge_field(values: &mut Map<String, Value>, key: String, value: Value) {
    let nullable = matches!(
        key.as_str(),
        "feature_registry"
            | "platforms"
            | "architectures"
            | "artifacts"
            | "migrations"
            | "signatures"
            | "rotation_key_ids"
            | "preflight"
            | "readiness"
            | "data_contract"
            | "post_commit"
            | "compatible_modes"
            | "compatible_rollback_digests"
            | "known_blockers"
            | "keys"
    );
    if value.is_null() && !nullable && values.contains_key(&key) {
        return;
    }
    if let (Some(Value::Object(existing)), Value::Object(incoming)) = (values.get_mut(&key), &value)
    {
        for (name, field) in incoming {
            merge_field(existing, name.clone(), field.clone());
        }
    } else {
        values.insert(key, value);
    }
}
