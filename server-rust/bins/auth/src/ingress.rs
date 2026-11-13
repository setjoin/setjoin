//! Go's first json.Decoder.Decode into the login struct: unknown fields and
//! trailing JSON values accepted; field names folded; null scalar is ignored.
use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::Value;
#[derive(Default)]
pub struct Login {
    pub email: String,
    pub password: String,
    pub dpop: Value,
    pub stay: bool,
}
impl<'de> Deserialize<'de> for Login {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Login;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("login object or null")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Login, E> {
                Ok(Login::default())
            }
            fn visit_none<E: de::Error>(self) -> Result<Login, E> {
                Ok(Login::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> Result<Login, M::Error> {
                let mut out = Login::default();
                while let Some(k) = m.next_key::<String>()? {
                    if !matches!(
                        fold_name(&k).as_str(),
                        "email" | "password" | "stay_signed_in" | "dpop_jwk"
                    ) {
                        m.next_value::<de::IgnoredAny>()?;
                        continue;
                    }
                    let v = m.next_value::<Value>()?;
                    match fold_name(&k).as_str() {
                        "email" if !v.is_null() => {
                            out.email = v
                                .as_str()
                                .ok_or_else(|| de::Error::custom("email type"))?
                                .into()
                        }
                        "password" if !v.is_null() => {
                            out.password = v
                                .as_str()
                                .ok_or_else(|| de::Error::custom("password type"))?
                                .into()
                        }
                        "stay_signed_in" if !v.is_null() => {
                            out.stay = v.as_bool().ok_or_else(|| de::Error::custom("stay type"))?
                        }
                        "dpop_jwk" => {
                            if !v.is_null() && !v.is_object() {
                                return Err(de::Error::custom("jwk type"));
                            }
                            // A struct map field is reused for duplicate JSON
                            // keys in Go. An empty later object cannot erase a
                            // binding key already presented in this body.
                            if let (Some(previous), Some(next)) =
                                (out.dpop.as_object_mut(), v.as_object())
                            {
                                previous.extend(next.iter().map(|(k, v)| (k.clone(), v.clone())));
                            } else {
                                out.dpop = v;
                            }
                        }
                        _ => {}
                    }
                }
                Ok(out)
            }
        }
        d.deserialize_any(V)
    }
}

/// encoding/json replaces invalid UTF-8 and lone UTF-16 surrogates with U+FFFD.
/// This only prepares the decode view; the original bytes remain available for
/// an unported-shape handoff and future device body-digest verification (#420).
pub fn go_decode_bytes(raw: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(raw);
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut at = 0;
    let mut string = false;
    let code = |at: usize| -> Option<u16> {
        if b.get(at..at + 2) != Some(b"\\u") {
            return None;
        }
        let h = std::str::from_utf8(b.get(at + 2..at + 6)?).ok()?;
        u16::from_str_radix(h, 16).ok()
    };
    while at < b.len() {
        if b[at] == b'"' {
            string = !string;
            out.push(b[at]);
            at += 1;
            continue;
        }
        if string && b[at] == b'\\' {
            if let Some(c) = code(at) {
                if (0xD800..=0xDBFF).contains(&c) {
                    if code(at + 6).is_some_and(|c| (0xDC00..=0xDFFF).contains(&c)) {
                        out.extend_from_slice(&b[at..at + 12]);
                        at += 12;
                        continue;
                    }
                    out.extend_from_slice(b"\\ufffd");
                    at += 6;
                    continue;
                }
                if (0xDC00..=0xDFFF).contains(&c) {
                    out.extend_from_slice(b"\\ufffd");
                    at += 6;
                    continue;
                }
            }
            out.push(b[at]);
            at += 1;
            if at < b.len() {
                out.push(b[at]);
                at += 1;
            }
            continue;
        }
        out.push(b[at]);
        at += 1;
    }
    out
}

// Go encoding/json uses Unicode simple folding. These are the two non-ASCII
// fold classes that can match the ASCII names in this request struct.
fn fold_name(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            'ſ' => 's',
            'K' => 'k',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

/// Go's first Decode into a route-specific struct of string fields. Unknown
/// fields are skipped (even overflowing numeric values), duplicate null is a no-op.
pub fn fields(
    raw: &[u8],
    names: &[&str],
) -> Result<std::collections::BTreeMap<String, String>, serde_json::Error> {
    struct Fields<'a>(&'a [&'a str]);
    impl<'de> Visitor<'de> for Fields<'_> {
        type Value = std::collections::BTreeMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("object or null")
        }
        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(Default::default())
        }
        fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> Result<Self::Value, M::Error> {
            let mut out = std::collections::BTreeMap::new();
            while let Some(key) = m.next_key::<String>()? {
                let key = fold_name(&key);
                if self.0.contains(&key.as_str()) {
                    if let Some(v) = m.next_value::<Option<String>>()? {
                        out.insert(key, v);
                    }
                } else {
                    m.next_value::<de::IgnoredAny>()?;
                }
            }
            Ok(out)
        }
    }
    let decoded = go_decode_bytes(raw);
    let mut d = serde_json::Deserializer::from_slice(&decoded);
    d.deserialize_any(Fields(names))
}

/// Go's first Decoder.Decode into a struct; unknown fields are skipped without
/// converting their numbers, null scalars preserve an earlier duplicate value.
#[derive(Clone, Copy)]
pub enum Field {
    Text,
    Integer,
    Object,
}
pub fn typed_fields(
    raw: &[u8],
    known: &[(&str, Field)],
) -> Result<serde_json::Map<String, Value>, serde_json::Error> {
    typed_fields_impl(raw,known,false)
}
pub fn closed_fields(raw:&[u8],known:&[(&str,Field)])->Result<serde_json::Map<String,Value>,serde_json::Error>{typed_fields_impl(raw,known,true)}
fn typed_fields_impl(raw:&[u8],known:&[(&str,Field)],closed:bool)->Result<serde_json::Map<String,Value>,serde_json::Error>{
    use serde::de::DeserializeSeed;
    struct Seed<'a>(&'a [(&'a str, Field)],bool);
    impl<'de> DeserializeSeed<'de> for Seed<'_> {
        type Value = serde_json::Map<String, Value>;
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            struct V<'a>(&'a [(&'a str, Field)],bool);
            impl<'de> Visitor<'de> for V<'_> {
                type Value = serde_json::Map<String, Value>;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("object or null")
                }
                fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                    Ok(Default::default())
                }
                fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> Result<Self::Value, M::Error> {
                    let mut out = serde_json::Map::new();
                    while let Some(k) = m.next_key::<String>()? {
                        let folded = fold_name(&k);
                        let Some((name, kind)) = self.0.iter().find(|(n, _)| *n == folded) else {
                            if self.1{return Err(de::Error::custom("unknown field"));}
                            m.next_value::<de::IgnoredAny>()?;
                            continue;
                        };
                        let v = m.next_value::<Value>()?;
                        if v.is_null() {
                            if matches!(kind,Field::Object){out.insert((*name).to_owned(),Value::Null);}
                            continue;
                        }
                        let ok = match kind {
                            Field::Text => v.is_string(),
                            Field::Integer => v.as_i64().is_some(),
                            Field::Object => v.is_object(),
                        };
                        if !ok {
                            return Err(de::Error::custom("field type"));
                        }
                        if matches!(kind,Field::Object){
                            if let (Some(previous),Some(next))=(out.get_mut(*name).and_then(Value::as_object_mut),v.as_object()){
                                previous.extend(next.iter().map(|(k,v)|(k.clone(),v.clone())));continue;
                            }
                        }
                        out.insert((*name).to_owned(), v);
                    }
                    Ok(out)
                }
            }
            d.deserialize_any(V(self.0,self.1))
        }
    }
    let raw = go_decode_bytes(raw);
    Seed(known,closed).deserialize(&mut serde_json::Deserializer::from_slice(&raw))
}

/// httputil.DecodeJSON's one-value boundary, unlike plain Decoder.Decode.
pub fn exact(raw: &[u8]) -> bool {
    use serde::Deserialize;
    let mut de = serde_json::Deserializer::from_slice(raw);
    serde::de::IgnoredAny::deserialize(&mut de).is_ok() && de.end().is_ok()
}
