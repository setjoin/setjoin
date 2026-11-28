//! Go `json.NewDecoder(r.Body).Decode(&struct)` semantics for the F02 admin
//! bodies: first value only, case-folded keys, null keeps zero values.
use serde::de::{MapAccess, Visitor};
use std::fmt;

pub use crate::guests_input::fold;

/// First JSON value of the body; trailing bytes are never examined, as Go's.
pub async fn first<T: serde::de::DeserializeOwned>(
    r: &mut hyper::Request<crate::Body>,
    cap: usize,
) -> Result<T, ()> {
    use http_body_util::BodyExt;
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        let frame = frame.map_err(|_| ())?;
        if let Ok(data) = frame.into_data() {
            if data.len() > cap.saturating_sub(bytes.len()) {
                return Err(());
            }
            bytes.extend_from_slice(&data);
        }
    }
    let fixed = crate::guests_input::go_json_bytes(&bytes);
    match serde_json::Deserializer::from_slice(&fixed)
        .into_iter::<T>()
        .next()
    {
        Some(Ok(value)) => Ok(value),
        _ => Err(()),
    }
}

macro_rules! body {
    ($name:ident { $($field:ident : $ty:ty = $key:literal),+ $(,)? }) => {
        #[derive(Default)]
        pub struct $name { $(pub $field: $ty),+ }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
                struct Fields;
                impl<'de> Visitor<'de> for Fields {
                    type Value = $name;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str("a JSON object")
                    }
                    fn visit_unit<E: serde::de::Error>(self) -> Result<$name, E> {
                        Ok($name::default())
                    }
                    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<$name, M::Error> {
                        let mut body = $name::default();
                        while let Some(key) = map.next_key::<String>()? {
                            match fold(&key).as_str() {
                                $($key => {
                                    if let Some(value) = map.next_value::<Option<$ty>>()? {
                                        body.$field = value;
                                    }
                                })+
                                _ => {
                                    let _: serde::de::IgnoredAny = map.next_value()?;
                                }
                            }
                        }
                        Ok(body)
                    }
                }
                decoder.deserialize_any(Fields)
            }
        }
    };
}
body!(Resolution {
    resolution: String = "resolution"
});
body!(FieldPolicy {
    user_id: i64 = "userid",
    field: String = "field",
    policy: String = "policy"
});
body!(Principal {
    user_id: i64 = "userid",
    krb5_principal: String = "krb5principal"
});

/// `strconv.Atoi`/`ParseInt` with the error ignored: syntax errors give 0 and
/// range errors saturate.
pub fn atoi(text: &str) -> i64 {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return 0;
    }
    match digits.parse::<i64>() {
        Ok(n) if negative => -n,
        Ok(n) => n,
        Err(_) if negative => i64::MIN,
        Err(_) => i64::MAX,
    }
}

/// Go `r.URL.Query().Get(name)`: pairs with `;` or bad escapes are dropped.
pub fn query(uri: &hyper::Uri, name: &str) -> Option<String> {
    fn decode(value: &str) -> Option<String> {
        let input = value.as_bytes();
        let mut out = Vec::new();
        let mut index = 0;
        while index < input.len() {
            match input[index] {
                b'+' => out.push(b' '),
                b'%' => {
                    let a = (*input.get(index + 1)? as char).to_digit(16)?;
                    let b = (*input.get(index + 2)? as char).to_digit(16)?;
                    out.push((a * 16 + b) as u8);
                    index += 2;
                }
                b => out.push(b),
            }
            index += 1;
        }
        Some(crate::guests_input::go_utf8(&out))
    }
    for pair in uri.query()?.split('&') {
        if pair.is_empty() || pair.contains(';') {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let (Some(key), Some(value)) = (decode(key), decode(value)) else {
            continue;
        };
        if key == name {
            return Some(value);
        }
    }
    None
}
