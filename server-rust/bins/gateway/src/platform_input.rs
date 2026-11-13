//! Go `json.Decoder` semantics for the Platform `system-features` bodies: the tolerant first
//! value (case-folded keys, `null` keeps the zero value, unknown keys ignored) and the strict
//! single-object form `decodeFeatureJSON` uses (`DisallowUnknownFields`, one object, capped).
use crate::guests_input::{fold, go_json_bytes};
use serde::de::{MapAccess, Visitor};
use std::collections::BTreeMap;
use std::fmt;

/// Go `http.MaxBytesReader` plus `Decode` over every byte the cap admits: the first JSON
/// value only, as `json_body`, but reporting whether the body went beyond the cap.
pub async fn capped(
    r: &mut hyper::Request<crate::Body>,
    cap: usize,
) -> Result<(Vec<u8>, bool), ()> {
    use http_body_util::BodyExt;
    let mut bytes = Vec::new();
    while bytes.len() <= cap {
        let Some(frame) = r.body_mut().frame().await else {
            break;
        };
        if let Ok(data) = frame.map_err(|_| ())?.into_data() {
            bytes.extend_from_slice(&data[..data.len().min(cap + 1 - bytes.len())]);
        }
    }
    let over = bytes.len() > cap;
    bytes.truncate(cap);
    Ok((bytes, over))
}

pub const BOUNDED: &str = "request must be bounded JSON with only documented fields";
pub const ONE_OBJECT: &str = "request must contain one JSON object";

/// `decodeFeatureJSON`: a first value that must end inside the cap, then nothing but
/// whitespace (a body beyond the cap fails the second read as well).
pub async fn strict<T: serde::de::DeserializeOwned>(
    r: &mut hyper::Request<crate::Body>,
    cap: usize,
) -> Result<T, &'static str> {
    let (bytes, over) = capped(r, cap).await.map_err(|_| BOUNDED)?;
    let fixed = go_json_bytes(&bytes);
    let mut stream = serde_json::Deserializer::from_slice(&fixed).into_iter::<T>();
    let value = match stream.next() {
        Some(Ok(value)) => value,
        _ => return Err(BOUNDED),
    };
    let rest = &fixed[stream.byte_offset()..];
    if over
        || rest
            .iter()
            .any(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
    {
        return Err(ONE_OBJECT);
    }
    Ok(value)
}

macro_rules! fields {
    ($(#[$m:meta])* $name:ident, strict: $strict:literal { $($field:ident : $ty:ty = $key:literal),+ $(,)? }) => {
        $(#[$m])*
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
                                _ if $strict => {
                                    return Err(serde::de::Error::custom("unknown field"));
                                }
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

fields!(
    /// `struct{Enabled *bool}`, strict.
    EnabledBody, strict: true { enabled: Option<bool> = "enabled" }
);
fields!(
    /// `struct{Mode string}`, strict.
    ModeBody, strict: true { mode: String = "mode" }
);
fields!(
    /// `sodModeSetRequest`.
    Sod, strict: false { enabled: bool = "enabled" }
);
fields!(
    /// `jitDefaults`.
    Jit, strict: false {
        minutes: i64 = "defaultmaxdurationminutes",
        required: bool = "defaultrequirejustification"
    }
);
fields!(
    /// `welcomeTestSendRequest`.
    WelcomeTest, strict: false {
        locale: String = "locale",
        subject: String = "subject",
        body_text: String = "body_text",
        body_html: String = "body_html"
    }
);
fields!(
    /// `notify.WelcomeLocale`.
    LocaleBody, strict: false {
        subject: String = "subject",
        body_text: String = "body_text",
        body_html: String = "body_html"
    }
);

/// `notify.WelcomeEmailConfig` as `json.Decoder` fills it: a `null` locales map is nil, a
/// `null` locale is the zero value, later duplicate keys replace earlier ones.
#[derive(Default)]
pub struct WelcomeBody {
    pub enabled: bool,
    pub default_locale: String,
    pub locales: Option<BTreeMap<String, LocaleBody>>,
}
impl<'de> serde::Deserialize<'de> for WelcomeBody {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = WelcomeBody;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<WelcomeBody, E> {
                Ok(WelcomeBody::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<WelcomeBody, M::Error> {
                let mut body = WelcomeBody::default();
                while let Some(key) = map.next_key::<String>()? {
                    match fold(&key).as_str() {
                        "enabled" => {
                            if let Some(v) = map.next_value::<Option<bool>>()? {
                                body.enabled = v;
                            }
                        }
                        "default_locale" => {
                            if let Some(v) = map.next_value::<Option<String>>()? {
                                body.default_locale = v;
                            }
                        }
                        "locales" => {
                            // `null` sets the map to nil; an object decodes into the existing
                            // map, adding or replacing keys.
                            match map.next_value::<Option<LocaleMap>>()? {
                                Some(entries) => body
                                    .locales
                                    .get_or_insert_with(BTreeMap::new)
                                    .extend(entries.0),
                                None => body.locales = None,
                            }
                        }
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
struct LocaleMap(BTreeMap<String, LocaleBody>);
impl<'de> serde::Deserialize<'de> for LocaleMap {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = LocaleMap;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<LocaleMap, M::Error> {
                let mut out = BTreeMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    // A fresh zero value per element: `null` stays zero, a repeat replaces.
                    let value = map.next_value::<Option<LocaleBody>>()?.unwrap_or_default();
                    out.insert(key, value);
                }
                Ok(LocaleMap(out))
            }
        }
        decoder.deserialize_map(Fields)
    }
}

/// `struct{Enabled *bool; Priority *int; ConfigJSON json.RawMessage}`: a `null` config is the
/// raw text `null`, which Go's `len(req.ConfigJSON) > 0` still counts as present.
#[derive(Default)]
pub struct AuthPatch {
    pub enabled: Option<bool>,
    pub priority: Option<i64>,
    pub config: Option<String>,
}
impl<'de> serde::Deserialize<'de> for AuthPatch {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = AuthPatch;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<AuthPatch, E> {
                Ok(AuthPatch::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<AuthPatch, M::Error> {
                let mut body = AuthPatch::default();
                while let Some(key) = map.next_key::<String>()? {
                    match fold(&key).as_str() {
                        "enabled" => {
                            if let Some(v) = map.next_value::<Option<bool>>()? {
                                body.enabled = Some(v);
                            }
                        }
                        "priority" => {
                            if let Some(v) = map.next_value::<Option<i64>>()? {
                                body.priority = Some(v);
                            }
                        }
                        "config" => {
                            let raw = map.next_value::<Box<serde_json::value::RawValue>>()?;
                            body.config = Some(raw.get().to_owned());
                        }
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
