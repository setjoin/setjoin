//! Go `encoding/json` request decoding for the F06 spam slice: case-folded keys, `null`
//! rules per target type (a pointer or slice becomes nil, anything else is left alone),
//! the first value only for the lenient handlers, and the strict one-object decoder of
//! the sender-control action (64 KiB, unknown fields refused, nothing after the value).
use crate::guests_input::fold;
use serde::de::{MapAccess, Visitor};

/// One decoded field: `prev` is what the struct held before this key was read.
pub trait GoField: Sized {
    fn read<'de, M: MapAccess<'de>>(map: &mut M, prev: Self) -> Result<Self, M::Error>;
}
impl GoField for String {
    fn read<'de, M: MapAccess<'de>>(map: &mut M, prev: Self) -> Result<Self, M::Error> {
        Ok(map.next_value::<Option<String>>()?.unwrap_or(prev))
    }
}
/// A plain `bool`: JSON null leaves the previous value.
impl GoField for bool {
    fn read<'de, M: MapAccess<'de>>(map: &mut M, prev: Self) -> Result<Self, M::Error> {
        Ok(map.next_value::<Option<bool>>()?.unwrap_or(prev))
    }
}
/// An `int64` that Go decodes and the handler ignores: null leaves it, a non-integer fails.
impl GoField for Option<i64> {
    fn read<'de, M: MapAccess<'de>>(map: &mut M, prev: Self) -> Result<Self, M::Error> {
        Ok(map.next_value::<Option<i64>>()?.or(prev))
    }
}
/// A plain `int64`: JSON null leaves the previous value, a non-integer fails.
impl GoField for i64 {
    fn read<'de, M: MapAccess<'de>>(map: &mut M, prev: Self) -> Result<Self, M::Error> {
        Ok(map.next_value::<Option<i64>>()?.unwrap_or(prev))
    }
}
/// A `*string`: JSON null is nil.
impl GoField for Option<String> {
    fn read<'de, M: MapAccess<'de>>(map: &mut M, _: Self) -> Result<Self, M::Error> {
        map.next_value::<Option<String>>()
    }
}
impl GoField for Option<bool> {
    fn read<'de, M: MapAccess<'de>>(map: &mut M, _: Self) -> Result<Self, M::Error> {
        map.next_value::<Option<bool>>()
    }
}
/// A `[]string`: JSON null is nil, and a null element is the empty string.
impl GoField for Option<Vec<String>> {
    fn read<'de, M: MapAccess<'de>>(map: &mut M, _: Self) -> Result<Self, M::Error> {
        Ok(map
            .next_value::<Option<Vec<Option<String>>>>()?
            .map(|items| items.into_iter().map(Option::unwrap_or_default).collect()))
    }
}

macro_rules! go_body {
    ($name:ident, $strict:expr, { $($field:ident : $ty:ty = $key:literal),+ $(,)? }) => {
        #[derive(Default)]
        pub struct $name { $(pub $field: $ty),+ }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
                struct Fields;
                impl<'de> Visitor<'de> for Fields {
                    type Value = $name;
                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
                                    body.$field = GoField::read(&mut map, std::mem::take(&mut body.$field))?;
                                })+
                                _ => {
                                    if $strict {
                                        return Err(serde::de::Error::custom("unknown field"));
                                    }
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

go_body!(SenderList, false, {
    safe: Option<Vec<String>> = "safe",
    blocked: Option<Vec<String>> = "blocked",
    expected_generation: String = "expectedgeneration",
    operation_id: String = "operationid",
});
go_body!(Sender, false, { sender: String = "sender" });
go_body!(External, false, { enabled: Option<bool> = "enabled" });
go_body!(Report, false, {
    email_id: String = "emailid",
    kind: String = "type",
    note: String = "note",
});
go_body!(TlsPolicy, false, {
    enforce: Option<Vec<String>> = "enforce_domains",
    skip: Option<Vec<String>> = "skip_domains",
    mode: String = "global_mode",
});
go_body!(DlpPattern, false, {
    id: Option<i64> = "id",
    name: String = "name",
    regex: String = "regex",
    severity: String = "severity",
    enabled: bool = "enabled",
});
go_body!(AntiPhishBody, false, {
    display_name: bool = "display_name_enabled",
    lookalike: bool = "lookalike_enabled",
    contact_graph: bool = "contact_graph_enabled",
    strict_mode: bool = "strict_mode",
    domains: Option<Vec<String>> = "exclusion_domains",
    users: Option<Vec<String>> = "exclusion_users",
});
go_body!(LinkClaims, false, {
    url: String = "u",
    message_id: String = "m",
    mailbox: i64 = "b",
    expires: i64 = "e",
});
go_body!(IpRule, false, {
    cidr: String = "cidr",
    action: String = "action",
    description: String = "description",
    expires: Option<String> = "expiresat",
});
go_body!(ControlAction, true, {
    mailbox_id: String = "mailboxid",
    message_id: String = "messageid",
    received_at: String = "receivedat",
    operation_id: String = "operationid",
    action: String = "action",
    expected_generation: String = "expectedgeneration",
    target_operation_id: String = "targetoperationid",
});

/// `json.NewDecoder(r.Body).Decode(&v)` with no size cap: the first value, whatever
/// follows is never examined.
pub async fn lenient<T: serde::de::DeserializeOwned>(
    r: &mut hyper::Request<crate::Body>,
) -> Result<T, ()> {
    crate::admin_identity_input::first(r, usize::MAX).await
}

/// The sender-control action decoder: at most 64 KiB, one value, nothing after it.
/// `Err(true)` is "invalid request", `Err(false)` is "must contain one JSON object".
pub async fn strict_one<T: serde::de::DeserializeOwned>(
    r: &mut hyper::Request<crate::Body>,
) -> Result<T, bool> {
    one_capped(r, 64 << 10).await
}

/// `httputil.DecodeJSON`-style decoding with a body cap: one value, nothing after it.
pub async fn one_capped<T: serde::de::DeserializeOwned>(
    r: &mut hyper::Request<crate::Body>,
    cap: usize,
) -> Result<T, bool> {
    use http_body_util::BodyExt;
    let cap_bytes = cap;
    let mut bytes = Vec::new();
    let mut over = false;
    while let Some(frame) = r.body_mut().frame().await {
        let frame = frame.map_err(|_| true)?;
        if let Ok(data) = frame.into_data() {
            let room = cap_bytes - bytes.len();
            if data.len() > room {
                bytes.extend_from_slice(&data[..room]);
                over = true;
                break;
            }
            bytes.extend_from_slice(&data);
        }
    }
    let fixed = crate::guests_input::go_json_bytes(&bytes);
    let mut stream = serde_json::Deserializer::from_slice(&fixed).into_iter::<T>();
    let value = match stream.next() {
        Some(Ok(value)) => value,
        _ => return Err(true),
    };
    // Go decodes the first value, then a second Decode must see EOF: running into the
    // cap while looking for it is an error of that second read.
    let rest = &fixed[stream.byte_offset()..];
    if !over
        && rest
            .iter()
            .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
    {
        Ok(value)
    } else {
        Err(false)
    }
}

/// `normalizeSender`: trim, lower-case, then `validate.ValidateEmail` with SMTPUTF8 on.
/// Returns "" when Go does (the value is not a plausible address). The stored value is the
/// normalised input itself, not the parsed address.
pub fn normalize_sender(raw: &str) -> String {
    let value = raw.trim().to_lowercase();
    if valid_email(&value) {
        value
    } else {
        String::new()
    }
}

fn valid_email(email: &str) -> bool {
    if email.is_empty() || email.len() > 254 {
        return false;
    }
    if email.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return false;
    }
    if let Some(at) = email.rfind('@').filter(|at| *at >= 1) {
        let local = &email[..at];
        if local.contains("..") || local.starts_with('.') || local.ends_with('.') {
            return false;
        }
    }
    let parse = |text: &str| -> Option<String> {
        match mailparse::addrparse(text).ok()?.as_slice() {
            [mailparse::MailAddr::Single(a)] => Some(a.addr.clone()),
            _ => None,
        }
    };
    let address = match parse(email) {
        Some(a) => a,
        None if !email.starts_with('<') => match parse(&format!("<{email}>")) {
            Some(a) => a,
            None => return false,
        },
        None => return false,
    };
    let Some(at) = address.rfind('@') else {
        return false;
    };
    if at < 1 || at == address.len() - 1 {
        return false;
    }
    let domain = &address[at + 1..];
    domain.len() <= 255
        && !(domain.starts_with('[') && domain.ends_with(']'))
        && domain.contains('.')
        && !domain.contains('_')
}

/// `encoding/json` of a Go string (HTML escapes, U+2028/9).
pub fn go_string(text: &str) -> String {
    crate::problem::go_string(text)
}

/// `json.Marshal` of `[]string`: `null` for nil.
pub fn go_strings(items: &Option<Vec<String>>) -> String {
    match items {
        None => "null".into(),
        Some(list) => format!(
            "[{}]",
            list.iter()
                .map(|s| go_string(s))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}
go_body!(SpamTrain, false, {
    user_id: i64 = "user_id",
    message_id: i64 = "message_id",
    is_spam: bool = "is_spam",
});
