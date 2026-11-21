//! RFC 8887's typed envelope and RFC 8620 batch projection.
use serde::de::{MapAccess, Visitor};
use serde_json::{value::RawValue, Value};
use std::collections::BTreeMap;

#[derive(Default)]
pub struct Envelope {
    pub kind: String,
    pub id: String,
    pub using: Vec<String>,
    pub calls: Vec<Call>,
}
#[derive(Clone)]
pub struct Call {
    pub name: String,
    pub args: Box<RawValue>,
    pub id: String,
}

impl<'de> serde::Deserialize<'de> for Call {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let (name, args, id) = <(Option<String>, Box<RawValue>, Option<String>)>::deserialize(d)?;
        Ok(Self {
            name: name.unwrap_or_default(),
            args,
            id: id.unwrap_or_default(),
        })
    }
}

impl<'de> serde::Deserialize<'de> for Envelope {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Envelope;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("WebSocket envelope")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Envelope, E> {
                Ok(Envelope::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> Result<Envelope, M::Error> {
                let mut env = Envelope::default();
                while let Some(key) = m.next_key::<String>()? {
                    match crate::guests_input::fold(&key).as_str() {
                        "@type" => {
                            if let Some(v) = m.next_value::<Option<String>>()? {
                                env.kind = v
                            }
                        }
                        "id" => {
                            if let Some(v) = m.next_value::<Option<String>>()? {
                                env.id = v
                            }
                        }
                        "using" => {
                            env.using = m
                                .next_value::<Option<Vec<Option<String>>>>()?
                                .unwrap_or_default()
                                .into_iter()
                                .map(Option::unwrap_or_default)
                                .collect()
                        }
                        "methodcalls" => {
                            env.calls = m.next_value::<Option<Vec<Call>>>()?.unwrap_or_default()
                        }
                        "datatypes" => {
                            m.next_value::<Option<Vec<Option<String>>>>()?;
                        }
                        "methodresponses" => {
                            m.next_value::<Option<Vec<Call>>>()?;
                        }
                        "sessionstate" | "requestid" | "type" | "detail" | "pushstate" => {
                            m.next_value::<Option<String>>()?;
                        }
                        "status" => {
                            m.next_value::<Option<i64>>()?;
                        }
                        "createdids" => {
                            m.next_value::<Option<BTreeMap<String, Option<String>>>>()?;
                        }
                        "changed" => {
                            m.next_value::<Option<BTreeMap<String,Option<BTreeMap<String,Option<String>>>>>>()?;
                        }
                        _ => {
                            m.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(env)
            }
        }
        d.deserialize_any(Fields)
    }
}

pub fn decode(data: &[u8]) -> Option<Envelope> {
    serde_json::from_slice(&crate::guests_input::go_json_bytes(data)).ok()
}

pub const CORE: &str = "urn:ietf:params:jmap:core";
pub const MAIL: &str = "urn:ietf:params:jmap:mail";

/// Use Go's WebSocket seam: forwarding this as HTTP POST would introduce
/// different CSRF/device admission and could change frozen-Go behavior.
pub async fn forward_unported(
    raw: &[u8],
    token: &str,
    env: &Envelope,
    context: &crate::RequestContext,
) -> Result<String, ()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};
    let (base, timeout) = context.upstream.unported_push_target().ok_or(())?;
    let authority = base.authority().ok_or(())?;
    let host = authority.host();
    let port = authority.port_u16().unwrap_or(80);
    tokio::time::timeout(timeout, async {
        let stream = tokio::net::TcpStream::connect((host, port))
            .await
            .map_err(|_| ())?;
        let mut request = format!("ws://{authority}/jmap/ws")
            .into_client_request()
            .map_err(|_| ())?;
        request.headers_mut().insert(
            "cookie",
            format!("access_token={token}").parse().map_err(|_| ())?,
        );
        request.headers_mut().insert(
            "origin",
            format!("http://{authority}").parse().map_err(|_| ())?,
        );
        crate::forwarded::apply(request.headers_mut(), &context.identity);
        let (mut socket, _) = tokio_tungstenite::client_async(request, stream)
            .await
            .map_err(|_| ())?;
        socket
            .send(Message::Binary(raw.to_vec().into()))
            .await
            .map_err(|_| ())?;
        while let Some(frame) = socket.next().await {
            match frame.map_err(|_| ())? {
                Message::Ping(_) => socket.flush().await.map_err(|_| ())?,
                Message::Text(text) => {
                    let value: Value = serde_json::from_str(&text).map_err(|_| ())?;
                    let kind = value["@type"].as_str().unwrap_or("");
                    if matches!(kind, "Response" | "RequestError")
                        && value["requestId"].as_str().unwrap_or("") == env.id
                    {
                        let _ = socket.close(None).await;
                        return Ok(text.to_string());
                    }
                }
                Message::Close(_) => return Err(()),
                _ => {}
            }
        }
        Err(())
    })
    .await
    .map_err(|_| ())?
}

pub async fn execute<K: super::token::KeySource>(
    commands: &super::JmapCommands<K>,
    identity: &setjoin_authz::push::PushIdentity,
    env: &Envelope,
) -> Result<String, super::DeferToGo> {
    if env.using.is_empty() {
        return Ok(request_error(
            &env.id,
            "notRequest",
            "'using' array must not be empty",
        ));
    }
    if env.calls.len() > 32 {
        return Ok(request_error(
            &env.id,
            "requestTooLarge",
            &format!(
                "maxCallsInRequest of 32 exceeded ({} calls)",
                env.calls.len()
            ),
        ));
    }
    let authorized = identity
        .command_authorization(&commands.exec)
        .await
        .ok_or(super::DeferToGo("push authorization unavailable"))?;
    let id_ctx = authorized.context();
    let session = authorized.session_state().encode();
    let (_, outcome) = commands
        .execute_batch_verified(
            id_ctx.user_id(),
            id_ctx.mailbox_id(),
            id_ctx.email(),
            &env.using,
            &env.calls,
            false,
        )
        .await?;
    Ok(match outcome {
        super::BatchOutcome::Problem { kind, detail, .. } => request_error(&env.id, kind, &detail),
        super::BatchOutcome::Response(responses) => response(&session, &responses, &env.id),
    })
}

pub fn response(session: &str, calls: &[Call], id: &str) -> String {
    let mut out = format!(
        "{{\"@type\":\"Response\",\"sessionState\":{}",
        crate::problem::go_string(session)
    );
    if !calls.is_empty() {
        out.push_str(",\"methodResponses\":[");
        for (index, call) in calls.iter().enumerate() {
            if index > 0 {
                out.push(',')
            }
            out.push_str(&format!(
                "[{},{},{}]",
                crate::problem::go_string(&call.name),
                call.args.get(),
                crate::problem::go_string(&call.id)
            ));
        }
        out.push(']');
    }
    let created_ids = super::reply::collect_created_ids(calls);
    if !created_ids.is_empty() {
        out.push_str(",\"createdIds\":");
        out.push_str(
            &super::reply::go_compact(&serde_json::to_string(&created_ids).expect("created IDs"))
                .expect("created IDs JSON"),
        );
    }
    if !id.is_empty() {
        out.push_str(&format!(",\"requestId\":{}", crate::problem::go_string(id)))
    }
    out.push('}');
    out
}

pub fn request_error(id: &str, kind: &str, detail: &str) -> String {
    let mut out = "{\"@type\":\"RequestError\"".to_owned();
    if !id.is_empty() {
        out.push_str(&format!(",\"requestId\":{}", crate::problem::go_string(id)))
    }
    out.push_str(&format!(
        ",\"type\":\"urn:ietf:params:jmap:error:{kind}\",\"status\":400"
    ));
    if !detail.is_empty() {
        out.push_str(&format!(
            ",\"detail\":{}",
            crate::problem::go_string(detail)
        ))
    }
    out.push('}');
    out
}

pub fn method_error(kind: &str, detail: &str) -> String {
    let mut out = format!("{{\"type\":\"urn:ietf:params:jmap:error:{kind}\",\"status\":400");
    if !detail.is_empty() {
        out.push_str(&format!(
            ",\"detail\":{}",
            crate::problem::go_string(detail)
        ))
    }
    out.push('}');
    out
}

#[derive(Default)]
struct ResultReference {
    result_of: String,
    name: String,
    path: String,
}
impl<'de> serde::Deserialize<'de> for ResultReference {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = ResultReference;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("ResultReference")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(ResultReference::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> Result<Self::Value, M::Error> {
                let mut reference = ResultReference::default();
                while let Some(key) = m.next_key::<String>()? {
                    let target = match crate::guests_input::fold(&key).as_str() {
                        "resultof" => &mut reference.result_of,
                        "name" => &mut reference.name,
                        "path" => &mut reference.path,
                        _ => {
                            m.next_value::<serde::de::IgnoredAny>()?;
                            continue;
                        }
                    };
                    if let Some(value) = m.next_value::<Option<String>>()? {
                        *target = value;
                    }
                }
                Ok(reference)
            }
        }
        d.deserialize_any(Fields)
    }
}
pub(super) fn references(raw: &str, prior: &[Call]) -> Result<String, (&'static str, String)> {
    // Go rewrites map[string]RawMessage: only referenced values are decoded.
    // Preserve every ordinary nested object's order and numeric spelling.
    let Ok(mut args) = serde_json::from_str::<BTreeMap<String, Box<RawValue>>>(raw) else {
        return Ok(raw.into());
    };
    let keys: Vec<_> = args
        .keys()
        .filter(|k| k.starts_with('#'))
        .cloned()
        .collect();
    if keys.is_empty() {
        return Ok(raw.into());
    }
    for key in keys {
        let name = &key[1..];
        if args.contains_key(name) {
            return Err((
                "invalidArguments",
                format!(
                    "argument {} given in both plain and referenced (#{name}) form",
                    crate::problem::go_string(name)
                ),
            ));
        }
        let value = args.remove(&key).expect("reference key");
        let error = |detail: String| ("invalidResultReference", format!("{key}: {detail}"));
        let reference = serde_json::from_str::<ResultReference>(value.get())
            .ok()
            .filter(|r| !r.result_of.is_empty() && !r.name.is_empty())
            .ok_or_else(|| {
                (
                    "invalidResultReference",
                    format!("malformed ResultReference for {key}"),
                )
            })?;
        let Some(call) = prior.iter().find(|c| c.id == reference.result_of) else {
            return Err(error(format!(
                "no prior response with resultOf {}",
                crate::problem::go_string(&reference.result_of)
            )));
        };
        if call.name != reference.name {
            return Err(error(format!(
                "response name {} does not match referenced name {}",
                crate::problem::go_string(&call.name),
                crate::problem::go_string(&reference.name)
            )));
        }
        let doc: Value = serde_json::from_str(call.args.get()).expect("prior JSON");
        check_float64(&doc).map_err(|number|error(format!("prior response args are not valid JSON: json: cannot unmarshal number {number} into Go value of type float64")))?;
        let value = pointer(&doc, &reference.path).map_err(error)?;
        args.insert(
            name.to_owned(),
            RawValue::from_string(resolved_json(&value)).expect("resolved JSON"),
        );
    }
    let rewritten = format!(
        "{{{}}}",
        args.iter()
            .map(|(key, value)| format!(
                "{}:{}",
                crate::problem::go_string(key),
                super::reply::go_compact(value.get()).expect("raw JSON")
            ))
            .collect::<Vec<_>>()
            .join(",")
    );
    Ok(rewritten)
}
fn check_float64(value: &Value) -> Result<(), String> {
    match value {
        Value::Number(n) if n.as_f64().is_none_or(|n| !n.is_finite()) => return Err(n.to_string()),
        Value::Array(items) => {
            for item in items {
                check_float64(item)?
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                check_float64(item)?
            }
        }
        _ => {}
    }
    Ok(())
}
/// encoding/json decodes reference documents into any (all numbers float64).
/// Re-encoding uses its fixed/exponent thresholds and explicit positive sign.
fn resolved_json(value: &Value) -> String {
    match value {
        Value::Number(n) => {
            let n = n.as_f64().expect("checked float64");
            if n != 0.0 && !(1e-6..1e21).contains(&n.abs()) {
                let text = format!("{n:e}");
                let (mantissa, exponent) = text.split_once('e').expect("exponent");
                let exponent: i32 = exponent.parse().expect("exponent number");
                format!("{mantissa}e{exponent:+}")
            } else {
                format!("{n}")
            }
        }
        Value::String(text) => crate::problem::go_string(text),
        Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(resolved_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(map) => {
            let sorted: BTreeMap<_, _> = map.iter().collect();
            format!(
                "{{{}}}",
                sorted
                    .iter()
                    .map(|(key, value)| format!(
                        "{}:{}",
                        crate::problem::go_string(key),
                        resolved_json(value)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        _ => value.to_string(),
    }
}

fn pointer(doc: &Value, path: &str) -> Result<Value, String> {
    if path.is_empty() {
        return Ok(doc.clone());
    }
    if !path.starts_with('/') {
        return Err(format!(
            "invalid JSON Pointer {}: must be empty or begin with '/'",
            crate::problem::go_string(path)
        ));
    }
    tokens(doc, &path[1..].split('/').collect::<Vec<_>>())
}
fn tokens(doc: &Value, path: &[&str]) -> Result<Value, String> {
    let Some((head, rest)) = path.split_first() else {
        return Ok(doc.clone());
    };
    if *head == "*" {
        let Some(array) = doc.as_array() else {
            return Err("'*' applied to non-array value".into());
        };
        let mut out = Vec::new();
        for item in array {
            match tokens(item, rest)? {
                Value::Array(items) => out.extend(items),
                value => out.push(value),
            }
        }
        return Ok(Value::Array(out));
    }
    let key = head.replace("~1", "/").replace("~0", "~");
    let quoted = crate::problem::go_string(&key);
    let next = match doc {
        Value::Object(object) => object
            .get(&key)
            .ok_or_else(|| format!("pointer token {quoted} not found in object"))?,
        Value::Array(array) => key
            .parse::<i64>()
            .ok()
            .filter(|i| *i >= 0)
            .and_then(|i| array.get(i as usize))
            .ok_or_else(|| {
                format!(
                    "pointer token {quoted} is not a valid index into array of length {}",
                    array.len()
                )
            })?,
        _ => {
            return Err(format!(
                "pointer token {quoted} applied to non-container value"
            ))
        }
    };
    tokens(next, rest)
}

pub(super) fn server_fail() -> String {
    r#"{"type":"urn:ietf:params:jmap:error:serverFail","status":500,"detail":"database error"}"#
        .into()
}

// Frozen Go registerMethods metadata; unknown names retain core.
pub(super) fn metadata(name: &str) -> Option<&'static str> {
    Some(match name {
        "Core/echo" => "urn:ietf:params:jmap:core",
        "Continuity/get"
        | "Continuity/present"
        | "Mailbox/get"
        | "Mailbox/changes"
        | "Mailbox/query"
        | "Mailbox/queryChanges"
        | "Mailbox/set"
        | "Email/get"
        | "Email/recoveryReceipt"
        | "Email/query"
        | "Email/changes"
        | "Email/set"
        | "Email/deletedQuery"
        | "Email/recover"
        | "Email/purge"
        | "Email/bundles"
        | "Email/nudges"
        | "Email/nudgeDismiss"
        | "Thread/get"
        | "Thread/changes"
        | "SearchSnippet/get"
        | "MailWork/get"
        | "MailWork/changes"
        | "MailWork/set"
        | "MailWork/action"
        | "MailWorkCollaborators/get"
        | "MailWorkPolicy/get"
        | "MailWorkPolicy/set"
        | "MailWorkNotificationPreferences/get"
        | "MailWorkNotificationPreferences/set"
        | "MailWorkMetrics/get"
        | "MailComment/get"
        | "MailComment/set"
        | "MailDraft/get"
        | "MailDraft/open"
        | "MailDraft/lease"
        | "MailDraft/save"
        | "MailDraft/replace" => "urn:ietf:params:jmap:mail",
        "EmailSubmission/set"
        | "EmailSubmission/cancel"
        | "EmailSubmission/get"
        | "EmailSubmission/query"
        | "Identity/get"
        | "Identity/changes"
        | "Identity/set" => "urn:ietf:params:jmap:submission",
        "Calendar/get"
        | "Calendar/changes"
        | "Calendar/set"
        | "Calendar/getShared"
        | "Calendar/shareGet"
        | "Calendar/shareSet"
        | "Calendar/delegateList"
        | "CalendarEvent/get"
        | "CalendarEvent/query"
        | "CalendarEvent/changes"
        | "CalendarEvent/set"
        | "CalendarEvent/import"
        | "CalendarEvent/freeBusy"
        | "CalendarEvent/queryFreeSlots"
        | "CalendarEvent/rsvp"
        | "CalendarEvent/counter"
        | "CalendarEvent/getShared"
        | "CalendarEvent/setOccurrence"
        | "CalendarEvent/resourceList"
        | "CalendarEvent/sendUpdate" => "urn:ietf:params:jmap:calendars",
        "AddressBook/get"
        | "AddressBook/changes"
        | "AddressBook/set"
        | "ContactCard/get"
        | "ContactCard/query"
        | "ContactCard/changes"
        | "ContactCard/set"
        | "ContactCard/findDuplicates"
        | "ContactCard/merge"
        | "ContactCard/galSearch"
        | "ContactCard/directoryTree"
        | "ContactCard/directoryMembers"
        | "ContactCard/directorySearch"
        | "ContactGroup/get"
        | "ContactGroup/query"
        | "ContactGroup/set"
        | "ContactGroup/expand" => "urn:ietf:params:jmap:contacts",
        "Task/get"
        | "Task/query"
        | "Task/changes"
        | "Task/set"
        | "TaskComment/get"
        | "TaskComment/set"
        | "TaskList/get"
        | "TaskList/set"
        | "TaskListMember/set"
        | "TaskList/tasks"
        | "TaskList/taskSet"
        | "TaskAssigned/get"
        | "TaskAssigned/setStatus" => "urn:ietf:params:jmap:tasks",
        "Reminder/get" | "Reminder/dismiss" | "Reminder/snooze" => {
            "urn:setjoin:params:jmap:reminders"
        }
        "QuickStep/get"
        | "QuickStep/set"
        | "QuickStep/apply"
        | "SavedSearch/list"
        | "SavedSearch/set"
        | "SavedSearch/delete"
        | "EmailTemplate/list"
        | "EmailTemplate/set"
        | "EmailTemplate/delete" => "urn:setjoin:params:jmap:mail",
        "Blob/get" | "Blob/copy" | "Blob/lookup" => "urn:ietf:params:jmap:blob",
        _ => return None,
    })
}
pub(super) fn capability(name: &str) -> &'static str {
    metadata(name).unwrap_or(CORE)
}
pub(super) fn registered(name: &str) -> bool {
    metadata(name).is_some()
}

#[cfg(test)]
mod family_tests {
    use super::*;

    #[test]
    fn null_family_args_classify_natively_by_call() {
        assert!(crate::jmap::family::classify_call("Test/get", "null", "c", None).is_none());
        assert_eq!(
            metadata("CalendarEvent/get"),
            Some("urn:ietf:params:jmap:calendars")
        );
        let call = Call {
            name: "Core/echo".into(),
            args: RawValue::from_string("null".into()).expect("null"),
            id: "c".into(),
        };
        assert_eq!(capability(&call.name), CORE);
        assert!(registered(&call.name));
    }
}
