//! `POST /chat/messages/{id}/translate` (#271, deferred here by Chat 3/3).
//! Called by `ChatBRoute` after its feature, entitlement and authentication
//! chain, which is the chain Go's chat mount applies before the handler.
//! Mirrors `mailserver/internal/chat/translate.go`.
use crate::assist::{feature_on, restore, typed_problem};
use crate::{Body, RequestContext};
use hyper::{Request, Response};
use setjoin_authz::Authorized;
use setjoin_pg::ScopedExecutor;
use setjoin_static::assist as logic;
use setjoin_static::wellknown::go_json_string;

pub(crate) async fn serve(
    exec: &ScopedExecutor,
    auth: &Authorized,
    mut r: Request<Body>,
    instance: &str,
    language: &str,
    c: &RequestContext,
    id: String,
    nonce: [u8; 16],
) -> Response<Body> {
    let path = instance;
    let message = r
        .uri()
        .path()
        .split('/')
        .nth(4)
        .and_then(|s| String::from_utf8(crate::inventory::unescape(s)).ok())
        .and_then(|s| s.parse::<i64>().ok());
    let Some(message) = message else {
        return crate::chat::problem(400, "invalid id", path, c, id);
    };
    let locale = async {
        let bytes = crate::chat_channels::read_body(&mut r)
            .await
            .map_err(|_| ())?;
        let fields = crate::chat_channels::decode_fields(&bytes)?;
        Ok::<_, ()>((
            crate::chat_channels::text_field(&fields, "TARGETLOCALE")?,
            bytes,
        ))
    }
    .await;
    let Ok((locale, bytes)) = locale else {
        return crate::chat::problem(400, "invalid JSON", path, c, id);
    };
    if locale.is_empty() {
        return typed_problem(
            422,
            "validation-failed",
            "Validation Failed",
            "targetLocale is required.",
            path,
            language,
            c,
            id,
        );
    }
    match feature_on(exec, "feature.assist").await {
        Some(true) => {}
        Some(false) => {
            return typed_problem(
                503,
                "service-unavailable",
                "Service Unavailable",
                "AI assist is not enabled.",
                path,
                language,
                c,
                id,
            )
        }
        None => return c.upstream.forward(restore(r, bytes), &c.identity).await,
    }
    let actor = auth.context();
    let thread = match setjoin_chat::members::thread(exec, actor, message).await {
        Ok(thread) => thread,
        Err(ref error) => return crate::chat_channels::failure(error, path, c, id, language),
    };
    let Ok(serde_json::Value::Array(items)) = serde_json::from_str::<serde_json::Value>(&thread)
    else {
        return crate::chat::problem(500, "internal error", path, c, id);
    };
    let mut found = None;
    for item in &items {
        let (Some(item_id), Some(channel)) = (
            item.get("messageId").and_then(|v| v.as_i64()),
            item.get("channelId").and_then(|v| v.as_i64()),
        ) else {
            return crate::chat::problem(500, "internal error", path, c, id);
        };
        if item_id == message {
            let body = item
                .get("body")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            found = Some((body, channel));
            break;
        }
    }
    let Some((body, channel)) = found else {
        return crate::chat::problem(404, "message not found", path, c, id);
    };
    let config = match logic::load_config(exec).await {
        Ok(config) => config,
        Err(_) => {
            return typed_problem(
                503,
                "service-unavailable",
                "Service Unavailable",
                "AI assist is not configured.",
                path,
                language,
                c,
                id,
            )
        }
    };
    // Intent to egress is recorded before the provider call.
    match feature_on(exec, "feature.chat_compliance").await {
        Some(false) => {}
        Some(true) => {
            let after = format!(
                "{{\"provider\":{},\"targetLocale\":{}}}",
                go_json_string(&config.model),
                go_json_string(&locale)
            );
            match setjoin_chat::members::translate_egress(
                exec, actor, channel, message, &after, nonce,
            )
            .await
            {
                setjoin_pg::CommandOutcome::Committed(_) => {}
                setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(ref e))
                | setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(ref e)) => {
                    return crate::chat_channels::failure(e, path, c, id, language)
                }
                setjoin_pg::CommandOutcome::RolledBack(_) => {
                    return crate::chat::problem(500, "request failed", path, c, id)
                }
                setjoin_pg::CommandOutcome::Unknown { operation } => {
                    return crate::chat::unknown(operation, path, c, id)
                }
            }
        }
        None => return c.upstream.forward(restore(r, bytes), &c.identity).await,
    }
    let request = logic::Request {
        messages: vec![logic::Message { role: "user".into(), content: body }],
        context: "Translate the following chat message. Respond with ONLY the translated text, no commentary.".into(),
        locale,
    };
    match logic::complete(&config, &request).await {
        Ok(content) => crate::jmap::reply::response(
            format!("{{\"translated\":{}}}\n", go_json_string(&content)),
            c.identity.proto,
            id,
        ),
        // Go writes this as a bare `Problem{502}`: about:blank, unlike Assist's typed one.
        Err(logic::UpstreamError) => crate::chat::problem(
            502,
            "The AI assist provider returned an error. Please try again.",
            path,
            c,
            id,
        ),
    }
}
