//! `mailserver/internal/assist` and `shared/assist`: the AI-assist envelope,
//! provider configuration and the OpenAI-compatible completion call.
use setjoin_pg::{ScopedExecutor, Type};
use std::time::Duration;

/// `sharedassist.MaxRequestBytes`.
pub const MAX_REQUEST_BYTES: usize = 512 * 1024;
/// `sharedassist.MaxResponseBytes`.
pub const MAX_RESPONSE_BYTES: usize = 1 << 20;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    pub messages: Vec<Message>,
    pub context: String,
    pub locale: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalid {
    EmptyMessages,
    TooLarge,
    Role,
}

impl Invalid {
    /// The handler's `detail` for each sentinel.
    pub fn detail(self) -> &'static str {
        match self {
            Invalid::EmptyMessages => {
                "messages must not be empty and each message must have non-empty content."
            }
            Invalid::TooLarge => "Request content exceeds the maximum allowed size.",
            Invalid::Role => "Message role must be one of: system, user, assistant.",
        }
    }
}

/// `sharedassist.Validate`.
pub fn validate(req: &Request) -> Result<(), Invalid> {
    if req.messages.is_empty() {
        return Err(Invalid::EmptyMessages);
    }
    let mut total = 0usize;
    for m in &req.messages {
        if m.content.is_empty() {
            return Err(Invalid::EmptyMessages);
        }
        if !matches!(m.role.as_str(), "system" | "user" | "assistant") {
            return Err(Invalid::Role);
        }
        total += m.content.len();
    }
    total += req.context.len();
    if total > MAX_REQUEST_BYTES {
        return Err(Invalid::TooLarge);
    }
    Ok(())
}

fn sanitize_preamble(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// `buildMessages`: the caller never speaks at system tier.
pub fn build_messages(req: &Request) -> Vec<Message> {
    let mut out = Vec::new();
    if !req.context.is_empty() {
        let mut system = format!("Context: {}", sanitize_preamble(&req.context));
        if !req.locale.is_empty() {
            system.push_str(". Respond in locale: ");
            system.push_str(&sanitize_preamble(&req.locale));
        }
        out.push(Message {
            role: "system".into(),
            content: system,
        });
    }
    for m in &req.messages {
        let role = if m.role == "system" { "user" } else { &m.role };
        out.push(Message {
            role: role.into(),
            content: m.content.clone(),
        });
    }
    out
}

/// `sharedassist.Config`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub base_url: String,
    pub model: String,
    pub api_key: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// `ErrNotConfigured`: provider URL or model absent/empty.
    NotConfigured,
    /// Any other `LoadConfig` failure (bad URL, failed read).
    Unavailable,
}

async fn get(exec: &ScopedExecutor, key: &str) -> Result<String, ConfigError> {
    let rows = exec
        .read(
            "SELECT get_system_config($1) #>> '{}'",
            &[(&key, Type::TEXT)],
        )
        .await
        .map_err(|_| ConfigError::Unavailable)?;
    let value = rows
        .first()
        .and_then(|r| r.get::<_, Option<String>>(0))
        .unwrap_or_default();
    if setjoin_config_secret::is_config_secret_envelope(value.as_bytes()) {
        let rows = exec
            .read(
                "SELECT get_system_config('identity.deployment_id') #>> '{}'",
                &[],
            )
            .await
            .map_err(|_| ConfigError::Unavailable)?;
        let deployment = rows
            .first()
            .and_then(|row| row.get::<_, Option<String>>(0))
            .ok_or(ConfigError::Unavailable)?;
        let keyring = setjoin_config_secret::keyring_from_env(&deployment)
            .map_err(|_| ConfigError::Unavailable)?;
        let codec = setjoin_config_secret::ConfigSecretCodec::new(keyring)
            .map_err(|_| ConfigError::Unavailable)?;
        let plaintext = codec
            .decrypt(key, value.as_bytes())
            .map_err(|_| ConfigError::Unavailable)?;
        return match serde_json::from_slice::<serde_json::Value>(&plaintext) {
            Ok(serde_json::Value::String(value)) => Ok(value),
            // Go json.Unmarshal(null, &string) leaves the zero value.
            Ok(serde_json::Value::Null) => Ok(String::new()),
            _ => Err(ConfigError::Unavailable),
        };
    }
    Ok(value)
}

/// `LoadConfig`: three `system_config` keys, URL validated as absolute
/// HTTP(S) with a host.
pub async fn load_config(exec: &ScopedExecutor) -> Result<Config, ConfigError> {
    let url = get(exec, "assist.provider_url").await?;
    if url.is_empty() {
        return Err(ConfigError::NotConfigured);
    }
    let trimmed =
        url.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{b}' | '\u{c}'));
    let parsed = reqwest::Url::parse(trimmed).ok();
    if !parsed.as_ref().is_some_and(|u| {
        matches!(u.scheme(), "http" | "https") && u.host_str().is_some_and(|h| !h.is_empty())
    }) {
        return Err(ConfigError::Unavailable);
    }
    let model = get(exec, "assist.model").await?;
    if model.is_empty() {
        return Err(ConfigError::NotConfigured);
    }
    let api_key = get(exec, "assist.api_key").await?;
    Ok(Config {
        base_url: url,
        model,
        api_key,
    })
}

/// A provider failure: Go reports every cause as the same 502.
#[derive(Debug)]
pub struct UpstreamError;

/// `OpenAICompatible.Complete`.
pub async fn complete(config: &Config, req: &Request) -> Result<String, UpstreamError> {
    let messages: Vec<_> = build_messages(req)
        .into_iter()
        .map(|m| serde_json::json!({"role": m.role, "content": m.content}))
        .collect();
    let payload = format!(
        "{{\"model\":{},\"messages\":{}}}",
        serde_json::to_string(&config.model).map_err(|_| UpstreamError)?,
        serde_json::to_string(&messages).map_err(|_| UpstreamError)?
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| UpstreamError)?;
    let mut request = client
        .post(format!("{}/chat/completions", config.base_url))
        .header("Content-Type", "application/json")
        .body(payload);
    if !config.api_key.is_empty() {
        request = request.header("Authorization", format!("Bearer {}", config.api_key));
    }
    let mut response = request.send().await.map_err(|_| UpstreamError)?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(UpstreamError);
    }
    let mut raw = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| UpstreamError)? {
        raw.extend_from_slice(&chunk);
        if raw.len() > MAX_RESPONSE_BYTES {
            return Err(UpstreamError);
        }
    }
    let value: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| UpstreamError)?;
    let content = value
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|c| c.first())
        .ok_or(UpstreamError)?
        .get("message")
        .and_then(|m| m.get("content"));
    match content {
        None | Some(serde_json::Value::Null) => Ok(String::new()),
        Some(serde_json::Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(UpstreamError),
    }
}
