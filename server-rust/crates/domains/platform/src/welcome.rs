//! Platform slice `system-features`, group `welcome-email`: the org-wide welcome message
//! (`/admin/system/welcome-email*`), Go's `WelcomeEmailHandler`. The config lives in
//! `system_config` under `welcome_email`; the test send delivers into the caller's own inbox
//! through `deliver()` (no mailer), mirrored by `rust_platform_welcome_test_send`.
use super::{command, deadline, done, envelope, invalid, s, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};
use std::collections::BTreeMap;

/// Go's `notify.WelcomeLocale`.
#[derive(Clone, Default)]
pub struct Locale {
    pub subject: String,
    pub body_text: String,
    pub body_html: String,
}
/// Go's `notify.WelcomeEmailConfig` as decoded; `locales` is `None` for a nil map.
#[derive(Default)]
pub struct Config {
    pub enabled: bool,
    pub default_locale: String,
    pub locales: Option<BTreeMap<String, Locale>>,
}

/// Go's `validateWelcomeConfig` (the first unknown locale in sorted order stands in for
/// Go's random map iteration).
pub fn validate(config: &Config) -> Result<(), String> {
    const KNOWN: [&str; 3] = ["en", "zh", "de"];
    if !KNOWN.contains(&config.default_locale.as_str()) {
        return Err("default_locale must be one of en, zh, de".into());
    }
    let en = config.locales.as_ref().and_then(|l| l.get("en"));
    if en.is_none_or(|l| l.subject.is_empty() || l.body_text.is_empty()) {
        return Err("the en locale must have a non-empty subject and plain-text body".into());
    }
    for locale in config.locales.iter().flat_map(|l| l.keys()) {
        if !KNOWN.contains(&locale.as_str()) {
            return Err(format!(
                "unknown locale {} (allowed: en, zh, de)",
                setjoin_contracts::go_quote::quote(locale.as_bytes())
            ));
        }
    }
    Ok(())
}

/// `json.Marshal(cfg)`: struct field order, sorted map keys.
pub fn marshal(config: &Config) -> String {
    let locales = match &config.locales {
        None => "null".to_owned(),
        Some(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(key, l)| format!(
                    "{}:{{\"subject\":{},\"body_text\":{},\"body_html\":{}}}",
                    s(key),
                    s(&l.subject),
                    s(&l.body_text),
                    s(&l.body_html)
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
    };
    super::go_escape(&format!(
        "{{\"enabled\":{},\"default_locale\":{},\"locales\":{locales}}}",
        config.enabled,
        s(&config.default_locale)
    ))
}

/// What `GET` answers.
pub enum Read {
    /// The stored jsonb text, written verbatim.
    Stored(String),
    /// Not seeded: Go's empty disabled shell, written by `WriteJSON`.
    Shell(String),
}

pub async fn get(exec: &ScopedExecutor) -> Result<Read, StatementFailure> {
    let rows = exec
        .read("SELECT get_system_config('welcome_email')::text", &[])
        .await?;
    let stored: Option<String> = rows
        .first()
        .ok_or_else(invalid)?
        .try_get(0)
        .map_err(|_| invalid())?;
    Ok(match stored {
        Some(text) if text != "null" => Read::Stored(text),
        _ => Read::Shell(done(
            "{\"enabled\":false,\"default_locale\":\"en\",\"locales\":{}}".into(),
        )),
    })
}

/// `PUT` of an already validated and marshalled config, recording the actor as
/// `updated_by`.
pub async fn put(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    value: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("welcome_email_set"),
        &envelope(&auth, operation, value),
        &auth,
        deadline(),
        "SELECT key FROM public.set_system_config('welcome_email', $4::text::jsonb, false, $2::bigint) \
         WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
        &[(&value, Type::TEXT)],
        |rows| if rows.len() == 1 { Ok(()) } else { Err(invalid()) },
    )
    .await
}

/// `POST .../test`: deliver the supplied content to the caller's own primary mailbox.
pub async fn test_send(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    subject: &str,
    body_text: &str,
    body_html: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("welcome_email_test_send"),
        &envelope(
            &auth,
            operation,
            &format!("{subject}:{body_text}:{body_html}"),
        ),
        &auth,
        deadline(),
        "SELECT public.rust_platform_welcome_test_send($2::bigint, $4::text, $5::text, $6::text) \
         WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
        &[
            (&subject, Type::TEXT),
            (&body_text, Type::TEXT),
            (&body_html, Type::TEXT),
        ],
        |rows| {
            if rows.len() == 1 {
                Ok(())
            } else {
                Err(invalid())
            }
        },
    )
    .await
}
