//! Platform slice `system-features`, group `welcome-email`: the org-wide welcome message
//! (`/admin/system/welcome-email*`), Go's `WelcomeEmailHandler`.
use super::{command, deadline, done, envelope, invalid, s, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};
use std::collections::BTreeMap;

#[derive(Clone, Default)]
pub struct Locale {
    pub subject: String,
    pub body_text: String,
    pub body_html: String,
}

#[derive(Default)]
pub struct Config {
    pub enabled: bool,
    pub default_locale: String,
    pub locales: Option<BTreeMap<String, Locale>>,
}

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

pub enum Read {
    Stored(String),
    Shell(String),
}

pub async fn get(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<Read, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::WELCOME_GET, &[])
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

pub async fn put(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    value: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor_id = user.user().get();
    let env = envelope(user.user(), user.generation(), operation, value);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::WELCOME_PUT,
            &[&value, &actor_id],
            Some(command("welcome_email_set")),
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

pub async fn test_send(
    factory: &TxFactory,
    user: &UserPrincipal,
    _admin: &AdminPermissionProof,
    subject: &str,
    body_text: &str,
    body_html: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor_id = user.user().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{subject}:{body_text}:{body_html}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::WELCOME_TEST_SEND,
            &[&actor_id, &subject, &body_text, &body_html],
            Some(command("welcome_email_test_send")),
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
