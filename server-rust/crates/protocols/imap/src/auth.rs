//! LOGIN and AUTHENTICATE PLAIN: a port of `handleLogin`/`handleAuthenticate`
//! including their ordering, replies and audit effects.
use crate::{
    hooks::{ConnectionMeta, ThreatAction, ThreatPolicy, WebhookPolicy},
    session::{split_args, Session},
};
use base64::{
    alphabet,
    engine::{general_purpose::GeneralPurposeConfig, GeneralPurpose},
    Engine,
};
use setjoin_pg::Type;
use sha2::{Digest, Sha256};
use std::time::SystemTime;

/// Go's `base64.StdEncoding`: padded, but non-zero trailing bits are accepted.
const STD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
);

fn non_empty(s: &str) -> Option<&str> {
    (!s.is_empty()).then_some(s)
}

#[derive(Clone, Copy)]
enum Style {
    Login,
    Authenticate,
}

pub(crate) async fn login(s: &mut Session, tag: &str, args: &str) {
    if s.authed {
        s.reply(tag, "NO Already authenticated");
        return;
    }
    if s.reject_plaintext_auth(tag) {
        return;
    }
    let parts = split_args(args);
    if parts.len() < 2 {
        s.reply(tag, "BAD Missing arguments");
        return;
    }
    let email = parts[0].trim_matches('"').to_string();
    let password = parts[1].trim_matches('"').to_string();
    credentials(s, tag, &email, &password, Style::Login).await;
}

pub(crate) async fn authenticate(s: &mut Session, tag: &str, args: &str) {
    if s.authed {
        s.reply(tag, "BAD Already authenticated");
        return;
    }
    if s.reject_plaintext_auth(tag) {
        return;
    }
    let mut fields = args.split_whitespace();
    let Some(mechanism) = fields.next() else {
        s.reply(tag, "BAD mechanism required");
        return;
    };
    if !mechanism.eq_ignore_ascii_case("PLAIN") {
        s.reply(tag, "NO Only AUTH=PLAIN supported");
        return;
    }
    s.reply("+", "Ready for additional data");
    // A failed read ends this command silently; the command loop then
    // meets the same condition (Go parity).
    let Some(line) = s.continuation().await else {
        return;
    };
    if line == "*" {
        s.reply(tag, "BAD Authentication cancelled");
        return;
    }
    let Ok(decoded) = STD.decode(line.as_bytes()) else {
        s.reply(tag, "BAD Invalid base64");
        return;
    };
    let decoded = String::from_utf8_lossy(&decoded).into_owned();
    let parts: Vec<&str> = decoded.splitn(3, '\0').collect();
    if parts.len() < 3 {
        s.reply(tag, "BAD Invalid PLAIN credentials");
        return;
    }
    let (email, password) = (parts[1].to_string(), parts[2].to_string());
    credentials(s, tag, &email, &password, Style::Authenticate).await;
}

async fn log_event(
    s: &Session,
    user: Option<i64>,
    event: &str,
    provider: &str,
    email: &str,
    ip: Option<&str>,
) {
    // Best effort, errors swallowed: logging never breaks authentication.
    let _ = s
        .server
        .db
        .record_protocol_auth_event(
            user,
            event,
            provider,
            non_empty(email),
            ip.and_then(non_empty),
        )
        .await;
}

async fn webhook(s: &Session, success: bool, email: &str, provider: &str, ip: &str) {
    if let WebhookPolicy::Wired(sink) = &s.server.webhooks {
        if success {
            sink.login(email, provider, ip).await;
        } else {
            sink.login_failed(email, provider, ip).await;
        }
    }
}

async fn credentials(s: &mut Session, tag: &str, email: &str, password: &str, style: Style) {
    let authenticated_at = SystemTime::now();
    let client_ip = s
        .peer
        .map(|p| p.ip().to_canonical().to_string())
        .unwrap_or_else(|| "unknown".into());
    let peer_text = s.peer.map(|p| p.to_string()).unwrap_or_default();
    let mut meta = ConnectionMeta {
        source_ip: client_ip.clone(),
        username: email.to_string(),
        ..ConnectionMeta::default()
    };
    let gate = match &s.server.threat {
        ThreatPolicy::Enforced(gate) => Some(gate.clone()),
        ThreatPolicy::Unwired => None,
    };
    if let Some(gate) = &gate {
        let (action, delay) = gate.intercept(&meta).await;
        match action {
            ThreatAction::Reject | ThreatAction::Tarpitted => {
                if action == ThreatAction::Tarpitted && !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                log_event(s, None, "login_failed", "threat", email, Some(&client_ip)).await;
                s.reply(tag, "NO Authentication temporarily unavailable");
                return;
            }
            ThreatAction::RateLimited => {
                log_event(
                    s,
                    None,
                    "login_failed",
                    "rate_limit",
                    email,
                    Some(&client_ip),
                )
                .await;
                s.reply(
                    tag,
                    "NO Too many authentication attempts \u{2014} try again later",
                );
                return;
            }
            ThreatAction::Allow => {}
        }
    }
    // App password first.
    if let Some(user) = check_app_password(s, email, password).await {
        meta.app_password = true;
        admit(
            s,
            tag,
            user,
            email,
            &client_ip,
            &mut meta,
            true,
            authenticated_at,
            style,
        )
        .await;
        return;
    }

    let Some(user) = check_password(s, email, password).await else {
        if let Some(gate) = &gate {
            gate.record_result(&meta, false, 0).await;
        }
        log_event(s, None, "login_failed", "bcrypt", email, Some(&peer_text)).await;
        webhook(s, false, email, "bcrypt", &client_ip).await;
        s.reply(tag, "NO Authentication failed");
        return;
    };
    log_event(s, Some(user), "login", "bcrypt", email, Some(&peer_text)).await;
    webhook(s, true, email, "bcrypt", &client_ip).await;
    admit(
        s,
        tag,
        user,
        email,
        &client_ip,
        &mut meta,
        false,
        authenticated_at,
        style,
    )
    .await;
}

/// Identity install plus the post-credential checks, in Go's order. The app
/// password branch dispatches its webhook after the threat evaluation; the
/// password branch already dispatched it.
#[allow(clippy::too_many_arguments)]
async fn admit(
    s: &mut Session,
    tag: &str,
    user: i64,
    email: &str,
    client_ip: &str,
    meta: &mut ConnectionMeta,
    app: bool,
    authenticated_at: SystemTime,
    style: Style,
) {
    s.reset_selected();
    s.authed = true;
    s.user_id = user;
    if let ThreatPolicy::Enforced(gate) = s.server.threat.clone() {
        gate.record_result(meta, true, user).await;
        meta.user_id = user;
        let (action, reason) = gate.evaluate_post_auth(meta).await;
        if action == ThreatAction::Reject {
            log_event(
                s,
                Some(user),
                "login_failed",
                "conditional_access",
                email,
                Some(client_ip),
            )
            .await;
            s.authed = false;
            s.user_id = 0;
            s.reply(tag, &format!("NO [{reason}] Access blocked by policy"));
            return;
        }
    }
    if app {
        webhook(s, true, email, "app_password", client_ip).await;
    }
    if deny_if_imap_disabled(s, tag, user).await || deny_if_mailbox_blocked(s, tag, user).await {
        return;
    }
    meta.device_bound = false;
    // Release-then-acquire: hand back any slot before taking the new identity's.
    s.release = None;
    match s.server.users.try_acquire(user) {
        Ok(slot) => s.release = Some(slot),
        Err(()) => {
            s.reply(tag, "NO Too many connections from this account");
            s.authed = false;
            s.user_id = 0;
            return;
        }
    }
    s.session_release = None;
    if let Some(registry) = s.server.registry.clone() {
        s.session_release = Some(registry.register(user, authenticated_at, s.close_tx.clone()));
    }
    let text = match style {
        Style::Login => format!("OK [CAPABILITY {}] LOGIN completed", s.capabilities()),
        Style::Authenticate => "OK AUTHENTICATE completed".to_string(),
    };
    s.reply(tag, &text);
}

fn deny(s: &mut Session, tag: &str, msg: &str) -> bool {
    s.authed = false;
    s.user_id = 0;
    s.reply(tag, msg);
    true
}

/// Fail-open only when no row exists; any database error fails closed.
async fn deny_if_imap_disabled(s: &mut Session, tag: &str, user: i64) -> bool {
    let rows = s
        .server
        .db
        .read(
            "SELECT COALESCE(imap_enabled, TRUE) FROM user_imap_settings WHERE user_id = $1",
            &[(&user, Type::INT8)],
        )
        .await;
    match rows {
        Err(_) => deny(s, tag, "NO internal error"),
        Ok(rows) => match rows.first() {
            None => false,
            Some(row) => match row.try_get::<_, bool>(0) {
                Ok(true) => false,
                Ok(false) => deny(s, tag, "NO IMAP access disabled for this account by policy"),
                Err(_) => deny(s, tag, "NO internal error"),
            },
        },
    }
}

async fn deny_if_mailbox_blocked(s: &mut Session, tag: &str, user: i64) -> bool {
    let mailbox: Option<i64> = s
        .server
        .db
        .read(
            "SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1",
            &[(&user, Type::INT8)],
        )
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|r| r.try_get(0).ok()));
    let Some(mailbox) = mailbox else {
        return deny(s, tag, "NO Mailbox access unavailable");
    };
    let allowed = s
        .server
        .db
        .read(
            "SELECT mailbox_lifecycle_access_allowed($1)",
            &[(&mailbox, Type::INT8)],
        )
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
        .unwrap_or(false);
    if !allowed {
        return deny(s, tag, "NO Mailbox access suspended");
    }
    false
}

/// `pwhash.CheckAppPassword`: SHA-256 of the presented token, bookkeeping and
/// the audit rows on both outcomes (the failure row carries no IP).
async fn check_app_password(s: &Session, email: &str, token: &str) -> Option<i64> {
    let digest = Sha256::digest(token.as_bytes());
    let hash: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    let found = s
        .server
        .db
        .read(
            "SELECT u.id FROM users u JOIN app_passwords ap ON ap.user_id = u.id \
             WHERE lower(u.email) = lower($1) AND u.enabled = TRUE AND ap.token_hash = $2 \
             AND ap.revoked_at IS NULL AND (ap.expires_at IS NULL OR ap.expires_at > now())",
            &[(&email, Type::TEXT), (&hash, Type::TEXT)],
        )
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, i64>(0).ok()));
    let Some(user) = found else {
        log_event(s, None, "login_failed", "app_password", email, None).await;
        return None;
    };
    let _ = s.server.db.touch_app_password(user, &hash).await;
    log_event(s, Some(user), "login", "app_password", email, None).await;
    // Go re-reads the enabled user; a vanished row makes the credential fail
    // over to the password check after the success row was already written.
    let rows = s
        .server
        .db
        .read(
            "SELECT id FROM users WHERE id = $1 AND enabled = TRUE",
            &[(&user, Type::INT8)],
        )
        .await
        .ok()?;
    rows.first()?;
    Some(user)
}

/// `auth.CheckPassword`: bcrypt/SM3 verification, best-effort below-floor
/// self-heal, then the fail-closed guest check.
async fn check_password(s: &Session, email: &str, password: &str) -> Option<i64> {
    let rows = s
        .server
        .db
        .read(
            "SELECT u.id, u.password_hash FROM users u JOIN domains d ON d.id = u.domain_id \
             WHERE u.email = $1 AND u.enabled = TRUE",
            &[(&email, Type::TEXT)],
        )
        .await
        .ok()?;
    let row = rows.first()?;
    let id: i64 = row.get(0);
    let hash: String = row.try_get(1).ok()?;
    if hash.is_empty() {
        return None;
    }
    let verified = hash.clone();
    let password = password.to_string();
    let (valid, upgrade) = tokio::task::spawn_blocking(move || {
        let valid = setjoin_authz::password::verify(&hash, &password);
        let upgrade = valid
            .then(|| setjoin_authz::password::standard_upgrade(&hash, &password))
            .flatten();
        (valid, upgrade)
    })
    .await
    .ok()?;
    if !valid {
        return None;
    }
    if let Some(new) = upgrade {
        let _ = s
            .server
            .db
            .upgrade_legacy_protocol_password(id, email, &verified, &new)
            .await;
    }
    let guest = s
        .server
        .db
        .read("SELECT is_guest_account($1)", &[(&id, Type::INT8)])
        .await
        .ok()?;
    if guest.first()?.try_get::<_, bool>(0).ok()? {
        return None;
    }
    Some(id)
}
