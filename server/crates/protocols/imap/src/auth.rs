//! LOGIN and AUTHENTICATE PLAIN: a port of `handleLogin`/`handleAuthenticate`
//! including their ordering, replies and audit effects. Credential checks are
//! the shared `setjoin_authz::basic` module (#355-0); a TOTP user's account
//! password is refused (owner-approved divergence, oracle/divergences.json).
use crate::{
    hooks::{ConnectionMeta, ThreatAction, ThreatPolicy, WebhookPolicy},
    session::{split_args, Session},
};
use base64::{
    alphabet,
    engine::{general_purpose::GeneralPurposeConfig, GeneralPurpose},
    Engine,
};
use setjoin_authz::{
    basic::{Policy, Verdict},
    policy_gate::{self, GateDenial, ProtocolSurface},
    principals::{PrincipalError, UserPrincipal},
};
use setjoin_contracts::ids::ActorId;
use setjoin_pg::Type;
use std::time::SystemTime;

/// Go's `base64.StdEncoding`: padded, but non-zero trailing bits are accepted.
const STD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
);

/// IMAP's unified credential policy (#355-0, #542): app-then-account order,
/// guest app passwords refused (`GuestAppPasswords::Refuse`), and TOTP users'
/// account passwords refused (`TotpAccountPassword::Refuse`).
const POLICY: Policy = match ProtocolSurface::Imap.basic_policy() {
    Some(p) => p,
    None => unreachable!(),
};

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
    setjoin_authz::basic::record_event(&s.server.db, user, event, provider, email, ip).await;
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
    let auth_exec = s.server.auth_db.as_ref().unwrap_or(&s.server.db);
    let verdict =
        setjoin_authz::basic::verify(auth_exec, &s.server.passwords, email, password, POLICY).await;
    match verdict {
        Verdict::AppPassword(user) => {
            meta.app_password = true;
            admit(
                s,
                tag,
                user.user_id,
                email,
                &client_ip,
                &mut meta,
                true,
                authenticated_at,
                style,
            )
            .await;
        }
        Verdict::AccountPassword(user) => {
            log_event(
                s,
                Some(user.user_id),
                "login",
                "bcrypt",
                email,
                Some(&peer_text),
            )
            .await;
            webhook(s, true, email, "bcrypt", &client_ip).await;
            admit(
                s,
                tag,
                user.user_id,
                email,
                &client_ip,
                &mut meta,
                false,
                authenticated_at,
                style,
            )
            .await;
        }
        Verdict::Refused => {
            if let Some(gate) = &gate {
                gate.record_result(&meta, false, 0).await;
            }
            log_event(s, None, "login_failed", "bcrypt", email, Some(&peer_text)).await;
            webhook(s, false, email, "bcrypt", &client_ip).await;
            s.reply(tag, "NO Authentication failed");
        }
    }
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
    s.principal = None;
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
            s.principal = None;
            s.reply(tag, &format!("NO [{reason}] Access blocked by policy"));
            return;
        }
    }
    if app {
        webhook(s, true, email, "app_password", client_ip).await;
    }
    let Some(tx_factory) = s.server.tx_factory.clone() else {
        deny(s, tag, "NO internal error");
        return;
    };
    let Ok(actor) = ActorId::new(user) else {
        deny(s, tag, "NO internal error");
        return;
    };
    let Ok(user_principal) = tx_factory
        .mint_capability_user(actor, email, client_ip)
        .await
    else {
        deny(s, tag, "NO internal error");
        return;
    };
    if deny_if_imap_disabled(s, tag, &tx_factory, &user_principal, user).await
        || deny_if_policy_gate_blocks(s, tag, user).await
    {
        return;
    }
    let principal = match tx_factory
        .mint_capability_primary_mailbox(actor, email, client_ip)
        .await
    {
        Ok(principal) => principal,
        Err(PrincipalError::MailboxBlocked) => {
            deny(s, tag, "NO Mailbox access suspended");
            return;
        }
        Err(PrincipalError::Forbidden(_)) => {
            deny(s, tag, "NO Mailbox access unavailable");
            return;
        }
        Err(_) => {
            deny(s, tag, "NO internal error");
            return;
        }
    };
    if principal.require_read().is_err() {
        deny(s, tag, "NO Mailbox access unavailable");
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
            s.principal = None;
            return;
        }
    }
    s.user_principal = Some(user_principal);
    s.user_email = email.to_owned();
    s.client_ip = client_ip.to_owned();
    s.principal = Some(principal);
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
    s.user_email.clear();
    s.client_ip.clear();
    s.user_principal = None;
    s.principal = None;
    s.reply(tag, msg);
    true
}

/// Fail-open only when no row exists; any database error fails closed.
async fn deny_if_imap_disabled(
    s: &mut Session,
    tag: &str,
    tx_factory: &setjoin_authz::principals::TxFactory,
    user_principal: &UserPrincipal,
    user: i64,
) -> bool {
    let rows = tx_factory
        .run_user_read_pipelined(
            user_principal,
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

async fn deny_if_policy_gate_blocks(s: &mut Session, tag: &str, user: i64) -> bool {
    match policy_gate::check_protocol_post_auth(&s.server.db, ProtocolSurface::Imap, user).await {
        Ok(()) => false,
        Err(GateDenial::SessionRevoked) => deny(s, tag, "NO Session revoked"),
        Err(GateDenial::DeviceLockdown) => deny(
            s,
            tag,
            "NO Device not enrolled — contact your administrator",
        ),
        Err(GateDenial::EntitlementDenied(_)) => {
            deny(s, tag, "NO Mail access disabled for this account by policy")
        }
        Err(GateDenial::NoPrimaryMailbox) => deny(s, tag, "NO Mailbox access unavailable"),
        Err(GateDenial::MailboxBlocked) => deny(s, tag, "NO Mailbox access suspended"),
        Err(_) => deny(s, tag, "NO internal error"),
    }
}
