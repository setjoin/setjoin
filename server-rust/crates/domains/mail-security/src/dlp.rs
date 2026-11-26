//! Slice `dlp` (#325): Go's `admin.DLPHandler` (pattern list and replace),
//! `admin.AntiPhishHandler` (anti-phishing configuration) and
//! `admin.LinkProtectAuditHandler` (the click audit list).
//!
//! The gateway adapter checks the console gate (`requireMailPerm`, `requireMailSecurity`,
//! `requireSecurityWrite`, `requireLogsPerm`) first. `dlp_policies`, `system_config` and
//! `link_protect_audit` carry no tenant column, so reads run via `AdminReadTx`; the only
//! scoping is the domain scope of a domain-scoped admin on the pattern list. The pattern
//! replace calls `rust_mailsec_dlp_patterns_replace`; the anti-phish write calls the
//! owning `rust_system_config_upsert_batch` reducer.
use super::{command, deadline, done, envelope, invalid, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

/// `actionToSeverity`.
pub fn action_to_severity(action: &str) -> &'static str {
    match action {
        "block" => "critical",
        "quarantine" => "high",
        "notify_admin" => "medium",
        _ => "low",
    }
}

/// `severityToAction`.
pub fn severity_to_action(severity: &str) -> &'static str {
    match severity {
        "critical" => "block",
        "high" => "quarantine",
        "medium" => "notify_admin",
        _ => "warn",
    }
}

/// One submitted pattern row (`id` is read by Go and ignored on write).
#[derive(Default, Clone)]
pub struct Pattern {
    pub name: String,
    pub regex: String,
    pub severity: String,
    pub enabled: bool,
}

/// `GET /admin/dlp/patterns`: scoped admins see global patterns and their own domain's.
pub async fn patterns_get(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let domain_scope = admin.enforced_domain_scope().unwrap_or(0);
    let rows = factory
        .run_admin_read_contract(admin, &sql::DLP_PATTERNS_GET, &[&domain_scope])
        .await?;
    let mut items = vec![];
    for row in &rows {
        let id: i64 = row.try_get(0).map_err(|_| invalid())?;
        let name: String = row.try_get(1).map_err(|_| invalid())?;
        let regex: String = row.try_get(2).map_err(|_| invalid())?;
        let action: String = row.try_get(3).map_err(|_| invalid())?;
        let enabled: bool = row.try_get(4).map_err(|_| invalid())?;
        // `id,omitempty`: a zero id is left out.
        let id = if id == 0 {
            String::new()
        } else {
            format!("\"id\":{id},")
        };
        items.push(format!(
            "{{{id}\"name\":{},\"regex\":{},\"severity\":{},\"enabled\":{enabled}}}",
            s(&name),
            s(&regex),
            s(action_to_severity(&action))
        ));
    }
    Ok(done(format!("[{}]", items.join(","))))
}

fn s(text: &str) -> String {
    crate::s(text)
}

/// Why the replace did not commit.
pub enum ReplaceError {
    /// Go's `failed to clear patterns` (500).
    Clear,
    /// Go's `failed to save patterns` (500).
    Save,
    /// The commit outcome is unknown (503).
    Unknown([u8; 16]),
}

/// `PUT /admin/dlp/patterns`: delete every pattern row, then insert the submitted rows
/// (priority is the position), in one transaction.
pub async fn patterns_put(
    factory: &TxFactory,
    user: &UserPrincipal,
    patterns: &[Pattern],
    operation: [u8; 16],
) -> Result<(), ReplaceError> {
    // pgx caps a statement at 65535 bind parameters; Go sends five per row.
    if patterns.len() * 5 > 65535 {
        return Err(ReplaceError::Save);
    }
    let names: Vec<String> = patterns.iter().map(|p| p.name.clone()).collect();
    let enabled: Vec<bool> = patterns.iter().map(|p| p.enabled).collect();
    let actions: Vec<String> = patterns
        .iter()
        .map(|p| severity_to_action(&p.severity).to_owned())
        .collect();
    let regexes: Vec<String> = patterns.iter().map(|p| p.regex.clone()).collect();
    let digest = format!(
        "dlp.patterns.put:{}",
        patterns
            .iter()
            .map(|p| format!(
                "{}\u{1f}{}\u{1f}{}\u{1f}{}",
                p.name, p.regex, p.severity, p.enabled
            ))
            .collect::<Vec<_>>()
            .join("\u{1e}")
    );
    let env = envelope(user.user(), user.generation(), operation, &digest);
    let outcome = factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::DLP_PATTERNS_REPLACE,
            &[&names, &enabled, &actions, &regexes],
            Some(command("dlp.patterns.put")),
            |rows| {
                if rows.len() == 1 {
                    Ok(())
                } else {
                    Err(invalid())
                }
            },
        )
        .await;
    match outcome {
        CommandOutcome::Committed(()) => Ok(()),
        CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(f))
            if f.message.contains("dlp_clear_failed") =>
        {
            Err(ReplaceError::Clear)
        }
        CommandOutcome::RolledBack(_) => Err(ReplaceError::Save),
        CommandOutcome::Unknown { operation } => Err(ReplaceError::Unknown(operation.0)),
    }
}

// ---- anti-phishing configuration ----

/// `rawStringSlice`: absent or empty is `[]`; a decode error is `[]`; JSON null is nil.
fn raw_slice(raw: Option<&String>) -> Option<Vec<String>> {
    let Some(v) = raw.filter(|v| !v.is_empty()) else {
        return Some(vec![]);
    };
    match serde_json::from_str::<Option<Vec<Option<String>>>>(v) {
        Ok(items) => items.map(|l| l.into_iter().map(Option::unwrap_or_default).collect()),
        Err(_) => Some(vec![]),
    }
}

/// `GET /admin/anti-phish`: `antiphish_%` rows, values trimmed of `"`, with Go's defaults.
pub async fn antiphish_get(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::ANTIPHISH_GET, &[])
        .await?;
    let mut raw = std::collections::BTreeMap::new();
    for row in &rows {
        let key: String = row.try_get(0).map_err(|_| invalid())?;
        let value: String = row.try_get(1).map_err(|_| invalid())?;
        raw.insert(key, value.trim_matches('"').to_owned());
    }
    let flag = |key: &str, default: bool| match raw.get(key) {
        None => default,
        Some(v) => v == "true" || v == "True",
    };
    let list = |key: &str| match raw_slice(raw.get(key)) {
        None => "null".to_owned(),
        Some(items) => format!(
            "[{}]",
            items.iter().map(|d| s(d)).collect::<Vec<_>>().join(",")
        ),
    };
    Ok(done(format!(
        "{{\"display_name_enabled\":{},\"lookalike_enabled\":{},\"contact_graph_enabled\":{},\"strict_mode\":{},\"exclusion_domains\":{},\"exclusion_users\":{}}}",
        flag("antiphish_display_name", true),
        flag("antiphish_lookalike", true),
        flag("antiphish_contact_graph", true),
        flag("antiphish_strict_mode", false),
        list("antiphish_exclusion_domains"),
        list("antiphish_exclusion_users"),
    )))
}

/// The decoded `PUT /admin/anti-phish` body.
#[derive(Default)]
pub struct AntiPhish {
    pub display_name: bool,
    pub lookalike: bool,
    pub contact_graph: bool,
    pub strict_mode: bool,
    pub domains: Option<Vec<String>>,
    pub users: Option<Vec<String>>,
}

/// Encode `PUT /admin/anti-phish` keys and JSON values for the worker-only
/// `sql::ANTIPHISH_PUT` (`rust_system_config_upsert_batch`) contract.
/// `json.Marshal` of a nil slice is `null`.
pub fn antiphish_put_args(body: &AntiPhish) -> (Vec<String>, Vec<String>) {
    let list = |items: &Option<Vec<String>>| match items {
        None => "null".to_owned(),
        Some(l) => format!("[{}]", l.iter().map(|d| s(d)).collect::<Vec<_>>().join(",")),
    };
    let keys: Vec<String> = [
        "antiphish_display_name",
        "antiphish_lookalike",
        "antiphish_contact_graph",
        "antiphish_strict_mode",
        "antiphish_exclusion_domains",
        "antiphish_exclusion_users",
    ]
    .iter()
    .map(|k| (*k).to_owned())
    .collect();
    let values: Vec<String> = vec![
        body.display_name.to_string(),
        body.lookalike.to_string(),
        body.contact_graph.to_string(),
        body.strict_mode.to_string(),
        list(&body.domains),
        list(&body.users),
    ];
    (keys, values)
}

// ---- link-protect audit ----

/// One audit row. `message_id` and `client_ip` may be NULL, which Go's scan cannot take.
pub struct AuditRow {
    pub id: i64,
    pub url_hash: String,
    pub verdict: String,
    pub scanner: String,
    pub message_id: Option<i64>,
    pub mailbox_id: i64,
    pub client_ip: Option<String>,
    /// Whole seconds since the epoch (Go formats with `time.RFC3339`).
    pub epoch: i64,
}

/// `GET /admin/link-protect/audit`. `since` is a UTC `YYYY-MM-DDTHH:MM:SS.ffffffZ` text.
/// Go's `rows.Scan` failure on a NULL closes the rows, so the list ends at that row.
pub async fn audit_list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    since: Option<&str>,
    url_hash: &str,
    limit: i64,
) -> Result<Vec<AuditRow>, StatementFailure> {
    let since_text: Option<String> = since.map(str::to_owned);
    let mut tx = factory.begin_admin_read(admin).await?;
    let rows = tx
        .query_iterated_contract(
            &sql::LINK_PROTECT_AUDIT_LIST,
            &[&since_text, &url_hash, &limit],
        )
        .await?;
    tx.finish().await?;
    let mut out = vec![];
    for row in &rows {
        let (Ok(message_id), Ok(client_ip)) = (
            row.try_get::<_, Option<i64>>(4),
            row.try_get::<_, Option<String>>(6),
        ) else {
            return Err(invalid());
        };
        if message_id.is_none() || client_ip.is_none() {
            break;
        }
        out.push(AuditRow {
            id: row.try_get(0).map_err(|_| invalid())?,
            url_hash: row.try_get(1).map_err(|_| invalid())?,
            verdict: row.try_get(2).map_err(|_| invalid())?,
            scanner: row.try_get(3).map_err(|_| invalid())?,
            message_id,
            mailbox_id: row.try_get(5).map_err(|_| invalid())?,
            client_ip,
            epoch: row.try_get(7).map_err(|_| invalid())?,
        });
    }
    Ok(out)
}

// ---- link-protect click verdict decoding ----

/// What the click reducer decided, or why the audit could not be made durable.
pub enum Click {
    /// `"safe"`, `"malicious"` or `"unknown"`.
    Verdict(String),
    /// The reducer failed: Go fails closed to the warn interstitial.
    Failed,
    /// The mailbox id of the (signed) token cannot name an owner; Go answers it.
    Unscoped,
}

/// Extract the `"verdict"` string from `link_protect_check_and_audit`'s JSON output.
pub fn parse_click_verdict(text: &str) -> Result<String, StatementFailure> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|_| invalid())?;
    value["verdict"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(invalid)
}
