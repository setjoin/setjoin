//! Slice `dlp` (#325): Go's `admin.DLPHandler` (pattern list and replace),
//! `admin.AntiPhishHandler` (anti-phishing configuration) and
//! `admin.LinkProtectAuditHandler` (the click audit list).
//!
//! The gateway adapter checks the console gate (`requireMailPerm`, `requireMailSecurity`,
//! `requireSecurityWrite`, `requireLogsPerm`) first. `dlp_policies`, `system_config` and
//! `link_protect_audit` carry no tenant column, so reads are global; the only scoping is the
//! domain scope of a domain-scoped admin on the pattern list. The pattern replace is a
//! receipted reducer (`rust_mailsec_dlp_patterns_replace`: Go's delete-then-insert transaction);
//! the anti-phish write is one upsert statement (Go's six upserts are one implicit batch
//! transaction).
use super::{command, deadline, done, envelope, invalid, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure, Type};

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
    worker: &ScopedExecutor,
    domain_scope: i64,
) -> Result<String, StatementFailure> {
    let rows = if domain_scope > 0 {
        worker
            .read(
                "SELECT id, name, COALESCE(regex_patterns[1], ''), action, enabled FROM dlp_policies \
                 WHERE is_pattern = TRUE AND (domain_id IS NULL OR domain_id = $1) ORDER BY priority, id",
                &[(&domain_scope, Type::INT8)],
            )
            .await?
    } else {
        worker
            .read(
                "SELECT id, name, COALESCE(regex_patterns[1], ''), action, enabled FROM dlp_policies \
                 WHERE is_pattern = TRUE ORDER BY priority, id",
                &[],
            )
            .await?
    };
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
    worker: &ScopedExecutor,
    actor: &AuthContext,
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
    let auth = scope(actor);
    let outcome = setjoin_pg::run_receipted_command(
        worker,
        command("dlp.patterns.put"),
        &envelope(&auth, operation, &digest),
        &auth,
        deadline(),
        "SELECT rust_mailsec_dlp_patterns_replace($4::text[],$5::boolean[],$6::text[],$7::text[]) \
         WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",
        &[
            (&names, Type::TEXT_ARRAY),
            (&enabled, Type::BOOL_ARRAY),
            (&actions, Type::TEXT_ARRAY),
            (&regexes, Type::TEXT_ARRAY),
        ],
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
pub async fn antiphish_get(worker: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = worker
        .read(
            "SELECT key, value::text FROM system_config WHERE key LIKE 'antiphish_%' ORDER BY key",
            &[],
        )
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

/// `PUT /admin/anti-phish`: six upserts, one statement. `json.Marshal` of a nil slice is `null`.
pub async fn antiphish_put(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    body: &AntiPhish,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
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
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("antiphish.put"),
        &envelope(&auth, operation, &format!("antiphish.put:{}", values.join(","))),
        &auth,
        deadline(),
        "INSERT INTO system_config (key, value, description) \
         SELECT t.k, t.v::jsonb, 'anti-phish config' FROM unnest($4::text[], $5::text[]) AS t(k, v) \
         WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>'' \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now() RETURNING true",
        &[(&keys, Type::TEXT_ARRAY), (&values, Type::TEXT_ARRAY)],
        |rows| {
            if rows.len() == 6 {
                Ok(())
            } else {
                Err(invalid())
            }
        },
    )
    .await
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
    worker: &ScopedExecutor,
    since: Option<&str>,
    url_hash: &str,
    limit: i64,
) -> Result<Vec<AuditRow>, StatementFailure> {
    let mut sql = String::from(
        "SELECT id, url_hash, verdict, scanner, message_id, mailbox_id, client_ip, \
         floor(extract(epoch from created_at))::bigint FROM link_protect_audit WHERE 1=1",
    );
    let mut params: Vec<setjoin_pg::Param<'_>> = vec![];
    let since_text = since.map(str::to_owned);
    let hash_text = url_hash.to_owned();
    if let Some(t) = &since_text {
        params.push((t, Type::TEXT));
        sql.push_str(&format!(
            " AND created_at >= ${}::text::timestamptz",
            params.len()
        ));
    }
    if !hash_text.is_empty() {
        params.push((&hash_text, Type::TEXT));
        sql.push_str(&format!(" AND url_hash = ${}", params.len()));
    }
    params.push((&limit, Type::INT8));
    sql.push_str(&format!(
        " ORDER BY created_at DESC LIMIT ${}",
        params.len()
    ));
    let rows = worker.read_iterated(&sql, &params).await?;
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

// ---- link-protect click ----

/// The feature flag `feature.link_protect_strict_mode`: DB row, else the registry default (ON).
pub async fn strict_mode(worker: &ScopedExecutor) -> Result<bool, StatementFailure> {
    let rows = worker
        .read(
            "SELECT COALESCE((SELECT enabled FROM feature_toggles WHERE key='feature.link_protect_strict_mode'), true)",
            &[],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

/// What the click reducer decided, or why the audit could not be made durable.
pub enum Click {
    /// `"safe"`, `"malicious"` or `"unknown"`.
    Verdict(String),
    /// The reducer failed: Go fails closed to the warn interstitial.
    Failed,
    /// The mailbox id of the (signed) token cannot name an owner; Go answers it.
    Unscoped,
}

/// `link_protect_check_and_audit`: the verdict rules and the audit row in one transaction.
/// Ownership is the signed token's mailbox, set as the transaction's tenant scope.
#[allow(clippy::too_many_arguments)]
pub async fn click_audit(
    worker: &ScopedExecutor,
    mailbox: i64,
    url: &str,
    rfc_message_id: &str,
    base: &str,
    scanners: &str,
    all_errors: bool,
    strict: bool,
    ip: &str,
    operation: [u8; 16],
) -> Click {
    use setjoin_contracts::ids::{ActorId, Generation, MailboxId};
    let (Some(actor), Some(mailbox_id)) =
        (ActorId::new(mailbox).ok(), MailboxId::new(mailbox).ok())
    else {
        return Click::Unscoped;
    };
    let auth = setjoin_pg::MailboxAuthContext::from_authenticated_session(
        actor,
        mailbox_id,
        Generation(1),
    );
    let digest =
        format!("link_protect.click:{mailbox}:{url}:{base}:{scanners}:{all_errors}:{strict}");
    let outcome = setjoin_pg::run_receipted_command(
        worker,
        command("link_protect.click"),
        &envelope(&auth, operation, &digest),
        &auth,
        deadline(),
        "SELECT link_protect_check_and_audit($4,$5,$1,$6,$7::text::jsonb,$8,$9,$10)::text \
         WHERE $2::bigint>0 AND $3::text<>''",
        &[
            (&url, Type::TEXT),
            (&rfc_message_id, Type::TEXT),
            (&base, Type::TEXT),
            (&scanners, Type::TEXT),
            (&all_errors, Type::BOOL),
            (&strict, Type::BOOL),
            (&ip, Type::TEXT),
        ],
        |rows| {
            let text: String = rows
                .first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid)?;
            let value: serde_json::Value = serde_json::from_str(&text).map_err(|_| invalid())?;
            value["verdict"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(invalid)
        },
    )
    .await;
    match outcome {
        CommandOutcome::Committed(verdict) => Click::Verdict(verdict),
        _ => Click::Failed,
    }
}
