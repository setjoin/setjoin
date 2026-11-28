//! Conditional access (F03) slice `policies`: the policy lifecycle routes. Reads run via
//! `AdminReadTx`; writes run via `AdminWriteTx` (`ReducerWritesCoreAudit`) with in-tx reach and
//! priority checks.
use super::cmd::{one_i64, one_text, one_void, run_checked_audited, PolicyLock};
use super::{done, invalid, s, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_pg::{CommandOutcome, Rejection, StatementFailure};

/// One refusal as Go's `httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projected {
    pub status: u16,
    pub detail: String,
}

/// Go's `caErrorStatus`/`caErrorDetail` over a database failure.
pub fn project(error: &StatementFailure) -> Projected {
    let text = |hint: &Option<String>| match hint {
        Some(h) if !h.is_empty() => h.clone(),
        _ => error.message.clone(),
    };
    let code = error.sqlstate.as_deref().unwrap_or("");
    if code == "23514" {
        return Projected {
            status: 400,
            detail: text(&error.hint),
        };
    }
    let status = match code {
        "BZ080" | "BZ087" | "BZ093" | "BZ095" => 409,
        "BZ081" | "BZ086" | "BZ091" => 404,
        "BZ082" | "BZ085" | "BZ094" | "BZ097" | "BZ098" => 400,
        "BZ088" | "BZ090" | "BZ092" => 422,
        _ => {
            return Projected {
                status: 500,
                detail: "request failed".into(),
            }
        }
    };
    Projected {
        status,
        detail: text(&error.hint),
    }
}

/// The projection of a rejected command or read.
pub fn project_rejection(error: &Rejection<StatementFailure>) -> Projected {
    match error {
        Rejection::Statement(e) | Rejection::Body(e) => project(e),
        _ => Projected {
            status: 500,
            detail: "request failed".into(),
        },
    }
}

/// Whitespace outside strings removed: `json.Marshal` of a `RawMessage` compacts it.
pub fn compact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let (mut quoted, mut escaped) = (false, false);
    for c in text.chars() {
        if quoted {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                quoted = false;
            }
        } else if c == '"' {
            quoted = true;
            out.push(c);
        } else if !c.is_ascii_whitespace() {
            out.push(c);
        }
    }
    out
}

/// Test-only: restores frozen Go's missing tenant filter (feature `oracle-mutants`).
pub(crate) fn open() -> bool {
    setjoin_contracts::mutants::on("ca-policy-foreign")
}

/// Test-only: restores the missing priority floor (a scoped admin ahead of org-wide policies).
fn ahead() -> bool {
    setjoin_contracts::mutants::on("ca-priority-ahead")
}

/// Owner decision 2026-11-06 (#467, #510): whether the caller may give a policy `priority` (or
/// rebuild the `audit` snapshot's priority).
pub async fn priority_allowed(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    priority: Option<i64>,
    audit: Option<i64>,
) -> Result<bool, StatementFailure> {
    let user = admin.actor().get();
    let ahead_flag = ahead();
    let rows = factory
        .run_admin_read_contract(
            admin,
            &sql::PRIORITY_ALLOWED,
            &[&user, &priority, &audit, &ahead_flag],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

/// The refusal of an unreachable policy or scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    Allowed,
    /// The stored policy is outside the caller's reach: indistinguishable from missing.
    NotFound,
    /// The policy about to be written is scoped outside the caller's reach.
    Forbidden,
}

/// Read-side check run before a mutation to choose 404 or 403; the mutation repeats the same
/// predicate inside its own `AdminWriteTx`.
pub async fn gate(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: Option<i64>,
    audit: Option<i64>,
    scope: Option<(&str, &str)>,
    read: bool,
) -> Result<Gate, StatementFailure> {
    let user = admin.actor().get();
    let open_flag = open();
    let (scope_type, scope_target) = scope.map_or((None, None), |(a, b)| (Some(a), Some(b)));
    let contract = if read {
        &sql::POLICY_GATE_READ
    } else {
        &sql::POLICY_GATE_WRITE
    };
    let rows = factory
        .run_admin_read_contract(
            admin,
            contract,
            &[&user, &id, &audit, &scope_type, &scope_target, &open_flag],
        )
        .await?;
    match rows
        .first()
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .as_deref()
    {
        Some("ok") => Ok(Gate::Allowed),
        Some("row") => Ok(Gate::NotFound),
        Some("scope") => Ok(Gate::Forbidden),
        _ => Err(invalid()),
    }
}

/// The 404 Go's reducers give a missing policy (BZ081), reused for an unreachable one.
pub fn not_found() -> Projected {
    Projected {
        status: 404,
        detail: "no conditional_access_policy row with the given id".into(),
    }
}

/// Whether the caller reaches `user` for the policy-console reads.
pub async fn user_in_reach(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    user: i64,
) -> Result<bool, StatementFailure> {
    if open() {
        return Ok(true);
    }
    let actor_id = admin.actor().get();
    let rows = factory
        .run_admin_read_contract(admin, &sql::USER_IN_REACH, &[&actor_id, &user])
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

/// Whether the caller holds `access.policy_write` (or, for `read`, `access.policy_read`)
/// organization-wide.
pub async fn org_wide(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    read: bool,
) -> Result<bool, StatementFailure> {
    if open() {
        return Ok(true);
    }
    let user = admin.actor().get();
    let contract = if read {
        &sql::ORG_WIDE_READ
    } else {
        &sql::ORG_WIDE_WRITE
    };
    let rows = factory
        .run_admin_read_contract(admin, contract, &[&user])
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

/// `GET /admin/conditional-access/policies`: live policies by priority, tombstones too with
/// `?include_deleted=1`. Only the policies in the caller's reach are listed.
pub async fn list(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    include_deleted: bool,
) -> Result<String, StatementFailure> {
    let user = admin.actor().get();
    let open_flag = open();
    let rows = factory
        .run_admin_read_contract(
            admin,
            &sql::POLICY_LIST,
            &[&user, &open_flag, &include_deleted],
        )
        .await?;
    let bad = |_| invalid();
    let mut out = Vec::new();
    for r in &rows {
        let raw = |index: usize| -> Result<String, StatementFailure> {
            Ok(compact(&r.try_get::<_, String>(index).map_err(bad)?))
        };
        let deleted: Option<String> = r.try_get(14).map_err(bad)?;
        out.push(format!(
            "{{\"id\":{},\"priority\":{},\"name\":{},\"description\":{},\"state\":{},\"scope_type\":{},\"scope_target\":{},\"conditions\":{},\"actions\":{},\"exclude_users\":{},\"exclude_groups\":{},\"session_control\":{},\"created_at\":{},\"updated_at\":{},\"deleted_at\":{}}}",
            r.try_get::<_, i64>(0).map_err(bad)?,
            r.try_get::<_, i32>(1).map_err(bad)?,
            s(&r.try_get::<_, String>(2).map_err(bad)?),
            s(&r.try_get::<_, String>(3).map_err(bad)?),
            s(&r.try_get::<_, String>(4).map_err(bad)?),
            s(&r.try_get::<_, String>(5).map_err(bad)?),
            s(&r.try_get::<_, String>(6).map_err(bad)?),
            raw(7)?,
            raw(8)?,
            raw(9)?,
            raw(10)?,
            raw(11)?,
            s(&r.try_get::<_, String>(12).map_err(bad)?),
            s(&r.try_get::<_, String>(13).map_err(bad)?),
            deleted.map(|d| s(&d)).unwrap_or_else(|| "null".into()),
        ));
    }
    Ok(done(format!("[{}]", out.join(","))))
}

/// The create/update request after Go's decoding.
pub struct Policy<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub state: &'a str,
    pub scope_type: &'a str,
    pub scope_target: &'a str,
    pub priority: Option<i64>,
    /// Raw JSON texts (`json.RawMessage`), `None` when the field was absent.
    pub conditions: Option<&'a str>,
    pub actions: Option<&'a str>,
    pub exclude_users: Option<&'a str>,
    pub exclude_groups: Option<&'a str>,
    pub session_control: Option<&'a str>,
}

const DEFAULT_ACTIONS: &str = r#"{"action":"allow"}"#;

fn first_non_empty<'a>(value: &'a str, default: &'a str) -> &'a str {
    if value.is_empty() {
        default
    } else {
        value
    }
}

impl Policy<'_> {
    /// Go's `buildPolicyJSON`: `json.Marshal` of a map, so keys are sorted and the
    /// raw documents are compacted. `state` defaults to `off`, never `enabled`.
    fn document(&self) -> String {
        let raw = |value: Option<&str>, default: &str| compact(value.unwrap_or(default));
        let priority = self
            .priority
            .map(|p| format!("\"priority\":{p},"))
            .unwrap_or_default();
        format!(
            "{{\"actions\":{},\"conditions\":{},\"description\":{},\"exclude_groups\":{},\"exclude_users\":{},\"name\":{},{priority}\"scope_target\":{},\"scope_type\":{},\"state\":{}}}",
            raw(self.actions, DEFAULT_ACTIONS),
            raw(self.conditions, "{}"),
            s(self.description),
            raw(self.exclude_groups, "[]"),
            raw(self.exclude_users, "[]"),
            s(self.name),
            s(self.scope_target),
            s(first_non_empty(self.scope_type, "global")),
            s(first_non_empty(self.state, "off")),
        )
    }
}

/// `POST|PUT /admin/conditional-access/policies[/{id}]`: the reducer's persisted row, jsonb
/// text verbatim (no newline).
pub async fn save(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    ip: &str,
    id: Option<i64>,
    policy: &Policy<'_>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let actor_id = admin.actor().get();
    let document = policy.document();
    let actions = compact(policy.actions.unwrap_or(DEFAULT_ACTIONS));
    let session = policy.session_control.map(compact);
    let scope_type = first_non_empty(policy.scope_type, "global");
    let open_flag = open();
    let ahead_flag = ahead();
    run_checked_audited(
        factory,
        admin,
        if id.is_some() {
            "ca_policy_update"
        } else {
            "ca_policy_create"
        },
        operation,
        &format!("{id:?}:{ip}:{document}:{actions}:{session:?}"),
        id.map_or(PolicyLock::FenceOnly, PolicyLock::Row),
        &sql::POLICY_SAVE_CHECK,
        &[
            &actor_id,
            &id,
            &scope_type,
            &policy.scope_target,
            &policy.priority,
            &open_flag,
            &ahead_flag,
        ],
        &sql::POLICY_SAVE,
        &[&ip, &id, &document, &actions, &session],
        one_text,
    )
    .await
}

/// `DELETE .../policies/{id}` (soft delete).
pub async fn soft_delete(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    policy: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor_id = admin.actor().get();
    let open_flag = open();
    run_checked_audited(
        factory,
        admin,
        "ca_policy_soft_delete",
        operation,
        &policy.to_string(),
        PolicyLock::Row(policy),
        &sql::POLICY_ROW_REACH_WRITE,
        &[&actor_id, &policy, &open_flag],
        &sql::POLICY_SOFT_DELETE,
        &[&policy],
        one_void,
    )
    .await
}

pub async fn restore(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    policy: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor_id = admin.actor().get();
    let open_flag = open();
    run_checked_audited(
        factory,
        admin,
        "ca_policy_restore",
        operation,
        &policy.to_string(),
        PolicyLock::Row(policy),
        &sql::POLICY_ROW_REACH_WRITE,
        &[&actor_id, &policy, &open_flag],
        &sql::POLICY_RESTORE,
        &[&policy],
        one_void,
    )
    .await
}

/// `POST .../policies/restore-from-audit`: the rebuilt policy's new id.
pub async fn restore_from_audit(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    audit: i64,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let actor_id = admin.actor().get();
    let open_flag = open();
    let ahead_flag = ahead();
    run_checked_audited(
        factory,
        admin,
        "ca_policy_restore_from_audit",
        operation,
        &audit.to_string(),
        PolicyLock::FenceOnly,
        &sql::POLICY_RESTORE_FROM_AUDIT_CHECK,
        &[&actor_id, &audit, &open_flag, &ahead_flag],
        &sql::POLICY_RESTORE_FROM_AUDIT,
        &[&audit],
        one_i64,
    )
    .await
}

/// `POST .../policies/reorder`: priorities restepped by ten in the supplied order.
pub async fn reorder(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    ip: &str,
    ids: &Vec<i64>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor_id = admin.actor().get();
    let open_flag = open();
    let write_contract = if ahead() {
        &sql::POLICY_REORDER_MUTANT
    } else {
        &sql::POLICY_REORDER
    };
    run_checked_audited(
        factory,
        admin,
        "ca_policy_reorder",
        operation,
        &format!("{ip}:{ids:?}"),
        PolicyLock::Rows(ids),
        &sql::POLICY_REORDER_CHECK,
        &[&actor_id, ids, &open_flag],
        write_contract,
        &[&ip, ids],
        one_void,
    )
    .await
}

/// `ca_policy_impact(id, '7d', list)` as jsonb text; the reducer is STABLE and read-only.
pub async fn impact(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    policy: i64,
    list: Option<&str>,
) -> Result<String, StatementFailure> {
    let user = admin.actor().get();
    let open_flag = open();
    let rows = factory
        .run_admin_read_contract(
            admin,
            &sql::POLICY_IMPACT_7D,
            &[&policy, &list, &user, &open_flag],
        )
        .await?;
    one_text(&rows)
}

/// `ca_policy_promote`: the promoted policy's jsonb text, verbatim.
pub async fn promote(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    policy: i64,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let actor_id = admin.actor().get();
    let open_flag = open();
    run_checked_audited(
        factory,
        admin,
        "ca_policy_promote",
        operation,
        &policy.to_string(),
        PolicyLock::Row(policy),
        &sql::POLICY_ROW_REACH_WRITE,
        &[&actor_id, &policy, &open_flag],
        &sql::POLICY_PROMOTE,
        &[&policy],
        one_text,
    )
    .await
}

/// The promote dialog's blast-radius body (Go's `promotePreviewResponse`).
pub struct Preview {
    pub would_block_users: i64,
    pub would_block_admins: i64,
    pub self_locked_out: bool,
    pub blocked: Vec<(i64, String, bool)>,
    pub admins: Vec<(i64, String)>,
    pub shown: i64,
    pub total: i64,
    pub window: String,
}

impl Preview {
    pub fn zeroed(window: String) -> Self {
        Self {
            would_block_users: 0,
            would_block_admins: 0,
            self_locked_out: false,
            blocked: Vec::new(),
            admins: Vec::new(),
            shown: 0,
            total: 0,
            window,
        }
    }
    pub fn render(&self) -> String {
        let blocked: Vec<String> = self
            .blocked
            .iter()
            .map(|(id, address, admin)| {
                format!(
                    "{{\"id\":{id},\"address\":{},\"is_admin\":{admin}}}",
                    s(address)
                )
            })
            .collect();
        let admins: Vec<String> = self
            .admins
            .iter()
            .map(|(id, address)| format!("{{\"id\":{id},\"address\":{}}}", s(address)))
            .collect();
        done(format!(
            "{{\"would_block_users\":{},\"would_block_admins\":{},\"self_locked_out\":{},\"blocked_users\":[{}],\"admin_users\":[{}],\"shown\":{},\"total\":{},\"window\":{}}}",
            self.would_block_users,
            self.would_block_admins,
            self.self_locked_out,
            blocked.join(","),
            admins.join(","),
            self.shown,
            self.total,
            s(&self.window),
        ))
    }
}

/// The impact summary fields the promote handler reads.
pub fn parse_summary(text: &str) -> Option<(i64, i64, String)> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let object = value.as_object()?;
    let int = |key: &str| match object.get(key) {
        None | Some(serde_json::Value::Null) => Some(0),
        Some(v) => v.as_i64(),
    };
    let window = match object.get("window") {
        None | Some(serde_json::Value::Null) => String::new(),
        Some(serde_json::Value::String(w)) => w.clone(),
        Some(_) => return None,
    };
    Some((int("would_block")?, int("would_block_admins")?, window))
}

/// The impact list (`blocked_users`) the promote handler reads.
pub fn parse_list(text: &str) -> Option<Preview> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let object = value.as_object()?;
    let int = |key: &str| match object.get(key) {
        None | Some(serde_json::Value::Null) => Some(0),
        Some(v) => v.as_i64(),
    };
    let address = |v: &serde_json::Value| match v.get("address") {
        None | Some(serde_json::Value::Null) => Some(String::new()),
        Some(serde_json::Value::String(a)) => Some(a.clone()),
        Some(_) => None,
    };
    let id = |v: &serde_json::Value| match v.get("id") {
        None | Some(serde_json::Value::Null) => Some(0),
        Some(i) => i.as_i64(),
    };
    let mut preview = Preview::zeroed(String::new());
    for user in object
        .get("users")
        .and_then(|u| u.as_array())
        .into_iter()
        .flatten()
    {
        let admin = match user.get("is_admin") {
            None | Some(serde_json::Value::Null) => false,
            Some(serde_json::Value::Bool(b)) => *b,
            Some(_) => return None,
        };
        preview.blocked.push((id(user)?, address(user)?, admin));
    }
    for user in object
        .get("admin_users")
        .and_then(|u| u.as_array())
        .into_iter()
        .flatten()
    {
        preview.admins.push((id(user)?, address(user)?));
    }
    preview.shown = int("shown")?;
    preview.total = int("total")?;
    Some(preview)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure(code: &str, hint: Option<&str>, message: &str) -> StatementFailure {
        StatementFailure {
            sqlstate: Some(code.into()),
            hint: hint.map(Into::into),
            message: message.into(),
        }
    }

    #[test]
    fn reducer_codes_project_like_go() {
        for (code, status) in [
            ("BZ080", 409),
            ("BZ081", 404),
            ("BZ086", 404),
            ("BZ087", 409),
            ("BZ098", 400),
            ("23514", 400),
        ] {
            assert_eq!(
                project(&failure(code, Some("do this"), "msg")).status,
                status
            );
        }
        assert_eq!(
            project(&failure("BZ087", Some("do this"), "msg")).detail,
            "do this"
        );
        assert_eq!(project(&failure("BZ087", None, "msg")).detail, "msg");
        assert_eq!(project(&failure("BZ087", Some(""), "msg")).detail, "msg");
        let other = project(&failure("22003", None, "integer out of range"));
        assert_eq!(
            (other.status, other.detail.as_str()),
            (500, "request failed")
        );
    }

    #[test]
    fn document_is_go_marshal_of_the_map() {
        let policy = Policy {
            name: "n<&>",
            description: "",
            state: "",
            scope_type: "",
            scope_target: "",
            priority: Some(5),
            conditions: Some("{ \"a\": 1 }"),
            actions: None,
            exclude_users: None,
            exclude_groups: Some("[1, 2]"),
            session_control: None,
        };
        assert_eq!(
            policy.document(),
            "{\"actions\":{\"action\":\"allow\"},\"conditions\":{\"a\":1},\"description\":\"\",\"exclude_groups\":[1,2],\"exclude_users\":[],\"name\":\"n<&>\",\"priority\":5,\"scope_target\":\"\",\"scope_type\":\"global\",\"state\":\"off\"}"
        );
    }

    #[test]
    fn summary_and_list_parse_like_go() {
        assert_eq!(
            parse_summary(r#"{"window":"7d","would_block":3,"would_block_admins":1}"#),
            Some((3, 1, "7d".into()))
        );
        assert_eq!(parse_summary(r#"{"would_block":"x"}"#), None);
        let list = parse_list(
            r#"{"users":[{"id":4,"address":"a@x","is_admin":true}],"shown":1,"total":1,"admin_users":[{"id":4,"address":"a@x"}]}"#,
        )
        .unwrap();
        assert_eq!(list.blocked, vec![(4, "a@x".to_string(), true)]);
        assert_eq!(list.admins, vec![(4, "a@x".to_string())]);
        assert_eq!((list.shown, list.total), (1, 1));
    }
}
