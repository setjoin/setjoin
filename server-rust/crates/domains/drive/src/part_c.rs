//! #276 sharing/ACL, lock, watch and as-of reducer boundary. Reducers decide;
//! the verified actor is the only identity ever bound.
use super::*;

/// One bound statement parameter list; `$1` mailbox, `$2` actor and `$3`
/// operation are supplied by the receipted-command framework for writes.
pub type Params<'a> = &'a [Param<'a>];

fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid Drive result".into(),
    }
}

/// A scoped read returning one text value (`NULL` is `None`).
pub async fn read_text(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    sql: &str,
    params: Params<'_>,
) -> Result<Option<String>, StatementFailure> {
    let rows = exec.read_scoped(&session(actor), sql, params).await?;
    rows.first()
        .map(|r| r.try_get(0).map_err(|_| invalid()))
        .transpose()
        .map(Option::flatten)
}

/// Run `sql` (a `SELECT` over `$1..$3` plus caller parameters from `$4`) as one
/// receipted command; the first column of the first row is the reply text.
pub async fn write_text(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    command: &'static str,
    digest_source: &str,
    sql: &str,
    params: Params<'_>,
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    let auth = session(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(digest_source.as_bytes()).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(
        exec,
        ReceiptCommand {
            family: "F14",
            command,
        },
        &envelope,
        &auth,
        Instant::now() + Duration::from_secs(30),
        sql,
        params,
        |rows| match rows.first() {
            Some(row) => row.try_get::<_, Option<String>>(0).map_err(|_| invalid()),
            None => Err(StatementFailure {
                sqlstate: Some("42501".into()),
                hint: None,
                message: "authority changed".into(),
            }),
        },
    )
    .await
}

/// Go's per-user ACL mutation budget, committed separately from the mutation.
pub async fn acl_rate(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    write_text(exec,actor,"drive_acl_mutation_rate","acl-rate","SELECT rate_limit_check('drive:acl-mutation:'||$2::text,30,1,5)::text WHERE $2::bigint>0 AND $3::text IS NOT NULL",&[],operation).await
}

pub const NODE_DETAIL: &str = "SELECT drive_acl_node_detail($1,$2)::text";
pub const GRANT_PREVIEW: &str = "SELECT drive_acl_grant_preview($1,$2,$3,$4,$5,NULL::text[],$6,$7::text::timestamptz,$8::text::timestamptz,$9::bigint::int,$10)::text";
pub const GRANT: &str = "SELECT drive_acl_grant($2,$4,$5,$6,$7,NULL::text[],$8,$9::text::timestamptz,$10::text::timestamptz,$11::bigint::int,$12,$13,$14)::text WHERE $2::bigint>0 AND $3::text IS NOT NULL";
pub const REVOKE: &str =
    "SELECT drive_acl_revoke($2,$4,$5,$6)::text WHERE $2::bigint>0 AND $3::text IS NOT NULL";
pub const INHERITANCE_PREVIEW: &str = "SELECT drive_acl_inheritance_preview($1,$2,$3)::text";
pub const INHERITANCE_SET: &str = "SELECT drive_acl_inheritance_set($2,$4,$5,$6)::text WHERE $2::bigint>0 AND $3::text IS NOT NULL";
pub const QUICK_VIEW: &str = "SELECT drive_acl_quick_view($1,$2,$3::bigint::int)::text";
pub const REQUEST_PREVIEW: &str = "SELECT drive_access_request_preview($1,$2,$3,$4,$5,$6,$7::bigint::int,$8::bigint::int,$9,$10,$11)::text";
pub const REQUEST_CREATE: &str = "SELECT drive_access_request($2,$4,$5,$6,$7,$8,$9::bigint::int,$10::bigint::int,$11,$12,$13,$14)::text WHERE $2::bigint>0 AND $3::text IS NOT NULL";
pub const LOCK_LIST: &str = "SELECT drive_lock_list($1,$2)::text";
pub const LOCK_PUT: &str = "SELECT drive_file_lock($2,$4,$5,$6,$7,$8,$9::bigint::int)::text WHERE $2::bigint>0 AND $3::text IS NOT NULL";
pub const LOCK_DELETE: &str =
    "SELECT 'null'::text,drive_file_unlock($2,$4,$5) WHERE $2::bigint>0 AND $3::text IS NOT NULL";
pub const WATCH_PUT: &str =
    "SELECT 'null'::text,drive_watch_set($2,$4,$5) WHERE $2::bigint>0 AND $3::text IS NOT NULL";
pub const WATCH_DELETE: &str =
    "SELECT 'null'::text,drive_watch_remove($2,$4) WHERE $2::bigint>0 AND $3::text IS NOT NULL";
pub const FOLDER_ADMIN_GRANT: &str = "SELECT 'null'::text,drive_folder_admin_grant($2,$4,$5) WHERE $2::bigint>0 AND $3::text IS NOT NULL";
pub const FOLDER_ADMIN_REVOKE: &str = "SELECT 'null'::text,drive_folder_admin_revoke($2,$4,$5) WHERE $2::bigint>0 AND $3::text IS NOT NULL";
pub const AS_OF: &str = "SELECT drive_space_as_of($1,$2,$3::text::timestamptz)::text";

/// Subject candidates for the ACL picker (Go's inline read, one statement).
pub async fn subjects(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    node: i64,
    q: &str,
    groups: bool,
) -> Result<Vec<[String; 4]>, StatementFailure> {
    let rows = exec
        .read_scoped(
            &session(actor),
            r#"SELECT kind,id::text,label,secondary FROM (
              WITH target AS (
                SELECT u.domain_id FROM drive_nodes n JOIN drive_spaces s ON s.id=n.space_id
                JOIN users u ON u.id=s.owner_user_id
                WHERE n.id=$2 AND drive_runtime_has_node_capability($1,n.id,'manage_acl')
              ), candidates AS (
                SELECT 'user'::text kind,u.id,COALESCE(NULLIF(u.display_name,''),u.email) label,u.email secondary
                FROM users u,target t WHERE u.domain_id=t.domain_id AND u.enabled AND u.id<>$1
                  AND (strpos(lower(COALESCE(u.display_name,'')),lower($3))>0
                    OR strpos(lower(u.email),lower($3))>0)
                UNION ALL
                SELECT 'group',g.id,g.name,'' FROM directory_groups g,target t
                WHERE $4 AND g.domain_id=t.domain_id AND g.state='active'
                  AND g.visibility<>'hidden' AND strpos(lower(g.name),lower($3))>0
              )
              SELECT kind,id,label,secondary FROM candidates ORDER BY label,id LIMIT 50) x
              ORDER BY label,id"#,
            &[
                (&actor.user_id(), Type::INT8),
                (&node, Type::INT8),
                (&q, Type::TEXT),
                (&groups, Type::BOOL),
            ],
        )
        .await?;
    rows.iter()
        .map(|r| {
            Ok([
                r.try_get(0).map_err(|_| invalid())?,
                r.try_get(1).map_err(|_| invalid())?,
                r.try_get(2).map_err(|_| invalid())?,
                r.try_get::<_, Option<String>>(3)
                    .map_err(|_| invalid())?
                    .unwrap_or_default(),
            ])
        })
        .collect()
}

/// Folder-admin roster as Go's `[{userId,displayName,grantedBy,grantedAt}]`
/// array text, or `None` when the caller lacks `manage_acl` on the node.
pub async fn folder_admins(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    node: i64,
) -> Result<Option<Vec<(i64, String, i64, String)>>, StatementFailure> {
    let rows = exec
        .read_scoped(
            &session(actor),
            r#"SELECT c.can,fa.user_id,fa.display_name,fa.granted_by,fa.granted_at
                 FROM (SELECT EXISTS(SELECT 1 FROM drive_nodes n WHERE n.id=$2 AND drive_runtime_has_node_capability($1,n.id,'manage_acl')) can) c
                 LEFT JOIN LATERAL (
                   SELECT x.user_id,u.display_name,x.granted_by,
                          to_char(x.granted_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"') granted_at,x.granted_at ts
                     FROM drive_folder_admins x JOIN users u ON u.id=x.user_id
                    WHERE x.node_id=$2 AND c.can) fa ON true
                ORDER BY fa.ts"#,
            &[(&actor.user_id(), Type::INT8), (&node, Type::INT8)],
        )
        .await?;
    let can: bool = rows
        .first()
        .map(|r| r.try_get(0).map_err(|_| invalid()))
        .transpose()?
        .unwrap_or(false);
    if !can {
        return Ok(None);
    }
    let mut out = Vec::new();
    for r in &rows {
        let Some(user) = r.try_get::<_, Option<i64>>(1).map_err(|_| invalid())? else {
            continue;
        };
        out.push((
            user,
            r.try_get(2).map_err(|_| invalid())?,
            r.try_get(3).map_err(|_| invalid())?,
            r.try_get(4).map_err(|_| invalid())?,
        ));
    }
    Ok(Some(out))
}

/// The caller's own watches, newest first.
pub async fn watches(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<Vec<(i64, String, String, Option<Vec<String>>)>, StatementFailure> {
    let rows = exec
        .read_scoped(
            &session(actor),
            "SELECT w.node_id,n.name,n.kind,w.ops FROM drive_watches w JOIN drive_nodes n ON n.id=w.node_id WHERE w.user_id=$1 ORDER BY w.created_at DESC",
            &[(&actor.user_id(), Type::INT8)],
        )
        .await?;
    rows.iter()
        .map(|r| {
            Ok((
                r.try_get(0).map_err(|_| invalid())?,
                r.try_get(1).map_err(|_| invalid())?,
                r.try_get(2).map_err(|_| invalid())?,
                r.try_get(3).map_err(|_| invalid())?,
            ))
        })
        .collect()
}
