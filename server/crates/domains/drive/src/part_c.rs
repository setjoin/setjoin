//! #276 sharing/ACL, lock, watch and as-of reducer boundary. Reducers decide;
//! the verified `UserPrincipal` is the only identity ever bound.
use super::*;

fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid Drive result".into(),
    }
}

/// A user-scoped read returning one text value (`NULL` is `None`).
/// Binds `$1` exclusively from `user.user().get()`; caller supplies `$2..$N`.
pub async fn read_text(
    factory: &TxFactory,
    user: &UserPrincipal,
    contract: &'static SqlContract,
    rest_values: &[&(dyn ToSql + Sync)],
) -> Result<Option<String>, StatementFailure> {
    let actor = user.user().get();
    let mut values: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(rest_values.len() + 1);
    values.push(&actor);
    values.extend_from_slice(rest_values);
    let rows = factory
        .run_user_read_contract(user, contract, &values)
        .await?;
    rows.first()
        .map(|r| r.try_get(0).map_err(|_| invalid()))
        .transpose()
        .map(Option::flatten)
}

/// Run a text-returning `SqlContract` as one receipted F14 command.
/// Binds `$1` exclusively from `user.user().get()`; caller supplies `$2..$N`.
#[allow(clippy::too_many_arguments)]
pub async fn write_text(
    factory: &TxFactory,
    user: &UserPrincipal,
    command: &'static str,
    digest_source: &str,
    contract: &'static SqlContract,
    rest_values: &[&(dyn ToSql + Sync)],
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    let actor = user.user().get();
    let mut values: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(rest_values.len() + 1);
    values.push(&actor);
    values.extend_from_slice(rest_values);
    let env = user_envelope(
        user.user(),
        user.generation(),
        operation,
        digest_source.as_bytes(),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            contract,
            &values,
            Some(ReceiptCommand {
                family: "F14",
                command,
            }),
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

/// Run a void-returning `SqlContract` as one receipted F14 command.
/// Binds `$1` exclusively from `user.user().get()`; caller supplies `$2..$N`.
#[allow(clippy::too_many_arguments)]
pub async fn write_void(
    factory: &TxFactory,
    user: &UserPrincipal,
    command: &'static str,
    digest_source: &str,
    contract: &'static SqlContract,
    rest_values: &[&(dyn ToSql + Sync)],
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    let actor = user.user().get();
    let mut values: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(rest_values.len() + 1);
    values.push(&actor);
    values.extend_from_slice(rest_values);
    let env = user_envelope(
        user.user(),
        user.generation(),
        operation,
        digest_source.as_bytes(),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            contract,
            &values,
            Some(ReceiptCommand {
                family: "F14",
                command,
            }),
            |rows| {
                if rows.is_empty() {
                    return Err(StatementFailure {
                        sqlstate: Some("42501".into()),
                        hint: None,
                        message: "authority changed".into(),
                    });
                }
                Ok(None)
            },
        )
        .await
}

/// Go's per-user ACL mutation budget, committed separately from the mutation.
pub async fn acl_rate(
    factory: &TxFactory,
    user: &UserPrincipal,
    operation: [u8; 16],
) -> CommandOutcome<Option<String>, StatementFailure> {
    write_text(
        factory,
        user,
        "drive_acl_mutation_rate",
        "acl-rate",
        &sql::ACL_RATE,
        &[],
        operation,
    )
    .await
}

/// Parse rows returned by [`sql::ACL_SUBJECTS`].
pub fn parse_subjects(rows: &[Row]) -> Result<Vec<[String; 4]>, StatementFailure> {
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

/// Parse rows returned by [`sql::FOLDER_ADMINS`].
pub fn parse_folder_admins(
    rows: &[Row],
) -> Result<Option<Vec<(i64, String, i64, String)>>, StatementFailure> {
    let can: bool = rows
        .first()
        .map(|r| r.try_get(0).map_err(|_| invalid()))
        .transpose()?
        .unwrap_or(false);
    if !can {
        return Ok(None);
    }
    let mut out = Vec::new();
    for r in rows {
        let Some(user_id) = r.try_get::<_, Option<i64>>(1).map_err(|_| invalid())? else {
            continue;
        };
        out.push((
            user_id,
            r.try_get(2).map_err(|_| invalid())?,
            r.try_get(3).map_err(|_| invalid())?,
            r.try_get(4).map_err(|_| invalid())?,
        ));
    }
    Ok(Some(out))
}

/// Subject candidates for the ACL picker (Go's inline read, one statement).
pub async fn subjects(
    factory: &TxFactory,
    user: &UserPrincipal,
    node: i64,
    q: &str,
    groups: bool,
) -> Result<Vec<[String; 4]>, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::ACL_SUBJECTS, &[&actor, &node, &q, &groups])
        .await?;
    parse_subjects(&rows)
}

/// Folder-admin roster as Go's `[{userId,displayName,grantedBy,grantedAt}]`
/// array text, or `None` when the caller lacks `manage_acl` on the node.
pub async fn folder_admins(
    factory: &TxFactory,
    user: &UserPrincipal,
    node: i64,
) -> Result<Option<Vec<(i64, String, i64, String)>>, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::FOLDER_ADMINS, &[&actor, &node])
        .await?;
    parse_folder_admins(&rows)
}

/// The caller's own watches, newest first.
pub async fn watches(
    factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<Vec<(i64, String, String, Option<Vec<String>>)>, StatementFailure> {
    let actor = user.user().get();
    let rows = factory
        .run_user_read_contract(user, &sql::WATCHES_LIST, &[&actor])
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
