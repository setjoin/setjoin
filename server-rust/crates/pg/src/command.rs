//! One-statement commands under the authenticated mailbox authority.
use crate::{
    CommandOutcome, MailboxAuthContext, Param, Row, ScopedExecutor, ScopedTx, StatementFailure,
    Type,
};
use setjoin_contracts::{command::CommandEnvelope, ids::OperationId};
use std::time::Instant;

/// The operation ID representation used in durable audit receipts.
pub fn operation_hex(operation: OperationId) -> String {
    operation
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Whether the operation's transactional receipt exists under current authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationLookup {
    Committed,
    Absent,
}

fn operation_lock(auth: &MailboxAuthContext, operation: &str) -> String {
    format!(
        "setjoin-command:{}:{}:{operation}",
        auth.mailbox_optional().map_or(0, |m| m.get()),
        auth.actor().get()
    )
}

/// Read a family's durable transaction receipt under the current mailbox scope.
///
/// The family's `SELECT` must return exactly one boolean and constrain the
/// receipt by the authenticated mailbox (`$1`), as well as any other access
/// predicates it requires. `$2` is the authenticated actor and `$3` the
/// operation ID; `params` starts at `$4`. The receipt must have been written
/// in the command transaction. A transaction-scoped operation lock makes the
/// lookup wait for any in-flight writer before taking a READ COMMITTED
/// snapshot; a timeout or failed read stays an error, not `Absent`.
pub async fn lookup_operation(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    operation: OperationId,
    sql: &str,
    params: &[Param<'_>],
) -> Result<OperationLookup, StatementFailure> {
    let mailbox = auth.mailbox_optional().map_or(0, |m| m.get());
    let actor = auth.actor().get();
    let operation = operation_hex(operation);
    let mut bindings: Vec<Param<'_>> = vec![
        (&mailbox, Type::INT8),
        (&actor, Type::INT8),
        (&operation, Type::TEXT),
    ];
    bindings.extend(params.iter().map(|(value, ty)| (*value, ty.clone())));
    let lock = operation_lock(auth, &operation);
    let rows = exec
        .read_scoped_with_lock(auth, sql, &bindings, Some(&lock))
        .await?;
    match rows.as_slice() {
        [row] if row.len() == 1 => match row.try_get::<_, bool>(0) {
            Ok(true) => Ok(OperationLookup::Committed),
            Ok(false) => Ok(OperationLookup::Absent),
            Err(_) => Err(invalid_lookup()),
        },
        _ => Err(invalid_lookup()),
    }
}

fn invalid_lookup() -> StatementFailure {
    StatementFailure {
        hint: None,
        sqlstate: None,
        message: "operation lookup must return one boolean".into(),
    }
}

/// Run one reducer call or single-statement command in a scoped transaction.
///
/// The first three SQL parameters are supplied by the helper: authenticated
/// mailbox (`$1`), authenticated actor (`$2`), and operation ID (`$3`, text).
/// `params` starts at `$4`. The command statement must include all required
/// data, audit and notification effects, or call a reducer that does so; the
/// helper never publishes notifications or writes audits after commit. The
/// decoder runs before commit, so an invalid result rolls the whole command
/// back. Only an acknowledged commit returns `Committed`. Operation IDs must
/// be unique per attempt; never blindly replay an unknown command.
pub async fn run_command<C, T, D>(
    exec: &ScopedExecutor,
    envelope: &CommandEnvelope<C>,
    auth: &MailboxAuthContext,
    deadline: Instant,
    sql: &str,
    params: &[Param<'_>],
    decode: D,
) -> CommandOutcome<T, StatementFailure>
where
    D: FnOnce(&[Row]) -> Result<T, StatementFailure>,
{
    let mailbox = auth.mailbox_optional().map_or(0, |m| m.get());
    let actor = auth.actor().get();
    let operation = operation_hex(envelope.operation);
    let mut bindings: Vec<Param<'_>> = vec![
        (&mailbox, Type::INT8),
        (&actor, Type::INT8),
        (&operation, Type::TEXT),
    ];
    bindings.extend(params.iter().map(|(value, ty)| (*value, ty.clone())));
    let lock = operation_lock(auth, &operation);
    exec.run_with_lock(
        envelope,
        auth,
        deadline,
        Some(&lock),
        async move |tx: &mut ScopedTx| {
            let rows = tx.query(sql, &bindings).await?;
            decode(&rows)
        },
    )
    .await
}

/// A receipted command whose admission depends on a row count (a per-mailbox cap).
/// In one transaction: lock the mailbox row (`FOR UPDATE`, so competing capped
/// commands on any replica serialize), count with `count_sql` (only `$1` = mailbox),
/// and either report the cap (`at_cap`, nothing written) or run `sql` and decode it.
/// Each statement takes its own snapshot, so the count sees every committed row.
/// The receipt is written in both outcomes.
#[allow(clippy::too_many_arguments)]
pub async fn run_receipted_command_capped<C, T, D>(
    exec: &ScopedExecutor,
    command: ReceiptCommand,
    envelope: &CommandEnvelope<C>,
    auth: &MailboxAuthContext,
    deadline: Instant,
    count_sql: &str,
    cap: i64,
    sql: &str,
    params: &[Param<'_>],
    decode: D,
    at_cap: impl FnOnce() -> T,
) -> CommandOutcome<T, StatementFailure>
where
    D: FnOnce(&[Row]) -> Result<T, StatementFailure>,
{
    let mailbox = auth.mailbox_optional().map_or(0, |m| m.get());
    let actor = auth.actor().get();
    let operation = operation_hex(envelope.operation);
    let mut bindings: Vec<Param<'_>> = vec![
        (&mailbox, Type::INT8),
        (&actor, Type::INT8),
        (&operation, Type::TEXT),
    ];
    bindings.extend(params.iter().map(|(value, ty)| (*value, ty.clone())));
    let lock = operation_lock(auth, &operation);
    let operation = &operation;
    exec.run_with_lock(
        envelope,
        auth,
        deadline,
        Some(&lock),
        async move |tx: &mut ScopedTx| {
            tx.query(
                "SELECT id FROM public.mailboxes WHERE id=$1 FOR UPDATE",
                &bindings[..1],
            )
            .await?;
            let counted = tx.query(count_sql, &bindings[..1]).await?;
            let n: i64 = counted
                .first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(|| StatementFailure {
                    sqlstate: None,
                    hint: None,
                    message: "cap count result".into(),
                })?;
            let value = if n >= cap {
                at_cap()
            } else {
                decode(&tx.query(sql, &bindings).await?)?
            };
            tx.execute(
                "INSERT INTO public.rust_operation_receipts (operation_id, family, command) \
                 VALUES ($1::text::uuid, $2, $3)",
                &[
                    (operation, Type::TEXT),
                    (&command.family, Type::TEXT),
                    (&command.command, Type::TEXT),
                ],
            )
            .await?;
            Ok(value)
        },
    )
    .await
}

/// Stable catalog names for a Rust-owned receipt. These are code constants,
/// never request fields. The receipt holds no tenant identity or result data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptCommand {
    pub family: &'static str,
    pub command: &'static str,
}

/// Run a command and persist its commit receipt in the same transaction.
/// Family SQL and result decoding must both succeed before the receipt is
/// inserted. Receipt failure rolls back the command; an unacknowledged COMMIT
/// remains Unknown. Never replay an operation ID, even for a no-op command.
/// The legacy pilot uses `run_command` with its scoped audit-row receipt.
#[allow(clippy::too_many_arguments)]
pub async fn run_receipted_command<C, T, D>(
    exec: &ScopedExecutor,
    command: ReceiptCommand,
    envelope: &CommandEnvelope<C>,
    auth: &MailboxAuthContext,
    deadline: Instant,
    sql: &str,
    params: &[Param<'_>],
    decode: D,
) -> CommandOutcome<T, StatementFailure>
where
    D: FnOnce(&[Row]) -> Result<T, StatementFailure>,
{
    let mailbox = auth.mailbox_optional().map_or(0, |m| m.get());
    let actor = auth.actor().get();
    let operation = operation_hex(envelope.operation);
    let mut bindings: Vec<Param<'_>> = vec![
        (&mailbox, Type::INT8),
        (&actor, Type::INT8),
        (&operation, Type::TEXT),
    ];
    bindings.extend(params.iter().map(|(value, ty)| (*value, ty.clone())));
    let lock = operation_lock(auth, &operation);
    let operation = &operation;
    exec.run_with_lock(
        envelope,
        auth,
        deadline,
        Some(&lock),
        async move |tx: &mut ScopedTx| {
            let rows = tx.query(sql, &bindings).await?;
            let value = decode(&rows)?;
            tx.execute(
                "INSERT INTO public.rust_operation_receipts (operation_id, family, command) \
                 VALUES ($1::text::uuid, $2, $3)",
                &[
                    (&operation, Type::TEXT),
                    (&command.family, Type::TEXT),
                    (&command.command, Type::TEXT),
                ],
            )
            .await?;
            Ok(value)
        },
    )
    .await
}

/// Resolve an Unknown command by its opaque operation ID and static command
/// names. This exposes only committed/absent system metadata, never user data.
/// The caller must retain the operation ID under its authenticated context.
/// Waits for the writer; timeout is an error, never a claim of absence.
pub async fn lookup_command(
    exec: &ScopedExecutor,
    auth: &MailboxAuthContext,
    operation: OperationId,
    command: ReceiptCommand,
) -> Result<OperationLookup, StatementFailure> {
    lookup_operation(
        exec,
        auth,
        operation,
        "SELECT EXISTS(SELECT 1 FROM public.rust_operation_receipts \
         WHERE operation_id = $3::text::uuid AND family = $4 AND command = $5) \
         WHERE $1::bigint > 0 AND $2::bigint > 0",
        &[
            (&command.family, Type::TEXT),
            (&command.command, Type::TEXT),
        ],
    )
    .await
}

/// Receipted transaction with a peripheral effect between authorization/lock
/// acquisition and the family's atomic reducer. The effect must be idempotent
/// (e.g. content-addressed copy). Unknown retains bytes and requires lookup.
#[allow(clippy::too_many_arguments)]
pub async fn run_receipted_effect<C, T, F>(
    exec: &ScopedExecutor,
    command: ReceiptCommand,
    envelope: &CommandEnvelope<C>,
    auth: &MailboxAuthContext,
    deadline: Instant,
    body: F,
) -> CommandOutcome<T, StatementFailure>
where
    F: AsyncFnOnce(&mut ScopedTx) -> Result<T, StatementFailure>,
{
    let operation = operation_hex(envelope.operation);
    let lock = operation_lock(auth, &operation);
    exec.run_with_lock(envelope,auth,deadline,Some(&lock),async move |tx:&mut ScopedTx|{
  let value=body(tx).await?;
  tx.execute("INSERT INTO public.rust_operation_receipts(operation_id,family,command) VALUES($1::text::uuid,$2,$3)",
   &[(&operation,Type::TEXT),(&command.family,Type::TEXT),(&command.command,Type::TEXT)]).await?;
  Ok(value)
 }).await
}
