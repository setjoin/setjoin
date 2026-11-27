//! CardDAV's verified-user data access (#427). No request-owned identity.
use crate::{actor_scoped_op, command, deadline, user_envelope};
use setjoin_authz::principals::{ReadCapability, TxFactory, UserPrincipal};
use setjoin_contracts::ids::OperationId;
use setjoin_pg::{CommandOutcome, OperationLookup, Row, StatementFailure};

/// Go RequireApp's independent, best-effort routine denial audit.
pub async fn blocked_audit(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    ip: &str,
) -> Result<(), StatementFailure> {
    let uid = user.user().get();
    let tag = format!("blocked:{uid}:{ip}");
    let mut op_bytes = [0u8; 16];
    op_bytes.copy_from_slice(&<sha2::Sha256 as sha2::Digest>::digest(tag.as_bytes())[..16]);
    op_bytes[0] |= 1;
    let env = user_envelope(user, OperationId(op_bytes), &tag);
    match tx_factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &crate::sql::CARDDAV_BLOCKED_AUDIT,
            &[&uid, &ip],
            None,
            |_| Ok(()),
        )
        .await
    {
        CommandOutcome::Committed(()) => Ok(()),
        CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(e))
        | CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(e)) => Err(e),
        _ => Err(crate::invalid()),
    }
}

pub struct Book {
    pub id: i64,
    pub mailbox: i64,
    pub name: String,
    pub description: String,
}

pub async fn books(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<Vec<Book>, StatementFailure> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &crate::sql::CARDDAV_BOOKS, &[&uid])
        .await?;
    Ok(rows
        .iter()
        .map(|r| Book {
            id: r.get(0),
            mailbox: r.get(1),
            name: r.get(2),
            description: r.get(3),
        })
        .collect())
}

pub struct Contact {
    pub id: i64,
    pub book: i64,
    pub etag: String,
    pub row: crate::contacts::ContactRow,
}

fn contact(row: &Row) -> Result<Contact, StatementFailure> {
    Ok(Contact {
        id: row.get(18),
        etag: row.get(19),
        book: row.get(20),
        row: crate::contacts::contact_row(row)?,
    })
}

pub async fn get_contact(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    book: i64,
    uid: &str,
) -> Result<Option<Contact>, StatementFailure> {
    let user_id = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(
            user,
            &crate::sql::CARDDAV_GET_CONTACT,
            &[&book, &uid, &user_id],
        )
        .await?;
    rows.first().map(contact).transpose()
}

pub async fn book(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
) -> Result<Option<Book>, StatementFailure> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &crate::sql::CARDDAV_BOOK, &[&id, &uid])
        .await?;
    Ok(rows.first().map(|r| Book {
        id: r.get(0),
        mailbox: r.get(1),
        name: r.get(2),
        description: r.get(3),
    }))
}

pub async fn list_contacts(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    book: i64,
) -> Result<Vec<Contact>, StatementFailure> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &crate::sql::CARDDAV_LIST_CONTACTS, &[&book, &uid])
        .await?;
    rows.iter().map(contact).collect()
}

pub async fn search_contacts(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    book: i64,
    text: &str,
) -> Result<Vec<Contact>, StatementFailure> {
    let uid = user.user().get();
    let pattern = format!("%{text}%");
    let rows = tx_factory
        .run_user_read_contract(
            user,
            &crate::sql::CARDDAV_SEARCH_CONTACTS,
            &[&uid, &book, &text, &pattern],
        )
        .await?;
    rows.iter().map(contact).collect()
}

/// Frozen Go batches on UID alone across the caller's owned books. The href's
/// collection is deliberately not a second selector (carddav.go:361–402).
pub async fn contacts_by_uids(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    uids: &[String],
) -> Result<Vec<Contact>, StatementFailure> {
    let uid = user.user().get();
    let uids = uids.to_vec();
    let rows = tx_factory
        .run_user_read_contract(user, &crate::sql::CARDDAV_CONTACTS_BY_UIDS, &[&uids, &uid])
        .await?;
    Ok(rows.iter().filter_map(|r| contact(r).ok()).collect())
}

pub async fn sync(
    tx_factory: &TxFactory,
    read: &ReadCapability,
    book: &Book,
    since: &str,
) -> Result<Option<String>, StatementFailure> {
    let mb = read.mailbox().get();
    let uid = read.actor().get();
    let rows = tx_factory
        .run_mailbox_read_contract(
            read,
            &crate::sql::CARDDAV_SYNC,
            &[&mb, &book.id, &since, &uid],
        )
        .await?;
    Ok(rows.first().map(|r| r.get(0)))
}

#[derive(Clone, Copy)]
pub enum Operation {
    Create,
    Update,
    Delete,
}
impl Operation {
    fn command(self) -> &'static str {
        match self {
            Self::Create => "carddav-put-create",
            Self::Update => "carddav-put-update",
            Self::Delete => "carddav-delete",
        }
    }
}

fn remap_unknown(
    outcome: CommandOutcome<String, StatementFailure>,
    external: OperationId,
) -> CommandOutcome<String, StatementFailure> {
    match outcome {
        CommandOutcome::Unknown { .. } => CommandOutcome::Unknown {
            operation: external,
        },
        other => other,
    }
}

/// One canonical reducer call, with the publishing statement rechecking the
/// verified actor's collection owner.
pub async fn publish(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    book: i64,
    contact: i64,
    payload: &str,
    kind: Operation,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    let external = OperationId(operation);
    let scoped = actor_scoped_op(user.user(), external);
    let env = user_envelope(
        user,
        scoped,
        &format!("{}:{book}:{contact}:{payload}", kind.command()),
    );
    let project = |rows: Vec<Row>| {
        Ok(rows
            .first()
            .map(|r| r.get(0))
            .unwrap_or_else(|| "{}".into()))
    };
    let receipt = Some(command(kind.command()));
    let outcome = match kind {
        Operation::Create => {
            tx_factory
                .run_user_write_contract_pipelined(
                    user,
                    &env,
                    deadline(),
                    &crate::sql::CARDDAV_CREATE,
                    &[&uid, &book, &payload],
                    receipt,
                    project,
                )
                .await
        }
        Operation::Update => {
            tx_factory
                .run_user_write_contract_pipelined(
                    user,
                    &env,
                    deadline(),
                    &crate::sql::CARDDAV_UPDATE,
                    &[&uid, &book, &contact, &payload],
                    receipt,
                    project,
                )
                .await
        }
        Operation::Delete => {
            tx_factory
                .run_user_write_contract_pipelined(
                    user,
                    &env,
                    deadline(),
                    &crate::sql::CARDDAV_DELETE,
                    &[&uid, &book, &contact],
                    receipt,
                    project,
                )
                .await
        }
    };
    remap_unknown(outcome, external)
}

/// Org-wide ADR-004 directory view, reached only through the verified user's
/// primary mailbox. The enabled-only manager join intentionally mirrors Go
/// gal.go:98 except for its hidden-manager disclosure: owner-approved security fix 2026-11-05
/// (#427/#512), the manager's name is shown only when the manager is itself visible to the caller.
pub async fn gal_users(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    id: Option<i64>,
    text: &str,
    limit: Option<i64>,
) -> Result<Vec<String>, StatementFailure> {
    let uid = user.user().get();
    let pattern = format!("%{text}%");
    let contract = if setjoin_contracts::mutants::on("gal-manager-disclosed") {
        &crate::sql::CARDDAV_GAL_USERS_MUTANT
    } else {
        &crate::sql::CARDDAV_GAL_USERS
    };
    let rows = tx_factory
        .run_user_read_contract(user, contract, &[&uid, &id, &text, &pattern, &limit])
        .await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}

/// Go's best-effort disclosure journal: no business write is acknowledged by
/// the read response. The canonical definer re-filters every member id.
pub async fn gal_record(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    ids: &[i64],
) -> Result<(), StatementFailure> {
    if ids.is_empty() {
        return Ok(());
    }
    let uid = user.user().get();
    let ids = ids.to_vec();
    let tag = format!("gal_record:{uid}:{ids:?}");
    let mut op_bytes = [0u8; 16];
    op_bytes.copy_from_slice(&<sha2::Sha256 as sha2::Digest>::digest(tag.as_bytes())[..16]);
    op_bytes[0] |= 1;
    let env = user_envelope(user, OperationId(op_bytes), &tag);
    let _ = tx_factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &crate::sql::CARDDAV_GAL_RECORD,
            &[&uid, &ids],
            None,
            |_| Ok(()),
        )
        .await;
    Ok(())
}

pub async fn gal_sync(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    micros: i64,
    count: i64,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let uid = user.user().get();
    let external = OperationId(operation);
    let scoped = actor_scoped_op(user.user(), external);
    let env = user_envelope(user, scoped, &format!("gal_sync:{uid}:{micros}:{count}"));
    remap_unknown(
        tx_factory
            .run_user_write_contract_pipelined(
                user,
                &env,
                deadline(),
                &crate::sql::CARDDAV_GAL_SYNC,
                &[&uid, &micros, &count],
                Some(command("carddav-gal-sync")),
                |rows| Ok(rows.first().map(|r| r.get(0)).unwrap_or_default()),
            )
            .await,
        external,
    )
}

pub async fn primary_mailbox(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<Option<i64>, StatementFailure> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &crate::sql::CARDDAV_PRIMARY_MAILBOX, &[&uid])
        .await?;
    Ok(rows.first().map(|r| r.get(0)))
}

/// Code-owned recovery categories. A receipt proves transaction commitment,
/// never per-item success or continuing access to a resource.
#[derive(Clone, Copy)]
pub enum OutcomeKind {
    Create,
    Update,
    Delete,
    GalSync,
}
impl OutcomeKind {
    fn command(self) -> &'static str {
        match self {
            Self::Create => "carddav-put-create",
            Self::Update => "carddav-put-update",
            Self::Delete => "carddav-delete",
            Self::GalSync => "carddav-gal-sync",
        }
    }
}

/// Fresh verified-user lookup takes the same actor/operation lock as publication
/// and only observes that actor's hashed receipt under current identity admission.
pub async fn lookup_operation(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    operation: OperationId,
    kind: OutcomeKind,
) -> Result<bool, StatementFailure> {
    let scoped = actor_scoped_op(user.user(), operation);
    match tx_factory
        .lookup_user_command(user, scoped, command(kind.command()))
        .await?
    {
        OperationLookup::Committed => Ok(true),
        _ => Ok(false),
    }
}
