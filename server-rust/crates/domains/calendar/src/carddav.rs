//! CardDAV's verified-user data access (#427). No request-owned identity.
use setjoin_pg::{ScopedExecutor, StatementFailure, Type};
/// Go RequireApp's independent, best-effort routine denial audit.
pub async fn blocked_audit(
    exec: &ScopedExecutor,
    user: i64,
    ip: &str,
) -> Result<(), StatementFailure> {
    exec.read(
        crate::sql::CARDDAV_BLOCKED_AUDIT.sql,
        &[(&user, Type::INT8), (&ip, Type::TEXT)],
    )
    .await?;
    Ok(())
}

pub struct Book {
    pub id: i64,
    pub mailbox: i64,
    pub name: String,
    pub description: String,
}
pub async fn books(exec: &ScopedExecutor, user: i64) -> Result<Vec<Book>, StatementFailure> {
    let rows = exec
        .read(crate::sql::CARDDAV_BOOKS.sql, &[(&user, Type::INT8)])
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
fn contact(row: &setjoin_pg::Row) -> Result<Contact, StatementFailure> {
    Ok(Contact {
        id: row.get(18),
        etag: row.get(19),
        book: row.get(20),
        row: crate::contacts::contact_row(row)?,
    })
}
pub async fn get_contact(
    exec: &ScopedExecutor,
    user: i64,
    book: i64,
    uid: &str,
) -> Result<Option<Contact>, StatementFailure> {
    let rows = exec
        .read(
            crate::sql::CARDDAV_GET_CONTACT.sql,
            &[(&book, Type::INT8), (&uid, Type::TEXT), (&user, Type::INT8)],
        )
        .await?;
    rows.first().map(contact).transpose()
}

pub async fn book(
    exec: &ScopedExecutor,
    user: i64,
    id: i64,
) -> Result<Option<Book>, StatementFailure> {
    let rows = exec
        .read(
            crate::sql::CARDDAV_BOOK.sql,
            &[(&id, Type::INT8), (&user, Type::INT8)],
        )
        .await?;
    Ok(rows.first().map(|r| Book {
        id: r.get(0),
        mailbox: r.get(1),
        name: r.get(2),
        description: r.get(3),
    }))
}
pub async fn list_contacts(
    exec: &ScopedExecutor,
    user: i64,
    book: i64,
) -> Result<Vec<Contact>, StatementFailure> {
    let rows = exec
        .read(
            crate::sql::CARDDAV_LIST_CONTACTS.sql,
            &[(&book, Type::INT8), (&user, Type::INT8)],
        )
        .await?;
    rows.iter().map(contact).collect()
}

pub async fn search_contacts(
    exec: &ScopedExecutor,
    user: i64,
    book: i64,
    text: &str,
) -> Result<Vec<Contact>, StatementFailure> {
    let pattern = format!("%{text}%");
    let rows = exec
        .read(
            crate::sql::CARDDAV_SEARCH_CONTACTS.sql,
            &[
                (&user, Type::INT8),
                (&book, Type::INT8),
                (&text, Type::TEXT),
                (&pattern, Type::TEXT),
            ],
        )
        .await?;
    rows.iter().map(contact).collect()
}
/// Frozen Go batches on UID alone across the caller's owned books. The href's
/// collection is deliberately not a second selector (carddav.go:361–402).
pub async fn contacts_by_uids(
    exec: &ScopedExecutor,
    user: i64,
    uids: &[String],
) -> Result<Vec<Contact>, StatementFailure> {
    let uids = uids.to_vec();
    let rows = exec
        .read(
            crate::sql::CARDDAV_CONTACTS_BY_UIDS.sql,
            &[(&uids, Type::TEXT_ARRAY), (&user, Type::INT8)],
        )
        .await?;
    Ok(rows.iter().filter_map(|r| contact(r).ok()).collect())
}
pub async fn sync(
    exec: &ScopedExecutor,
    user: i64,
    book: &Book,
    since: &str,
) -> Result<Option<String>, StatementFailure> {
    use setjoin_contracts::ids::{ActorId, Generation, MailboxId};
    let scope = setjoin_pg::MailboxAuthContext::from_authenticated_session(
        ActorId::new(user).expect("verified user"),
        MailboxId::new(book.mailbox).expect("owned book"),
        Generation(1),
    );
    let rows = exec
        .read_scoped(
            &scope,
            crate::sql::CARDDAV_SYNC.sql,
            &[
                (&book.mailbox, Type::INT8),
                (&book.id, Type::INT8),
                (&since, Type::TEXT),
                (&user, Type::INT8),
            ],
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
/// One canonical reducer call, with the publishing statement rechecking the
/// verified actor's collection owner. No mailbox GUC, matching Go's Call.
pub async fn publish(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    book: i64,
    contact: i64,
    payload: &str,
    kind: Operation,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    let user = actor.user_id();
    let publisher = exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand {
        family: "F17",
        command: kind.command(),
    });
    let project = |rows: &[setjoin_pg::Row]| {
        Ok(rows
            .first()
            .map(|r| r.get(0))
            .unwrap_or_else(|| "{}".into()))
    };
    match kind {
        Operation::Create => {
            publisher
                .run_user_command(
                    ActorId::new(user).expect("verified actor"),
                    OperationId(operation),
                    crate::sql::CARDDAV_CREATE.sql,
                    &[(&user, Type::INT8), (&book, Type::INT8), (&payload, Type::TEXT)],
                    project,
                )
                .await
        }
        Operation::Update => {
            publisher
                .run_user_command(
                    ActorId::new(user).expect("verified actor"),
                    OperationId(operation),
                    crate::sql::CARDDAV_UPDATE.sql,
                    &[
                        (&user, Type::INT8),
                        (&book, Type::INT8),
                        (&contact, Type::INT8),
                        (&payload, Type::TEXT),
                    ],
                    project,
                )
                .await
        }
        Operation::Delete => {
            publisher
                .run_user_command(
                    ActorId::new(user).expect("verified actor"),
                    OperationId(operation),
                    crate::sql::CARDDAV_DELETE.sql,
                    &[(&user, Type::INT8), (&book, Type::INT8), (&contact, Type::INT8)],
                    project,
                )
                .await
        }
    }
}

/// Org-wide ADR-004 directory view, reached only through the verified user's
/// primary mailbox. The enabled-only manager join intentionally mirrors Go
/// gal.go:98 except for its hidden-manager disclosure: owner-approved security fix 2026-11-05
/// (#427/#512), the manager's name is shown only when the manager is itself visible to the caller.
pub async fn gal_users(
    exec: &ScopedExecutor,
    user: i64,
    id: Option<i64>,
    text: &str,
    limit: Option<i64>,
) -> Result<Vec<String>, StatementFailure> {
    let pattern = format!("%{text}%");
    let sql = if setjoin_contracts::mutants::on("gal-manager-disclosed") {
        crate::sql::CARDDAV_GAL_USERS_MUTANT.sql
    } else {
        crate::sql::CARDDAV_GAL_USERS.sql
    };
    let rows = exec
        .read(
            sql,
            &[
                (&user, Type::INT8),
                (&id, Type::INT8),
                (&text, Type::TEXT),
                (&pattern, Type::TEXT),
                (&limit, Type::INT8),
            ],
        )
        .await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}
/// Go's best-effort disclosure journal: no business write is acknowledged by
/// the read response. The canonical definer re-filters every member id.
pub async fn gal_record(
    exec: &ScopedExecutor,
    user: i64,
    ids: &[i64],
) -> Result<(), StatementFailure> {
    if ids.is_empty() {
        return Ok(());
    }
    let ids = ids.to_vec();
    exec.read(
        crate::sql::CARDDAV_GAL_RECORD.sql,
        &[(&user, Type::INT8), (&ids, Type::INT8_ARRAY)],
    )
    .await?;
    Ok(())
}
pub async fn gal_sync(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    micros: i64,
    count: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    use setjoin_contracts::ids::{ActorId, OperationId};
    let user = actor.user_id();
    exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand{family:"F17",command:"carddav-gal-sync"}).run_user_command(ActorId::new(user).expect("verified user"),OperationId(operation),crate::sql::CARDDAV_GAL_SYNC.sql,&[(&user,Type::INT8),(&micros,Type::INT8),(&count,Type::INT8)],|rows|Ok(rows.first().map(|r|r.get(0)).unwrap_or_default())).await
}

pub async fn primary_mailbox(
    exec: &ScopedExecutor,
    user: i64,
) -> Result<Option<i64>, StatementFailure> {
    let rows = exec
        .read(crate::sql::CARDDAV_PRIMARY_MAILBOX.sql, &[(&user, Type::INT8)])
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
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    operation: setjoin_contracts::ids::OperationId,
    kind: OutcomeKind,
) -> Result<bool, StatementFailure> {
    use setjoin_contracts::ids::ActorId;
    let invalid = || StatementFailure {
        sqlstate: None,
        hint: None,
        message: "CardDAV outcome authority unavailable".into(),
    };
    let user = actor.user_id();
    let op = setjoin_pg::operation_hex(operation);
    let command = kind.command();
    match exec.run_user_command(ActorId::new(user).map_err(|_|invalid())?,operation,
        crate::sql::DAV_LOOKUP_OPERATION.sql,
        &[(&user,Type::INT8),(&op,Type::TEXT),(&command,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await {
        setjoin_pg::CommandOutcome::Committed(found)=>Ok(found),_=>Err(invalid()),
    }
}
