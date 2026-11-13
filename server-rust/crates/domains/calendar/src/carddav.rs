//! CardDAV's verified-user data access (#427). No request-owned identity.
use setjoin_pg::{ScopedExecutor, StatementFailure, Type};
/// Go RequireApp's independent, best-effort routine denial audit.
pub async fn blocked_audit(
    exec: &ScopedExecutor,
    user: i64,
    ip: &str,
) -> Result<(), StatementFailure> {
    exec.read("SELECT audit_write($1,'app_blocked','app',NULL,NULL,NULL,$2::text::inet,'contacts','routine')",&[(&user,Type::INT8),(&ip,Type::TEXT)]).await?;
    Ok(())
}

pub struct Book {
    pub id: i64,
    pub mailbox: i64,
    pub name: String,
    pub description: String,
}
pub async fn books(exec: &ScopedExecutor, user: i64) -> Result<Vec<Book>, StatementFailure> {
    let rows=exec.read("SELECT ab.id,ab.mailbox_id,ab.name,coalesce(ab.description,'') FROM addressbooks ab JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE mb.user_id=$1 ORDER BY ab.name",&[(&user,Type::INT8)]).await?;
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
    let sql=format!("SELECT {},c.id,c.etag,c.addressbook_id FROM contacts c JOIN addressbooks ab ON ab.id=c.addressbook_id JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE c.addressbook_id=$1 AND c.vcard_uid=$2 AND mb.user_id=$3",crate::contacts::CONTACT_COLUMNS);
    let rows = exec
        .read(
            &sql,
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
    let rows=exec.read("SELECT ab.id,ab.mailbox_id,ab.name,coalesce(ab.description,'') FROM addressbooks ab JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE ab.id=$1 AND mb.user_id=$2",&[(&id,Type::INT8),(&user,Type::INT8)]).await?;
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
    let sql=format!("SELECT {},c.id,c.etag,c.addressbook_id FROM contacts c JOIN addressbooks ab ON ab.id=c.addressbook_id JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE c.addressbook_id=$1 AND mb.user_id=$2 ORDER BY c.display_name",crate::contacts::CONTACT_COLUMNS);
    let rows = exec
        .read(&sql, &[(&book, Type::INT8), (&user, Type::INT8)])
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
    let sql=format!("SELECT {},c.id,c.etag,c.addressbook_id FROM contacts c JOIN addressbooks ab ON ab.id=c.addressbook_id JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE mb.user_id=$1 AND ($2<=0 OR c.addressbook_id=$2) AND ($3='' OR c.display_name ILIKE $4 OR c.emails::text ILIKE $4) ORDER BY c.display_name LIMIT 1000",crate::contacts::CONTACT_COLUMNS);
    let rows = exec
        .read(
            &sql,
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
    let sql=format!("SELECT {},c.id,c.etag,c.addressbook_id FROM contacts c JOIN addressbooks ab ON ab.id=c.addressbook_id JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE c.vcard_uid=ANY($1) AND mb.user_id=$2",crate::contacts::CONTACT_COLUMNS);
    let rows = exec
        .read(&sql, &[(&uids, Type::TEXT_ARRAY), (&user, Type::INT8)])
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
    let rows=exec.read_scoped(&scope,"SELECT caldav_changes($1,'ContactCard',$2,$3)::text WHERE EXISTS(SELECT 1 FROM addressbooks ab JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE ab.id=$2 AND ab.mailbox_id=$1 AND mb.user_id=$4)",&[(&book.mailbox,Type::INT8),(&book.id,Type::INT8),(&since,Type::TEXT),(&user,Type::INT8)]).await?;
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
        Operation::Create=>publisher.run_user_command(ActorId::new(user).expect("verified actor"),OperationId(operation),"SELECT jmap_contact_set_create(ab.mailbox_id,$3::text::jsonb)::text FROM addressbooks ab JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE ab.id=$2 AND mb.user_id=$1",&[(&user,Type::INT8),(&book,Type::INT8),(&payload,Type::TEXT)],project).await,
        Operation::Update=>publisher.run_user_command(ActorId::new(user).expect("verified actor"),OperationId(operation),"SELECT jmap_contact_set_update(ab.mailbox_id,$4::text::jsonb)::text FROM addressbooks ab JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE ab.id=$2 AND mb.user_id=$1 AND $3::bigint>0",&[(&user,Type::INT8),(&book,Type::INT8),(&contact,Type::INT8),(&payload,Type::TEXT)],project).await,
        Operation::Delete=>publisher.run_user_command(ActorId::new(user).expect("verified actor"),OperationId(operation),"SELECT jmap_contact_set_destroy(ab.mailbox_id,ARRAY[$3::bigint])::text FROM addressbooks ab JOIN mailboxes mb ON mb.id=ab.mailbox_id WHERE ab.id=$2 AND mb.user_id=$1 AND $3::bigint>0",&[(&user,Type::INT8),(&book,Type::INT8),(&contact,Type::INT8)],project).await,
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
    let visible = if setjoin_contracts::mutants::on("gal-manager-disclosed") {
        ""
    } else {
        " AND EXISTS (SELECT 1 FROM directory_visible_users(caller.id) mv WHERE mv.id=mgr.id)"
    };
    let sql = format!("SELECT (to_jsonb(v)||jsonb_build_object('manager_name',mgr.display_name,'updated_micros',(extract(epoch FROM u.updated_at)*1000000)::bigint,'rev',to_char(u.updated_at AT TIME ZONE 'UTC','YYYYMMDD\"T\"HH24MISS\"Z\"')))::text FROM mailboxes caller CROSS JOIN LATERAL directory_visible_users(caller.id) v JOIN users u ON u.id=v.id LEFT JOIN users mgr ON mgr.id=u.manager_id AND mgr.enabled{visible} WHERE caller.user_id=$1 AND caller.is_primary AND ($2::bigint IS NULL OR v.id=$2) AND ($3='' OR v.display_name ILIKE $4 OR v.address_blob ILIKE $4) ORDER BY v.display_name LIMIT $5");
    let rows=exec.read(&sql,&[(&user,Type::INT8),(&id,Type::INT8),(&text,Type::TEXT),(&pattern,Type::TEXT),(&limit,Type::INT8)]).await?;
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
    exec.read("SELECT gal_visibility_record(mb.id,$2) FROM mailboxes mb WHERE mb.user_id=$1 AND mb.is_primary",&[(&user,Type::INT8),(&ids,Type::INT8_ARRAY)]).await?;
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
    exec.clone().with_user_receipt(setjoin_pg::ReceiptCommand{family:"F17",command:"carddav-gal-sync"}).run_user_command(ActorId::new(user).expect("verified user"),OperationId(operation),"SELECT gal_changes(mb.id,$2,$3)::text FROM mailboxes mb WHERE mb.user_id=$1 AND mb.is_primary",&[(&user,Type::INT8),(&micros,Type::INT8),(&count,Type::INT8)],|rows|Ok(rows.first().map(|r|r.get(0)).unwrap_or_default())).await
}

pub async fn primary_mailbox(
    exec: &ScopedExecutor,
    user: i64,
) -> Result<Option<i64>, StatementFailure> {
    let rows = exec
        .read(
            "SELECT id FROM mailboxes WHERE user_id=$1 AND is_primary",
            &[(&user, Type::INT8)],
        )
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
        "SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=substr(encode(digest($2::text || ':' || $1::text,'sha256'),'hex'),1,32)::uuid AND family='F17' AND command=$3) WHERE EXISTS(SELECT 1 FROM users u WHERE u.id=$1 AND u.enabled AND identity_transition_admission_allowed(u.id))",
        &[(&user,Type::INT8),(&op,Type::TEXT),(&command,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await {
        setjoin_pg::CommandOutcome::Committed(found)=>Ok(found),_=>Err(invalid()),
    }
}
