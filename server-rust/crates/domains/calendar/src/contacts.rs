//! F17 slice `contacts` (#297): the statements of the contacts CSV/vCard import
//! and export, one function per frozen-Go statement.
use crate::{deadline, invalid, user_envelope};
use setjoin_authz::principals::{TxFactory, UserPrincipal};
use setjoin_contracts::ids::OperationId;
use setjoin_pg::{CommandOutcome, Row, StatementFailure};

/// The mailbox that owns `book` and belongs to `user` (Go's `ownedMailboxForBook`).
pub async fn owned_mailbox_for_book(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    book: i64,
) -> Result<Option<i64>, StatementFailure> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &crate::sql::OWNED_MAILBOX_FOR_BOOK, &[&book, &uid])
        .await?;
    match rows.first() {
        Some(row) => Ok(Some(row.try_get(0).map_err(|_| invalid())?)),
        None => Ok(None),
    }
}

/// Whether `contact` sits in an address book of a mailbox of `user`.
pub async fn owns_contact(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    contact: i64,
) -> Result<bool, StatementFailure> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &crate::sql::OWNS_CONTACT, &[&contact, &uid])
        .await?;
    Ok(!rows.is_empty())
}

/// Go's `contactStore.exists`; a failed read counts as "absent", as in Go.
pub async fn exists(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    book: i64,
    uid: &str,
    owner: i64,
) -> bool {
    tx_factory
        .run_user_read_contract(user, &crate::sql::CONTACT_EXISTS, &[&book, &uid, &owner])
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
        .unwrap_or(false)
}

/// The contacts columns an import writes, already in the stored shapes.
pub struct NewContact<'a> {
    pub uid: &'a str,
    pub display_name: &'a str,
    pub first_name: &'a str,
    pub last_name: &'a str,
    pub company: &'a str,
    pub job_title: &'a str,
    pub emails: &'a str,
    pub phones: &'a str,
    pub urls: &'a str,
    pub instant_msgs: &'a str,
    pub addresses: &'a str,
    pub notes: &'a str,
    pub birthday: Option<&'a str>,
    pub anniversary: Option<&'a str>,
}

/// Go's `contactStore.insert`, or `upsert` (`ON CONFLICT DO UPDATE`), as the
/// reducer `rust_contacts_import_write`.
pub async fn write_contact(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    owner: i64,
    book: i64,
    contact: &NewContact<'_>,
    upsert: bool,
) -> Result<i64, StatementFailure> {
    let tag = format!("write_contact:{owner}:{book}:{}:{upsert}", contact.uid);
    let mut op_bytes = [0u8; 16];
    op_bytes.copy_from_slice(&<sha2::Sha256 as sha2::Digest>::digest(tag.as_bytes())[..16]);
    op_bytes[0] |= 1;
    let env = user_envelope(user, OperationId(op_bytes), &tag);
    match tx_factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &crate::sql::WRITE_CONTACT,
            &[
                &owner,
                &book,
                &contact.uid,
                &contact.display_name,
                &contact.first_name,
                &contact.last_name,
                &contact.company,
                &contact.job_title,
                &contact.emails,
                &contact.phones,
                &contact.urls,
                &contact.instant_msgs,
                &contact.addresses,
                &contact.notes,
                &contact.birthday,
                &contact.anniversary,
                &upsert,
            ],
            None,
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get::<_, i64>(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
    {
        CommandOutcome::Committed(n) => Ok(n),
        CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(e))
        | CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(e)) => Err(e),
        _ => Err(invalid()),
    }
}

/// Go's `contactStore.remove`: one `DELETE` with the ownership join in its WHERE.
pub async fn remove_contact(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    owner: i64,
    book: i64,
    uid: &str,
) -> Result<i64, StatementFailure> {
    let tag = format!("remove_contact:{owner}:{book}:{uid}");
    let mut op_bytes = [0u8; 16];
    op_bytes.copy_from_slice(&<sha2::Sha256 as sha2::Digest>::digest(tag.as_bytes())[..16]);
    op_bytes[0] |= 1;
    let env = user_envelope(user, OperationId(op_bytes), &tag);
    match tx_factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &crate::sql::REMOVE_CONTACT,
            &[&owner, &book, &uid],
            None,
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get::<_, i64>(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
    {
        CommandOutcome::Committed(n) => Ok(n),
        CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(e))
        | CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(e)) => Err(e),
        _ => Err(invalid()),
    }
}

/// Go's `notify_contact_state(mailbox, 'contact_created', NULL)`: the state bump
/// and push fan-out of a finished import, one reducer call.
pub async fn notify_import(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    owner: i64,
) -> Result<(), StatementFailure> {
    let tag = format!("notify_import:{owner}");
    let mut op_bytes = [0u8; 16];
    op_bytes.copy_from_slice(&<sha2::Sha256 as sha2::Digest>::digest(tag.as_bytes())[..16]);
    op_bytes[0] |= 1;
    let env = user_envelope(user, OperationId(op_bytes), &tag);
    match tx_factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &crate::sql::NOTIFY_IMPORT,
            &[&owner],
            None,
            |_| Ok(()),
        )
        .await
    {
        CommandOutcome::Committed(()) => Ok(()),
        CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(e))
        | CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(e)) => Err(e),
        _ => Err(invalid()),
    }
}

/// The CSV export rows of an owned book, in Go's order.
pub async fn export_csv_rows(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    book: i64,
) -> Result<Vec<[String; 8]>, StatementFailure> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &crate::sql::EXPORT_CSV_ROWS, &[&book, &uid])
        .await?;
    rows.iter()
        .map(|row| {
            let mut out: [String; 8] = Default::default();
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = row.try_get(i).map_err(|_| invalid())?;
            }
            Ok(out)
        })
        .collect()
}

/// One contact as the vCard serializer reads it; jsonb columns stay text.
pub struct ContactRow {
    pub uid: String,
    pub display_name: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub company: Option<String>,
    pub job_title: Option<String>,
    pub department: Option<String>,
    pub emails: String,
    pub phones: String,
    pub addresses: String,
    pub urls: String,
    pub instant_msgs: String,
    pub notes: Option<String>,
    /// `YYYYMMDD`.
    pub birthday: Option<String>,
    pub anniversary: Option<String>,
    pub avatar_sha256: Option<String>,
    /// A JSON array of strings.
    pub categories: String,
    /// `YYYYMMDDTHHMMSSZ`, UTC.
    pub updated_at: String,
}

pub(crate) fn contact_row(row: &Row) -> Result<ContactRow, StatementFailure> {
    let get = |i: usize| row.try_get::<_, String>(i).map_err(|_| invalid());
    let maybe = |i: usize| row.try_get::<_, Option<String>>(i).map_err(|_| invalid());
    Ok(ContactRow {
        uid: get(0)?,
        display_name: get(1)?,
        first_name: maybe(2)?,
        last_name: maybe(3)?,
        company: maybe(4)?,
        job_title: maybe(5)?,
        department: maybe(6)?,
        emails: get(7)?,
        phones: get(8)?,
        addresses: get(9)?,
        urls: get(10)?,
        instant_msgs: get(11)?,
        notes: maybe(12)?,
        birthday: maybe(13)?,
        anniversary: maybe(14)?,
        avatar_sha256: maybe(15)?,
        categories: get(16)?,
        updated_at: get(17)?,
    })
}

/// Go's `carddav.ExportVCards` read: the user's ownership is in the statement.
pub async fn export_vcard_rows(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    book: i64,
) -> Result<Vec<ContactRow>, StatementFailure> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &crate::sql::EXPORT_VCARD_ROWS, &[&book, &uid])
        .await?;
    rows.iter().map(contact_row).collect()
}

/// Go's `carddav.ExportVCard` read; `None` is `pgx.ErrNoRows` (missing or foreign).
pub async fn export_vcard_row(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
    contact: i64,
) -> Result<Option<ContactRow>, StatementFailure> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &crate::sql::EXPORT_VCARD_ROW, &[&contact, &uid])
        .await?;
    rows.first().map(contact_row).transpose()
}
