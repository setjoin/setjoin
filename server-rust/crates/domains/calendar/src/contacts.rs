//! F17 slice `contacts` (#297): the statements of the contacts CSV/vCard import
//! and export, one function per frozen-Go statement.
//!
//! Frozen Go runs every statement of an import as its own autocommit call on the
//! request pool with no tenant GUC (partial imports are possible by design); each
//! write here is the same single statement as one autocommit reducer call. Ownership is the
//! mailbox the gate proved belongs to the verified user, carried into every write's
//! WHERE (R3); reads carry the verified user in the same statement (R1).
use crate::invalid;
use setjoin_pg::{ScopedExecutor, StatementFailure, Type};

/// The mailbox that owns `book` and belongs to `user` (Go's `ownedMailboxForBook`).
pub async fn owned_mailbox_for_book(
    exec: &ScopedExecutor,
    book: i64,
    user: i64,
) -> Result<Option<i64>, StatementFailure> {
    let rows = exec
        .read(
            crate::sql::OWNED_MAILBOX_FOR_BOOK.sql,
            &[(&book, Type::INT8), (&user, Type::INT8)],
        )
        .await?;
    match rows.first() {
        Some(row) => Ok(Some(row.try_get(0).map_err(|_| invalid())?)),
        None => Ok(None),
    }
}

/// Whether `contact` sits in an address book of a mailbox of `user`.
pub async fn owns_contact(
    exec: &ScopedExecutor,
    contact: i64,
    user: i64,
) -> Result<bool, StatementFailure> {
    let rows = exec
        .read(
            crate::sql::OWNS_CONTACT.sql,
            &[(&contact, Type::INT8), (&user, Type::INT8)],
        )
        .await?;
    Ok(!rows.is_empty())
}

/// Go's `contactStore.exists`; a failed read counts as "absent", as in Go.
pub async fn exists(exec: &ScopedExecutor, book: i64, uid: &str, owner: i64) -> bool {
    exec.read(
        crate::sql::CONTACT_EXISTS.sql,
        &[
            (&book, Type::INT8),
            (&uid, Type::TEXT),
            (&owner, Type::INT8),
        ],
    )
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
/// reducer `rust_contacts_import_write`: one `INSERT .. SELECT .. WHERE EXISTS(owned
/// book)` on the request credential without a tenant GUC and without a receipt,
/// exactly Go's pool call. `Ok(rows)` is Go's `RowsAffected`, 0 meaning the book
/// is not owned by `owner`.
pub async fn write_contact(
    exec: &ScopedExecutor,
    owner: i64,
    book: i64,
    contact: &NewContact<'_>,
    upsert: bool,
) -> Result<i64, StatementFailure> {
    let rows = exec
        .read(
            crate::sql::WRITE_CONTACT.sql,
            &[
                (&owner, Type::INT8),
                (&book, Type::INT8),
                (&contact.uid, Type::TEXT),
                (&contact.display_name, Type::TEXT),
                (&contact.first_name, Type::TEXT),
                (&contact.last_name, Type::TEXT),
                (&contact.company, Type::TEXT),
                (&contact.job_title, Type::TEXT),
                (&contact.emails, Type::TEXT),
                (&contact.phones, Type::TEXT),
                (&contact.urls, Type::TEXT),
                (&contact.instant_msgs, Type::TEXT),
                (&contact.addresses, Type::TEXT),
                (&contact.notes, Type::TEXT),
                (&contact.birthday, Type::TEXT),
                (&contact.anniversary, Type::TEXT),
                (&upsert, Type::BOOL),
            ],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, i64>(0).ok())
        .ok_or_else(invalid)
}

/// Go's `contactStore.remove`: one `DELETE` with the ownership join in its WHERE.
pub async fn remove_contact(
    exec: &ScopedExecutor,
    owner: i64,
    book: i64,
    uid: &str,
) -> Result<i64, StatementFailure> {
    let rows = exec
        .read(
            crate::sql::REMOVE_CONTACT.sql,
            &[
                (&owner, Type::INT8),
                (&book, Type::INT8),
                (&uid, Type::TEXT),
            ],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, i64>(0).ok())
        .ok_or_else(invalid)
}

/// Go's `notify_contact_state(mailbox, 'contact_created', NULL)`: the state bump
/// and push fan-out of a finished import, one reducer call.
pub async fn notify_import(exec: &ScopedExecutor, owner: i64) -> Result<(), StatementFailure> {
    exec.read(crate::sql::NOTIFY_IMPORT.sql, &[(&owner, Type::INT8)])
        .await
        .map(|_| ())
}

/// The CSV export rows of an owned book, in Go's order. The ownership of `user`
/// is in the same statement (R1). Columns: first, last, display, company, job
/// title, emails (jsonb text), phones (jsonb text), notes.
pub async fn export_csv_rows(
    exec: &ScopedExecutor,
    book: i64,
    user: i64,
) -> Result<Vec<[String; 8]>, StatementFailure> {
    let rows = exec
        .read(
            crate::sql::EXPORT_CSV_ROWS.sql,
            &[(&book, Type::INT8), (&user, Type::INT8)],
        )
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

pub(crate) fn contact_row(row: &setjoin_pg::Row) -> Result<ContactRow, StatementFailure> {
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
    exec: &ScopedExecutor,
    book: i64,
    user: i64,
) -> Result<Vec<ContactRow>, StatementFailure> {
    let rows = exec
        .read(
            crate::sql::EXPORT_VCARD_ROWS.sql,
            &[(&book, Type::INT8), (&user, Type::INT8)],
        )
        .await?;
    rows.iter().map(contact_row).collect()
}

/// Go's `carddav.ExportVCard` read; `None` is `pgx.ErrNoRows` (missing or foreign).
pub async fn export_vcard_row(
    exec: &ScopedExecutor,
    contact: i64,
    user: i64,
) -> Result<Option<ContactRow>, StatementFailure> {
    let rows = exec
        .read(
            crate::sql::EXPORT_VCARD_ROW.sql,
            &[(&contact, Type::INT8), (&user, Type::INT8)],
        )
        .await?;
    rows.first().map(contact_row).transpose()
}
