//! iMIP egress for CalendarEvent/counter, sendUpdate, set and setOccurrence
//! (#369): Go `serializeAndEnqueueInvite` / `serializeAndEnqueueCounter`
//! (calendar.go:398/:798). Mail leaves the system here, so this module, not
//! the family seam, owns the egress rules: the sender (the caller, or a
//! mailbox the caller may send as), exact addr-specs, Go's closed seven-header
//! head with an exact `From:` address, and size bounds. Family code reaches it
//! only through `family::seam::send_imip`, which gates the method, bounds the
//! messages per method call (per `Cx`) and passes the verified caller. Every drop is logged
//! with the method, the uid and the reason. One non-ASCII or quoted address
//! among the recipients drops the whole invite (follow-up #398); an
//! organizer-only invite (no recipients) is logged as a drop and still counts
//! toward the per-method-call bound.
use std::sync::Arc;
use std::time::Duration;

use setjoin_contracts::ids::ActorId;
use setjoin_pg::{ScopedExecutor, Type};

use crate::recovery_worker::{ObjectStore, S3Store};

/// One serialized iMIP message (Go `buildInviteMIME` / `buildCounterMIME`).
pub(crate) struct Imip {
    pub message_id: String,
    pub from: String,
    pub recipients: Vec<String>,
    pub mime: String,
}

/// The methods that may send iMIP (Go's four egress call sites).
pub(crate) const METHODS: &[&str] = &[
    "CalendarEvent/counter",
    "CalendarEvent/sendUpdate",
    "CalendarEvent/set",
    "CalendarEvent/setOccurrence",
];

/// Rust-only bounds (Go has none); a message over them is dropped and logged
/// (seam-security-fixes.json SEAM-3, SEAM-4).
pub(crate) const MAX_MESSAGES_PER_REQUEST: usize = 100;
const MAX_MIME_BYTES: usize = 10 * 1024 * 1024;
const MAX_RECIPIENTS: usize = 500;
const MAX_ADDRESS_BYTES: usize = 320;

/// Go's head, exactly these lines in this order (caldav/imip.go:55-61).
const HEADERS: [&str; 7] = [
    "From",
    "To",
    "Subject",
    "Date",
    "Message-ID",
    "MIME-Version",
    "Content-Type",
];

/// The sender resolves (ADR-004, any address) to the caller, or to a mailbox
/// the caller holds `send_as`/`full_access` on: the reducer's own
/// `delegatedFrom` rule (jmap_calendar.sql:113). `$1` is the session user.
const SENDER: &str = "SELECT EXISTS (SELECT 1 FROM resolve_identity($2) ri WHERE ri.user_id = $1 OR EXISTS (SELECT 1 FROM mailbox_delegates d WHERE d.mailbox_id = ri.primary_mailbox AND d.user_id = $1 AND d.permission IN ('send_as','full_access')))";

const OUTBOUND: &str = "INSERT INTO outbound_queue (message_id, from_addr, rcpt_addrs, raw_ref, status) VALUES ($1, $2, $3, $4, 'pending')";

#[cfg(test)]
thread_local! {
    /// The last drop reason on this thread (the observable boundary for tests).
    pub(crate) static LAST_DROP: std::cell::Cell<Option<&'static str>> =
        const { std::cell::Cell::new(None) };
}

/// Log one dropped message by method and uid (`{:?}` escapes control characters).
pub(crate) fn dropped(method: &str, uid: &str, reason: &'static str) {
    #[cfg(test)]
    LAST_DROP.with(|last| last.set(Some(reason)));
    eprintln!("setjoin-gateway: imip {method} uid={uid:?}: dropped ({reason})");
}

/// An RFC 5322 dot-atom addr-spec: ASCII atext atoms, a dotted LDH domain,
/// local part at most 64 and the whole at most 320 bytes. No quoted local
/// parts, comments, whitespace, controls or `<>,;"`.
pub(crate) fn addr_spec(value: &str) -> bool {
    const SPECIAL: &str = "!#$%&'*+-/=?^_`{|}~";
    if value.len() > MAX_ADDRESS_BYTES {
        return false;
    }
    let Some((local, domain)) = value.rsplit_once('@') else {
        return false;
    };
    let local_ok = !local.is_empty()
        && local.len() <= 64
        && local.split('.').all(|atom| {
            !atom.is_empty()
                && atom
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || SPECIAL.contains(ch))
        });
    let domain_ok = !domain.is_empty()
        && domain.len() <= 255
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        });
    local_ok && domain_ok
}

/// Checks that need no database; `Err` names the refused part.
pub(crate) fn well_formed(mail: &Imip) -> Result<(), &'static str> {
    if mail.message_id.is_empty()
        || mail.message_id.len() > 255
        || !mail.message_id.chars().all(|ch| ch.is_ascii_graphic())
    {
        return Err("message id");
    }
    if !addr_spec(&mail.from) {
        return Err("sender");
    }
    if mail.recipients.is_empty() || mail.recipients.len() > MAX_RECIPIENTS {
        return Err("recipient count");
    }
    if !mail.recipients.iter().all(|recipient| addr_spec(recipient)) {
        return Err("recipient");
    }
    if mail.mime.len() > MAX_MIME_BYTES {
        return Err("size");
    }
    let Some((head, _)) = mail.mime.split_once("\r\n\r\n") else {
        return Err("header block");
    };
    let lines: Vec<&str> = head.split("\r\n").collect();
    if lines.len() != HEADERS.len() {
        return Err("header block");
    }
    for (line, name) in lines.iter().zip(HEADERS) {
        if line.chars().any(char::is_control) {
            return Err("header block");
        }
        if line
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix(": "))
            .is_none()
        {
            return Err("header block");
        }
    }
    let from = lines[0].strip_prefix("From: ").unwrap_or_default();
    let Some((display, address)) = from.rsplit_once('<') else {
        return Err("From header");
    };
    if address != format!("{}>", mail.from) || display.contains(['<', '>']) {
        return Err("From header");
    }
    Ok(())
}

/// Whether the session user may send as `from`.
pub(crate) async fn sender_allowed(
    exec: &ScopedExecutor,
    actor: ActorId,
    user: i64,
    from: &str,
) -> Result<bool, setjoin_pg::StatementFailure> {
    let rows = exec
        .read_user_scoped(actor, SENDER, &[(&user, Type::INT8), (&from, Type::TEXT)])
        .await?;
    Ok(rows.first().and_then(|row| row.try_get::<_, bool>(0).ok()) == Some(true))
}

/// The checks, then a content-addressed `imip/<sha256>.eml` object, then one
/// `outbound_queue` row on the request credential (Go's plain-pool `Exec`).
/// Nothing is stored or queued unless every check passed.
pub(crate) async fn deliver(
    exec: &ScopedExecutor,
    store: &dyn ObjectStore,
    actor: ActorId,
    user: i64,
    mail: &Imip,
) -> Result<(), &'static str> {
    well_formed(mail)?;
    match sender_allowed(exec, actor, user, &mail.from).await {
        Ok(true) => {}
        Ok(false) => return Err("sender not allowed"),
        Err(error) => {
            eprintln!(
                "setjoin-gateway: imip sender check failed: sqlstate={}",
                error.sqlstate.as_deref().unwrap_or("none")
            );
            return Err("sender check failed");
        }
    }
    let key = format!("imip/{}.eml", crate::booking_mail::sha256_hex(&mail.mime));
    if let Err(error) = crate::booking_mail::put(store, &key, &mail.mime).await {
        eprintln!("setjoin-gateway: imip store failed: {error}");
        return Err("store failed");
    }
    if let Err(error) = exec
        .protocol_statement(
            OUTBOUND,
            &[
                (&mail.message_id, Type::TEXT),
                (&mail.from, Type::TEXT),
                (&mail.recipients, Type::TEXT_ARRAY),
                (&key, Type::TEXT),
            ],
        )
        .await
    {
        eprintln!(
            "setjoin-gateway: imip enqueue failed: sqlstate={}",
            error.sqlstate.as_deref().unwrap_or("none")
        );
        return Err("enqueue failed");
    }
    Ok(())
}

/// Detached and best effort, bounded like Go (5 minutes).
pub(crate) fn spawn(
    exec: ScopedExecutor,
    store: Arc<S3Store>,
    actor: ActorId,
    user: i64,
    method: &'static str,
    mail: Imip,
) {
    tokio::spawn(async move {
        let outcome = tokio::time::timeout(
            Duration::from_secs(300),
            deliver(&exec, store.as_ref(), actor, user, &mail),
        )
        .await;
        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(reason)) => dropped(method, &mail.message_id, reason),
            Err(_) => dropped(method, &mail.message_id, "timed out"),
        }
    });
}

#[cfg(test)]
pub(crate) fn head(from_name: &str, from: &str) -> String {
    format!(
        "From: {from_name} <{from}>\r\nTo: B <b@y.test>\r\nSubject: Invitation: x\r\n\
         Date: Sat, 14 Nov 2026 10:00:00 +0000\r\nMessage-ID: <1@mailserver>\r\n\
         MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=b\r\n\r\n--b--\r\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mail(from: &str, mime: String) -> Imip {
        Imip {
            message_id: "uid-1".into(),
            from: from.into(),
            recipients: vec!["b@y.test".into()],
            mime,
        }
    }

    #[test]
    fn egress_fields_are_exact() {
        assert_eq!(
            well_formed(&mail("a@x.test", head("A", "a@x.test"))),
            Ok(())
        );
        assert_eq!(well_formed(&mail("a@x.test", head("", "a@x.test"))), Ok(()));
        let spoofed = [
            head("A", "ceo@x.test"),
            head("A", "a@x.test.evil.org"),
            head("A <a@x.test>", "ceo@x.test"),
            head("A", "a@x.test").replacen("From: ", "From : ", 1),
        ];
        for mime in spoofed {
            assert!(
                well_formed(&mail("a@x.test", mime.clone())).is_err(),
                "{mime:?}"
            );
        }
        let injected = head("A", "a@x.test").replacen("To: ", "Bcc: e@z.test\r\nTo: ", 1);
        assert_eq!(
            well_formed(&mail("a@x.test", injected)),
            Err("header block")
        );
        let doubled = head("A", "a@x.test").replacen("To: ", "From: e@z.test\r\nTo: ", 1);
        assert_eq!(well_formed(&mail("a@x.test", doubled)), Err("header block"));
        let lf = head("A", "a@x.test").replace("\r\n", "\n");
        assert_eq!(well_formed(&mail("a@x.test", lf)), Err("header block"));
        let tab = head("A", "a@x.test").replacen("Subject: ", "Subject: \t", 1);
        assert_eq!(well_formed(&mail("a@x.test", tab)), Err("header block"));
        for bad in [
            "a b@x.test",
            "<a@x.test>",
            "a@x.test,b@y.test",
            "a;b@x.test",
            "\"a\"@x.test",
            "a@x..test",
            "a@-x.test",
            "a\u{7}@x.test",
            "a@x.test\r\nBcc: e@z.test",
            "",
            "@x.test",
            "a@",
        ] {
            assert!(!addr_spec(bad), "{bad:?}");
            assert_eq!(
                well_formed(&mail(bad, head("A", bad))),
                Err("sender"),
                "{bad:?}"
            );
        }
        assert!(addr_spec(&format!("{}@x.test", "a".repeat(64))));
        assert!(!addr_spec(&format!("{}@x.test", "a".repeat(65))));
        assert!(!addr_spec(&format!("a@{}.test", "x".repeat(320))));
        let mut recipient = mail("a@x.test", head("A", "a@x.test"));
        recipient.recipients = vec!["b@y.test>".into()];
        assert_eq!(well_formed(&recipient), Err("recipient"));
        let mut id = mail("a@x.test", head("A", "a@x.test"));
        id.message_id = "u\nBcc: e@z.test".into();
        assert_eq!(well_formed(&id), Err("message id"));
        let mut none = mail("a@x.test", head("A", "a@x.test"));
        none.recipients.clear();
        assert_eq!(well_formed(&none), Err("recipient count"));
        let mut flood = mail("a@x.test", head("A", "a@x.test"));
        flood.recipients = vec!["b@y.test".into(); MAX_RECIPIENTS + 1];
        assert_eq!(well_formed(&flood), Err("recipient count"));
        let large = format!("{}{}", head("A", "a@x.test"), "x".repeat(MAX_MIME_BYTES));
        assert_eq!(well_formed(&mail("a@x.test", large)), Err("size"));
    }
}

/// Runs on the server-rust lane (per-test clone, REQUIRE_DB=1).
#[cfg(test)]
mod db {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    use futures_util::FutureExt;
    use setjoin_conformance::fixture;
    use setjoin_conformance::harness::Db;

    use super::*;

    /// An in-memory object store: every `put` is recorded.
    #[derive(Default)]
    struct Memory(Mutex<Vec<(String, Vec<u8>)>>);

    impl ObjectStore for Memory {
        fn put<'a>(
            &'a self,
            key: &'a str,
            bytes: &'a [u8],
            _content_type: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            self.0
                .lock()
                .expect("memory store")
                .push((key.to_owned(), bytes.to_vec()));
            Box::pin(async { Ok(()) })
        }

        fn remove<'a>(
            &'a self,
            _key: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }
    }

    async fn email(owner: &tokio_postgres::Client, mailbox: i64) -> String {
        owner
            .query_one("SELECT email FROM mailboxes WHERE id = $1", &[&mailbox])
            .await
            .expect("mailbox email")
            .get(0)
    }

    async fn grant(
        owner: &tokio_postgres::Client,
        mailbox: i64,
        user: i64,
        by: i64,
        permission: &str,
    ) {
        owner
            .execute(
                "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
                 VALUES ($1, $2, $3, $4)",
                &[&mailbox, &user, &permission, &by],
            )
            .await
            .expect("grant");
    }

    async fn revoke(owner: &tokio_postgres::Client, mailbox: i64) {
        owner
            .execute(
                "DELETE FROM mailbox_delegates WHERE mailbox_id = $1",
                &[&mailbox],
            )
            .await
            .expect("revoke");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_sender_is_the_caller_or_a_send_as_grant() {
        let Some(db) = Db::for_case("the_sender_is_the_caller_or_a_send_as_grant") else {
            return;
        };
        let owner = db.connect().await.expect("owner connection");
        let a = fixture::account(&owner, "famimip").await.expect("own");
        let f = fixture::account(&owner, "famimip-foreign")
            .await
            .expect("foreign");
        let exec =
            ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).expect("executor");
        let actor = ActorId::new(a.user).expect("actor");
        let own = email(&owner, a.mailbox).await;
        let foreign = email(&owner, f.mailbox).await;
        let outcome = std::panic::AssertUnwindSafe(async {
            let allowed = |from: String| {
                let exec = &exec;
                async move {
                    sender_allowed(exec, actor, a.user, &from)
                        .await
                        .expect("sender check")
                }
            };
            assert!(allowed(own.clone()).await, "the caller");
            assert!(!allowed(foreign.clone()).await, "a stranger");
            assert!(!allowed("nobody@nowhere.invalid".into()).await, "unknown");
            for (permission, expected) in [
                ("read", false),
                ("manage_calendar", false),
                ("send_on_behalf", false),
                ("send_as", true),
                ("full_access", true),
            ] {
                grant(&owner, f.mailbox, a.user, f.user, permission).await;
                assert_eq!(allowed(foreign.clone()).await, expected, "{permission}");
                revoke(&owner, f.mailbox).await;
            }
        })
        .catch_unwind()
        .await;
        let _ = owner
            .execute(
                "DELETE FROM mailbox_delegates WHERE mailbox_id = ANY($1)",
                &[&vec![a.mailbox, f.mailbox]],
            )
            .await;
        fixture::remove(&owner, &f).await.expect("remove foreign");
        fixture::remove(&owner, &a).await.expect("remove own");
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
    }

    /// F1: `deliver` itself runs the checks: an allowed send writes exactly one
    /// object and one queue row; every refused send writes neither.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn egress_enqueues_only_checked_mail() {
        let Some(db) = Db::for_case("egress_enqueues_only_checked_mail") else {
            return;
        };
        let owner = db.connect().await.expect("owner connection");
        let a = fixture::account(&owner, "famimipq").await.expect("own");
        let f = fixture::account(&owner, "famimipq-foreign")
            .await
            .expect("foreign");
        let exec =
            ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).expect("executor");
        let actor = ActorId::new(a.user).expect("actor");
        let own = email(&owner, a.mailbox).await;
        let foreign = email(&owner, f.mailbox).await;
        let prefix = format!("seam-imip-{}-", a.mailbox);
        let memory = Memory::default();
        let outcome = std::panic::AssertUnwindSafe(async {
            let rows = |id: String| {
                let owner = &owner;
                async move {
                    owner
                        .query(
                            "SELECT from_addr, rcpt_addrs, raw_ref FROM outbound_queue \
                             WHERE message_id = $1",
                            &[&id],
                        )
                        .await
                        .expect("queue rows")
                }
            };
            let good = Imip {
                message_id: format!("{prefix}ok"),
                from: own.clone(),
                recipients: vec!["b@y.test".into()],
                mime: head("A", &own),
            };
            deliver(&exec, &memory, actor, a.user, &good)
                .await
                .expect("an allowed send");
            let key = format!("imip/{}.eml", crate::booking_mail::sha256_hex(&good.mime));
            {
                let stored = memory.0.lock().expect("memory store");
                assert_eq!(stored.len(), 1, "exactly one object");
                assert_eq!(stored[0].0, key);
                assert_eq!(stored[0].1, good.mime.as_bytes());
            }
            let queued = rows(good.message_id.clone()).await;
            assert_eq!(queued.len(), 1, "exactly one queue row");
            assert_eq!(queued[0].get::<_, String>(0), own);
            assert_eq!(
                queued[0].get::<_, Vec<String>>(1),
                vec!["b@y.test".to_owned()]
            );
            assert_eq!(queued[0].get::<_, String>(2), key);

            let spoofed = Imip {
                message_id: format!("{prefix}foreign"),
                from: foreign.clone(),
                recipients: vec!["b@y.test".into()],
                mime: head("F", &foreign),
            };
            let malformed = Imip {
                message_id: format!("{prefix}malformed"),
                from: own.clone(),
                recipients: vec!["b@y.test".into()],
                mime: head("A", &own).replacen("To: ", "Bcc: e@z.test\r\nTo: ", 1),
            };
            let oversize = Imip {
                message_id: format!("{prefix}oversize"),
                from: own.clone(),
                recipients: vec!["b@y.test".into()],
                mime: format!("{}{}", head("A", &own), "x".repeat(MAX_MIME_BYTES)),
            };
            for mail in [&spoofed, &malformed, &oversize] {
                assert!(
                    deliver(&exec, &memory, actor, a.user, mail).await.is_err(),
                    "{}",
                    mail.message_id
                );
            }
            grant(&owner, f.mailbox, a.user, f.user, "manage_calendar").await;
            let calendar_only = Imip {
                message_id: format!("{prefix}manage-calendar"),
                ..spoofed
            };
            assert_eq!(
                deliver(&exec, &memory, actor, a.user, &calendar_only).await,
                Err("sender not allowed"),
                "manage_calendar does not allow sending as the mailbox"
            );
            revoke(&owner, f.mailbox).await;
            assert_eq!(
                memory.0.lock().expect("memory store").len(),
                1,
                "no new object"
            );
            for id in ["foreign", "malformed", "oversize", "manage-calendar"] {
                assert!(
                    rows(format!("{prefix}{id}")).await.is_empty(),
                    "{id}: no row"
                );
            }
        })
        .catch_unwind()
        .await;
        let pattern = format!("{prefix}%");
        let _ = owner
            .execute(
                "DELETE FROM outbound_queue WHERE message_id LIKE $1",
                &[&pattern],
            )
            .await;
        let _ = owner
            .execute(
                "DELETE FROM outbound_queue_hot WHERE message_id LIKE $1",
                &[&pattern],
            )
            .await;
        let _ = owner
            .execute(
                "DELETE FROM mailbox_delegates WHERE mailbox_id = ANY($1)",
                &[&vec![a.mailbox, f.mailbox]],
            )
            .await;
        fixture::remove(&owner, &f).await.expect("remove foreign");
        fixture::remove(&owner, &a).await.expect("remove own");
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
    }
}
