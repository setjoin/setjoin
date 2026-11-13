//! DB proofs for `Email/get` that the parity oracle cannot record: encrypted
//! mail is left for Go (no audit row, `Encrypted`), plaintext writes exactly
//! one audit row with the read, and the mailbox is the authenticated one.
use std::time::{Duration, Instant};

use setjoin_conformance::fixture::{self, Account};
use setjoin_conformance::harness::Db;
use setjoin_contracts::command::CommandEnvelope;
use setjoin_contracts::ids::{ActorId, Digest, Generation, MailboxId, OperationId};
use setjoin_db::lifecycle::accepted_contract;
use setjoin_jmap::{email_get, EmailGet, GetOutcome};
use setjoin_pg::{MailboxAuthContext, ScopedExecutor};
use tokio_postgres::types::Type;

async fn get(exec: &ScopedExecutor, a: &Account, ids: &[i64]) -> GetOutcome {
    let auth = MailboxAuthContext::from_authenticated_session(
        ActorId::new(a.user).unwrap(),
        MailboxId::new(a.mailbox).unwrap(),
        Generation(1),
    );
    let envelope = CommandEnvelope {
        operation: OperationId([0x6E; 16]),
        authority: auth.authority(),
        binding: accepted_contract(),
        payload_digest: Digest([1; 32]),
        command: EmailGet,
    };
    email_get(
        exec,
        &envelope,
        &auth,
        Instant::now() + Duration::from_secs(30),
        Some(ids),
        None,
    )
    .await
}

async fn audits(owner: &tokio_postgres::Client, a: &Account) -> i64 {
    owner
        .query_typed(
            "SELECT count(*) FROM mailbox_audit_log WHERE mailbox_id = $1 AND action = 'email_get'",
            &[(&a.mailbox, Type::INT8)],
        )
        .await
        .unwrap()[0]
        .get(0)
}

#[tokio::test]
async fn encrypted_mail_is_left_for_go_and_plaintext_is_audited_once() {
    let Some(db) = Db::for_case("encrypted_mail_is_left_for_go_and_plaintext_is_audited_once")
    else {
        return;
    };
    let owner = db.connect().await.unwrap();
    let exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).unwrap();
    let a = fixture::account(&owner, "email-get-db").await.unwrap();
    let plain = get(&exec, &a, &[a.two_labels]).await;
    assert!(matches!(plain, GetOutcome::Served(_)), "{plain:?}");
    assert_eq!(audits(&owner, &a).await, 1);

    owner
        .query_typed(
            "UPDATE messages SET crypto_type = 'smime-encrypted' WHERE id = $1",
            &[(&a.inbox_only, Type::INT8)],
        )
        .await
        .unwrap();
    let mixed = get(&exec, &a, &[a.two_labels, a.inbox_only]).await;
    assert_eq!(mixed, GetOutcome::Encrypted);
    assert_eq!(
        audits(&owner, &a).await,
        1,
        "an encrypted read writes nothing"
    );
    fixture::remove(&owner, &a).await.unwrap();
}

#[tokio::test]
async fn another_mailboxes_message_is_not_returned_and_is_still_audited_as_a_read() {
    let Some(db) =
        Db::for_case("another_mailboxes_message_is_not_returned_and_is_still_audited_as_a_read")
    else {
        return;
    };
    let owner = db.connect().await.unwrap();
    let exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).unwrap();
    let a = fixture::account(&owner, "email-get-db-a").await.unwrap();
    let b = fixture::account(&owner, "email-get-db-b").await.unwrap();
    let GetOutcome::Served(text) = get(&exec, &a, &[b.two_labels]).await else {
        panic!("served");
    };
    assert!(
        text.contains(&format!("\"{}\"", b.two_labels)) && text.contains("\"list\": []"),
        "{text}"
    );
    assert_eq!(audits(&owner, &b).await, 0);
    fixture::remove(&owner, &a).await.unwrap();
    fixture::remove(&owner, &b).await.unwrap();
}
