//! DB proofs for `Email/get` that the parity oracle cannot record: every read
//! (including `smime-encrypted` entries handled by gateway decrypt-on-read)
//! writes one `email_get` audit row, and the mailbox is the authenticated one.
use std::time::{Duration, Instant};

use setjoin_authz::principals::TxFactory;
use setjoin_conformance::fixture::{self, Account};
use setjoin_conformance::harness::Db;
use setjoin_contracts::authority::{AuthorityKey, ResourceScope};
use setjoin_contracts::command::CommandEnvelope;
use setjoin_contracts::ids::{ActorId, Digest, Generation, OperationId};
use setjoin_db::lifecycle::accepted_contract;
use setjoin_jmap::{email_get, EmailGet, GetOutcome};
use setjoin_pg::ScopedExecutor;
use tokio_postgres::types::Type;

async fn get(tx: &TxFactory, a: &Account, ids: &[i64]) -> GetOutcome {
    let principal = tx
        .mint_capability_primary_mailbox(ActorId::new(a.user).unwrap(), "", "127.0.0.1")
        .await
        .unwrap();
    let cap = principal.require_read().unwrap();
    let envelope = CommandEnvelope {
        operation: OperationId([0x6E; 16]),
        authority: AuthorityKey {
            actor: cap.actor(),
            scope: ResourceScope::Mailbox(cap.mailbox()),
            generation: Generation(1),
        },
        binding: accepted_contract(),
        payload_digest: Digest([1; 32]),
        command: EmailGet,
    };
    email_get(
        tx,
        &envelope,
        &cap,
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
async fn encrypted_mail_is_served_for_decrypt_and_audited_once() {
    let Some(db) = Db::for_case("encrypted_mail_is_served_for_decrypt_and_audited_once") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    let exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).unwrap();
    let tx = TxFactory::new(exec.try_app_pool().unwrap());
    let a = fixture::account(&owner, "email-get-db").await.unwrap();
    let plain = get(&tx, &a, &[a.two_labels]).await;
    assert!(matches!(plain, GetOutcome::Served(_)), "{plain:?}");
    assert_eq!(audits(&owner, &a).await, 1);

    owner
        .query_typed(
            "UPDATE messages SET crypto_type = 'smime-encrypted' WHERE id = $1",
            &[(&a.inbox_only, Type::INT8)],
        )
        .await
        .unwrap();
    let mixed = get(&tx, &a, &[a.two_labels, a.inbox_only]).await;
    let GetOutcome::Served(text) = mixed else {
        panic!("expected GetOutcome::Served for gateway decrypt-on-read, got {mixed:?}");
    };
    assert!(text.contains("smime-encrypted"), "{text}");
    assert_eq!(
        audits(&owner, &a).await,
        2,
        "encrypted read also commits its email_get audit row"
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
    let tx = TxFactory::new(exec.try_app_pool().unwrap());
    let a = fixture::account(&owner, "email-get-db-a").await.unwrap();
    let b = fixture::account(&owner, "email-get-db-b").await.unwrap();
    let GetOutcome::Served(text) = get(&tx, &a, &[b.two_labels]).await else {
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
