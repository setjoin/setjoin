//! Identity self-knowledge and atomic alias edits, mirroring frozen Go.
use crate::{sql, Failure, SetOutcome};
use setjoin_authz::principals::{OwnerCapability, TxFactory, UserPrincipal};
use setjoin_contracts::command::CommandEnvelope;
use setjoin_pg::{CommandOutcome, ReceiptCommand, Rejection, StatementFailure};

#[derive(Default)]
pub struct Primary {
    pub email: String,
    pub name: String,
    pub given: Option<String>,
    pub family: Option<String>,
    pub avatar: Option<String>,
}

pub struct Entry {
    pub id: i64,
    pub name: String,
    pub email: String,
    pub signature: Option<String>,
    pub reply: Option<String>,
}

pub async fn primary(tx_factory: &TxFactory, user: &UserPrincipal) -> Primary {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &sql::IDENTITY_PRIMARY, &[&uid])
        .await
        .unwrap_or_default();
    rows.first()
        .and_then(|r| {
            Some(Primary {
                email: r.try_get(0).ok()?,
                name: r.try_get(1).ok()?,
                given: r.try_get(2).ok()?,
                family: r.try_get(3).ok()?,
                avatar: r.try_get(4).ok()?,
            })
        })
        .unwrap_or_default()
}

pub async fn aliases(tx_factory: &TxFactory, user: &UserPrincipal) -> Vec<Entry> {
    let uid = user.user().get();
    let Ok(mut tx) = tx_factory.begin_user_read(user).await else {
        return Vec::new();
    };
    let rows = tx
        .query_iterated_contract(&sql::IDENTITY_ALIASES, &[&uid])
        .await
        .unwrap_or_default();
    let _ = tx.finish().await;
    rows.iter()
        .filter_map(|r| {
            Some(Entry {
                id: r.try_get(0).ok()?,
                name: r.try_get(1).ok()?,
                email: r.try_get(2).ok()?,
                signature: r.try_get(3).ok()?,
                reply: r.try_get(4).ok()?,
            })
        })
        .collect()
}

pub async fn delegated(tx_factory: &TxFactory, user: &UserPrincipal) -> Vec<Entry> {
    let uid = user.user().get();
    let Ok(mut tx) = tx_factory.begin_user_read(user).await else {
        return Vec::new();
    };
    let rows = tx
        .query_iterated_contract(&sql::IDENTITY_DELEGATED, &[&uid])
        .await
        .unwrap_or_default();
    let _ = tx.finish().await;
    rows.iter()
        .filter_map(|r| {
            Some(Entry {
                id: r.try_get(0).ok()?,
                name: r.try_get(1).ok()?,
                email: r.try_get(2).ok()?,
                signature: None,
                reply: None,
            })
        })
        .collect()
}

pub async fn state(tx_factory: &TxFactory, user: &UserPrincipal) -> Option<String> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &sql::IDENTITY_STATE, &[&uid])
        .await
        .ok()?;
    Some(rows.first()?.try_get::<_, i64>(0).ok()?.to_string())
}

pub async fn set(
    tx_factory: &TxFactory,
    owner: &OwnerCapability,
    envelope: &CommandEnvelope<()>,
    create: &Option<String>,
    update: &Option<String>,
    destroy: &Option<Vec<i64>>,
) -> SetOutcome {
    let mailbox = owner.mailbox().get();
    let out = tx_factory
        .run_owner_write_contract_pipelined(
            owner,
            envelope,
            std::time::Instant::now() + std::time::Duration::from_secs(10),
            &sql::IDENTITY_SET,
            &[&mailbox, create, update, destroy],
            Some(ReceiptCommand {
                family: "jmap",
                command: "identity.set",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(|| StatementFailure {
                        hint: None,
                        sqlstate: None,
                        message: "missing identity set result".into(),
                    })
            },
        )
        .await;
    match out {
        CommandOutcome::Committed(raw) => SetOutcome::Done(raw),
        CommandOutcome::Unknown { operation } => SetOutcome::Unknown { operation },
        CommandOutcome::RolledBack(Rejection::Statement(f)) => {
            SetOutcome::Failed(match crate::classify_failure(&f) {
                Failure::Forward => Failure::ServerFail,
                f => f,
            })
        }
        _ => SetOutcome::Failed(Failure::ServerFail),
    }
}
