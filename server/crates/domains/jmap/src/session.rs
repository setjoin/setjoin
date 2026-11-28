//! Data behind the authenticated JMAP discovery session. Public branding reads
//! only the same named system_config keys Go exposes to ordinary members.
use setjoin_authz::principals::{OwnerCapability, ReadCapability, TxFactory, UserPrincipal};
use setjoin_contracts::command::CommandEnvelope;
use setjoin_pg::{CommandOutcome, ReceiptCommand, StatementFailure};
use std::collections::BTreeMap;

use crate::sql;

pub struct Delegated {
    pub id: i64,
    pub email: String,
    pub grants: Vec<String>,
    pub aliases: Vec<String>,
}

pub async fn delegated(
    tx_factory: &TxFactory,
    read: &ReadCapability,
) -> Result<Vec<Delegated>, StatementFailure> {
    let user = read.actor().get();
    let mailbox = read.mailbox().get();
    let mut tx = tx_factory.begin_mailbox_read(read).await?;
    let rows = tx
        .query_iterated_contract(&sql::SESSION_DELEGATED, &[&user, &mailbox])
        .await?;
    tx.finish().await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            Some(Delegated {
                id: r.try_get(0).ok()?,
                email: r.try_get(1).ok()?,
                grants: r.try_get(2).ok()?,
                aliases: r.try_get(3).ok()?,
            })
        })
        .collect())
}

pub async fn effective_caps(
    tx_factory: &TxFactory,
    read: &ReadCapability,
) -> Result<String, StatementFailure> {
    let mailbox = read.mailbox().get();
    let rows = tx_factory
        .run_mailbox_read_contract(read, &sql::SESSION_EFFECTIVE_CAPS, &[&mailbox])
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(|| StatementFailure {
            hint: None,
            sqlstate: None,
            message: "missing capabilities".into(),
        })
}

#[derive(Default)]
pub struct Settings {
    pub deleted_days: i32,
    pub spam_days: i32,
    pub brand_name: String,
    pub brand_logo: String,
    pub help_email: String,
    pub strict: bool,
    pub flags: BTreeMap<String, bool>,
}

pub async fn settings(tx_factory: &TxFactory, read: &ReadCapability) -> Settings {
    let mailbox = read.mailbox().get();
    let mut s = Settings {
        deleted_days: 30,
        spam_days: 30,
        ..Default::default()
    };
    if let Ok(rows) = tx_factory
        .run_mailbox_read_contract(read, &sql::SESSION_PURGE_DAYS, &[&mailbox])
        .await
    {
        if let Some(row) = rows.first() {
            if let Ok(v) = row.try_get(0) {
                s.deleted_days = v;
            }
            if let Ok(v) = row.try_get(1) {
                s.spam_days = v;
            }
        }
    }
    if let Ok(rows) = tx_factory
        .run_mailbox_read_contract(read, &sql::SESSION_BRANDING, &[])
        .await
    {
        if let Some(row) = rows.first() {
            if let Ok(v) = row.try_get(0) {
                s.brand_name = v;
            }
            if let Ok(v) = row.try_get(1) {
                s.brand_logo = v;
            }
        }
    }
    if let Ok(rows) = tx_factory
        .run_mailbox_read_contract(read, &sql::SESSION_HELP_EMAIL, &[])
        .await
    {
        if let Some(row) = rows.first() {
            if let Ok(v) = row.try_get(0) {
                s.help_email = v;
            }
        }
    }
    if let Ok(rows) = tx_factory
        .run_mailbox_read_contract(read, &sql::SESSION_APPS_CAPS_STRICT, &[])
        .await
    {
        if let Some(row) = rows.first() {
            if let Ok(v) = row.try_get(0) {
                s.strict = v;
            }
        }
    }
    let keys = vec![
        "feature.shared_task_lists",
        "feature.biometric_unlock",
        "feature.windows_sso_unlock",
        "dengbao.sod_mode",
    ];
    if let Ok(rows) = tx_factory
        .run_mailbox_read_contract(read, &sql::SESSION_FEATURE_TOGGLES, &[&keys])
        .await
    {
        for row in rows {
            if let (Ok(k), Ok(v)) = (row.try_get(0), row.try_get(1)) {
                s.flags.insert(k, v);
            }
        }
    }
    s
}

pub async fn sod_class(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<String, StatementFailure> {
    let uid = user.user().get();
    let mut tx = tx_factory.begin_user_read(user).await?;
    let rows = tx
        .query_iterated_contract(&sql::SESSION_SOD_CLASS, &[&uid])
        .await?;
    tx.finish().await?;
    let classes: std::collections::BTreeSet<String> = rows
        .iter()
        .filter_map(|r| r.try_get::<_, String>(0).ok())
        .filter(|s| !s.is_empty())
        .collect();
    Ok(if classes.len() == 1 {
        classes.into_iter().next().unwrap()
    } else {
        String::new()
    })
}

/// Mirrors Go's mailbox-only CallScoped scope through the SQL adapter.
pub async fn register_device(
    tx_factory: &TxFactory,
    owner: &OwnerCapability,
    envelope: &CommandEnvelope<()>,
    fingerprint: &str,
    platform: &str,
) -> CommandOutcome<i64, StatementFailure> {
    let mailbox = owner.mailbox().get();
    tx_factory
        .run_owner_write_contract_pipelined(
            owner,
            envelope,
            std::time::Instant::now() + std::time::Duration::from_secs(10),
            &sql::SESSION_REGISTER_DEVICE,
            &[&mailbox, &fingerprint, &platform],
            Some(ReceiptCommand {
                family: "jmap",
                command: "session.device",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(|| StatementFailure {
                        hint: None,
                        sqlstate: None,
                        message: "missing native device".into(),
                    })
            },
        )
        .await
}

pub async fn device_caps(
    tx_factory: &TxFactory,
    read: &ReadCapability,
    device: i64,
) -> Result<String, StatementFailure> {
    let mailbox = read.mailbox().get();
    let rows = tx_factory
        .run_mailbox_read_contract(read, &sql::SESSION_DEVICE_CAPS, &[&mailbox, &device])
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(|| StatementFailure {
            hint: None,
            sqlstate: None,
            message: "missing device capabilities".into(),
        })
}

/// Same live union order as Go's permissions.ResolveAuthority; self-knowledge only.
pub async fn permissions(
    tx_factory: &TxFactory,
    user: &UserPrincipal,
) -> Result<Vec<String>, StatementFailure> {
    let uid = user.user().get();
    let rows = tx_factory
        .run_user_read_contract(user, &sql::SESSION_PERMISSIONS, &[&uid])
        .await?;
    let mut result = Vec::new();
    for row in rows {
        for p in row.get::<_, Vec<String>>(0) {
            if !result.contains(&p) {
                result.push(p);
            }
        }
    }
    Ok(result)
}
