//! `PUT /user/offline/sync-preferences` (#307).
use super::{command, deadline, invalid, mailbox_envelope};
use serde_json::{json, Value};
use setjoin_authz::principals::{MutateCapability, ReadCapability, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

pub struct SyncPut {
    pub opt_in: bool,
    pub window_days: i64,
    pub background: bool,
    pub network: String,
    pub prefetch: String,
}

pub fn valid(p: &SyncPut) -> bool {
    p.window_days >= 0
        && matches!(p.network.as_str(), "never" | "unmetered" | "any")
        && matches!(p.prefetch.as_str(), "never" | "unmetered" | "always")
}

pub async fn toggles(factory: &TxFactory) -> Result<[bool; 4], StatementFailure> {
    let rows = factory
        .run_public_read_contract(&crate::sql::SYNC_TOGGLES, &[])
        .await?;
    let row = rows.first().ok_or_else(invalid)?;
    let get = |i| row.try_get::<_, bool>(i).map_err(|_| invalid());
    Ok([get(0)?, get(1)?, get(2)?, get(3)?])
}

pub async fn primary_mailbox(factory: &TxFactory, user: &UserPrincipal) -> Option<i64> {
    let uid = user.user().get();
    factory
        .run_user_read_contract(user, &crate::sql::PRIMARY_MAILBOX, &[&uid])
        .await
        .ok()?
        .first()?
        .try_get(0)
        .ok()
}

pub async fn device(factory: &TxFactory, user: &UserPrincipal, fingerprint: &str) -> Option<i64> {
    if fingerprint.is_empty() {
        return None;
    }
    let uid = user.user().get();
    let bytes = fingerprint.as_bytes();
    let id: i64 = factory
        .run_user_read_contract(user, &crate::sql::SYNC_DEVICE, &[&uid, &bytes])
        .await
        .ok()?
        .first()?
        .try_get(0)
        .ok()?;
    (id > 0).then_some(id)
}

fn default_capabilities() -> Value {
    json!({
        "apps": {"mail": false, "calendar": false, "contacts": false, "tasks": false,
                 "approvals": false, "drive": false, "chat": false, "meet": false},
        "features": {"assist": false, "bundles": false, "external_labels": false,
                     "guest_accounts": false, "guest_invite": false, "mail_search_builder": false,
                     "sender_control_center": false, "shared_mail_work": false,
                     "shared_mail_comments": false},
        "offline": {"allowed": false, "approvalState": "pending", "maxOfflineDays": 0,
                    "wipeOnLogout": "admin_default", "requireApproval": true,
                    "biometricUnlock": false, "windowsSsoUnlock": false}
    })
}

pub async fn capabilities(
    factory: &TxFactory,
    cap: &ReadCapability,
    device: i64,
    unlock: [bool; 2],
) -> Value {
    let mailbox = cap.mailbox().get();
    let rows = factory
        .run_mailbox_read_contract(cap, &crate::sql::SYNC_CAPABILITIES, &[&mailbox, &device])
        .await;
    let parsed = rows
        .ok()
        .and_then(|r| r.first().and_then(|row| row.try_get::<_, String>(0).ok()))
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    match parsed {
        Some(Value::Object(mut map)) => {
            if let Some(Value::Object(offline)) = map.get_mut("offline") {
                offline.insert("biometricUnlock".into(), unlock[0].into());
                offline.insert("windowsSsoUnlock".into(), unlock[1].into());
            }
            Value::Object(map)
        }
        _ => default_capabilities(),
    }
}

pub fn mode(capabilities: &Value) -> &str {
    capabilities["offline"]["syncQoS"]["mode"]
        .as_str()
        .unwrap_or("")
}

pub async fn put(
    factory: &TxFactory,
    cap: &MutateCapability,
    device: i64,
    p: &SyncPut,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let mailbox = cap.mailbox().get();
    let window_days = p.window_days as i32;
    let env = mailbox_envelope(
        cap,
        operation,
        &format!(
            "sync.put:{device}:{}:{}:{}:{}:{}",
            p.opt_in, p.window_days, p.background, p.network, p.prefetch
        ),
    );
    factory
        .run_mailbox_write_contract_pipelined(
            cap,
            &env,
            deadline(),
            &crate::sql::SYNC_PUT,
            &[
                &mailbox,
                &device,
                &p.opt_in,
                &window_days,
                &p.background,
                &p.network,
                &p.prefetch,
            ],
            Some(command("sync.put")),
            |rows| rows.first().map(|_| ()).ok_or_else(invalid),
        )
        .await
}
