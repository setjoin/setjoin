//! F12 administrative compliance authority and user chat contracts.
#![forbid(unsafe_code)]

pub mod channels;
pub mod members;
pub mod sql;
pub use sql::SQL_CONTRACTS;

use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, OperationId},
};
use setjoin_pg::{CommandOutcome, ReceiptCommand, SqlContract, StatementFailure, ToSql};
use sha2::{Digest as _, Sha256};
use std::time::{Duration, Instant};

pub const VIEW: &str = "chat.compliance_view";
pub const MANAGE: &str = "chat.compliance_manage";

pub(crate) fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

pub(crate) fn envelope(
    actor: ActorId,
    generation: Generation,
    operation: [u8; 16],
    payload: &str,
) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: AuthorityKey {
            actor,
            scope: ResourceScope::User(actor),
            generation,
        },
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(payload.as_bytes()).into()),
        command: (),
    }
}

pub(crate) fn receipt(command: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: "F12",
        command,
    }
}

fn result_error() -> StatementFailure {
    StatementFailure {
        hint: None,
        sqlstate: None,
        message: "invalid compliance result".into(),
    }
}

async fn compliance_command(
    factory: &TxFactory,
    user: &UserPrincipal,
    name: &'static str,
    operation: [u8; 16],
    contract: &'static SqlContract,
    values: &[&(dyn ToSql + Sync)],
) -> CommandOutcome<(), StatementFailure> {
    let env = envelope(user.user(), user.generation(), operation, name);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            contract,
            values,
            Some(receipt(name)),
            |rows| {
                if rows.is_empty() {
                    Err(StatementFailure {
                        hint: None,
                        sqlstate: Some("42501".into()),
                        message: "compliance authority changed".into(),
                    })
                } else {
                    Ok(())
                }
            },
        )
        .await
}

/// One existing reducer owns the complete Go transaction and chain audit.
pub async fn hold(
    factory: &TxFactory,
    user: &UserPrincipal,
    _proof: &AdminPermissionProof,
    channel: i64,
    on: bool,
    reason: Option<String>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor = user.user().get();
    compliance_command(
        factory,
        user,
        "chat_channel_set_hold",
        operation,
        &sql::CHANNEL_SET_HOLD,
        &[&actor, &channel, &on, &reason],
    )
    .await
}

/// Frozen Go's durable best-effort middleware denial audit. Email is signed
/// token provenance; permission is current database authority, never that email.
pub async fn denied(
    factory: &TxFactory,
    user: &UserPrincipal,
    path: &str,
    manage: bool,
    operation: [u8; 16],
) {
    let missing = if manage {
        MANAGE.to_owned()
    } else {
        format!("{VIEW}|{MANAGE}")
    };
    let before = serde_json::json!({
        "actor": user.audit_meta().email,
        "target": path,
        "missingPermission": missing
    })
    .to_string();
    let _ = compliance_command(
        factory,
        user,
        "console.denied",
        operation,
        &sql::CONSOLE_DENIED,
        &[&before, &path],
    )
    .await;
}

/// Existing reducer owns the retention override, trigger rails and chain act.
pub async fn retention(
    factory: &TxFactory,
    user: &UserPrincipal,
    _proof: &AdminPermissionProof,
    channel: i64,
    days: Option<i32>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor = user.user().get();
    compliance_command(
        factory,
        user,
        "chat_channel_set_retention",
        operation,
        &sql::CHANNEL_SET_RETENTION,
        &[&actor, &channel, &days],
    )
    .await
}

pub async fn classification(
    factory: &TxFactory,
    user: &UserPrincipal,
    _proof: &AdminPermissionProof,
    channel: i64,
    class: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor = user.user().get();
    compliance_command(
        factory,
        user,
        "chat_channel_set_classification",
        operation,
        &sql::CHANNEL_SET_CLASSIFICATION,
        &[&actor, &channel, &class],
    )
    .await
}

pub async fn list(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    user: Option<i64>,
    query: Option<String>,
    limit: i64,
    offset: i64,
) -> Result<serde_json::Value, StatementFailure> {
    let actor = proof.actor().get();
    let rows = factory
        .run_admin_read_contract(
            proof,
            &sql::LIST_CHANNELS,
            &[&user, &query, &limit, &offset, &actor],
        )
        .await?;
    let decode_err = || StatementFailure {
        hint: None,
        sqlstate: None,
        message: "invalid channel row".into(),
    };
    let mut out = Vec::new();
    for row in rows {
        let participants: String = row.try_get(12).map_err(|_| decode_err())?;
        let mut v = serde_json::json!({
            "id": row.try_get::<_, i64>(0).map_err(|_| decode_err())?,
            "kind": row.try_get::<_, String>(1).map_err(|_| decode_err())?,
            "classification": row.try_get::<_, String>(3).map_err(|_| decode_err())?,
            "legalHold": row.try_get::<_, bool>(6).map_err(|_| decode_err())?,
            "lastPurgedSeq": row.try_get::<_, i64>(8).map_err(|_| decode_err())?,
            "memberCount": row.try_get::<_, i64>(10).map_err(|_| decode_err())?,
            "caseHoldCount": row.try_get::<_, i64>(11).map_err(|_| decode_err())?,
            "participants": serde_json::from_str::<serde_json::Value>(&participants).map_err(|_| {
                StatementFailure {
                    hint: None,
                    sqlstate: None,
                    message: "invalid participant JSON".into(),
                }
            })?
        });
        for (index, key) in [(2, "name"), (5, "wormMode"), (7, "legalHoldReason")] {
            if let Some(text) = row
                .try_get::<_, Option<String>>(index)
                .map_err(|_| decode_err())?
            {
                v[key] = text.into();
            }
        }
        for (index, key) in [(4, "retentionDays"), (9, "effectiveRetentionDays")] {
            if let Some(n) = row
                .try_get::<_, Option<i32>>(index)
                .map_err(|_| decode_err())?
            {
                v[key] = n.into();
            }
        }
        out.push(v);
    }
    Ok(out.into())
}

/// Go's independent, best-effort audited read. Never turns a successful read
/// into a failure; request data cannot supply the actor or action name.
pub async fn audit_read(
    factory: &TxFactory,
    user: &UserPrincipal,
    action: &'static str,
    target: Option<i64>,
    ip: &str,
    operation: [u8; 16],
) {
    let actor = user.user().get();
    let _ = compliance_command(
        factory,
        user,
        action,
        operation,
        &sql::AUDIT_READ,
        &[&actor, &action, &target, &ip],
    )
    .await;
}

pub async fn audit(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    channel: i64,
    before: Option<i64>,
    limit: i64,
) -> Result<serde_json::Value, StatementFailure> {
    let actor = proof.actor().get();
    let rows = factory
        .run_admin_read_contract(
            proof,
            &sql::AUDIT_LIST,
            &[&channel, &before, &limit, &actor],
        )
        .await?;
    let decode_err = || StatementFailure {
        hint: None,
        sqlstate: None,
        message: "invalid audit row".into(),
    };
    let mut out = Vec::new();
    for row in rows {
        let mut v = serde_json::json!({
            "id": row.try_get::<_, i64>(0).map_err(|_| decode_err())?,
            "occurredAt": row.try_get::<_, String>(1).map_err(|_| decode_err())?,
            "action": row.try_get::<_, String>(4).map_err(|_| decode_err())?,
        });
        for (index, key) in [(2, "userId"), (6, "targetId")] {
            if let Some(id) = row
                .try_get::<_, Option<i64>>(index)
                .map_err(|_| decode_err())?
            {
                v[key] = id.into();
            }
        }
        for (index, key) in [(5, "targetType"), (9, "notes")] {
            if let Some(s) = row
                .try_get::<_, Option<String>>(index)
                .map_err(|_| decode_err())?
            {
                v[key] = s.into();
            }
        }
        let ip: String = row.try_get(3).map_err(|_| decode_err())?;
        if !ip.is_empty() {
            v["ip"] = ip.into();
        }
        for (index, key) in [(7, "beforeState"), (8, "afterState")] {
            if let Some(s) = row
                .try_get::<_, Option<String>>(index)
                .map_err(|_| decode_err())?
            {
                v[key] = serde_json::from_str(&s).map_err(|_| StatementFailure {
                    hint: None,
                    sqlstate: None,
                    message: "invalid audit JSON".into(),
                })?;
            }
        }
        out.push(v);
    }
    Ok(out.into())
}

pub struct ChainSummary {
    pub checked: i64,
    pub valid: bool,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub first_invalid: Option<i64>,
    pub key_version: &'static str,
}

pub async fn chain_summary(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    channel: i64,
) -> Result<ChainSummary, StatementFailure> {
    let actor = proof.actor().get();
    let rows = factory
        .run_admin_read_contract(proof, &sql::VERIFY_CHAIN, &[&channel, &actor])
        .await?;
    let mut out = ChainSummary {
        checked: 0,
        valid: true,
        from: None,
        to: None,
        first_invalid: None,
        key_version: "v2",
    };
    for row in rows {
        let id: i64 = row.try_get(0).map_err(|_| result_error())?;
        let valid: bool = row.try_get(1).map_err(|_| result_error())?;
        out.checked += 1;
        out.from = out.from.or(Some(id));
        out.to = Some(id);
        if !valid {
            out.valid = false;
            out.first_invalid = out.first_invalid.or(Some(id));
        }
    }
    let rows = factory
        .run_admin_read_contract(proof, &sql::VERIFY_HMAC_KEY, &[&actor])
        .await?;
    let has: bool = rows
        .first()
        .ok_or_else(result_error)?
        .try_get(0)
        .map_err(|_| result_error())?;
    if has {
        out.key_version = "v3";
    }
    Ok(out)
}

/// Same ordered notary, chain and anchor checks as frozen Go. A broken or
/// truncated chain never receives anchor verdicts derived from that evidence.
pub async fn verify(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    channel: i64,
) -> Result<serde_json::Value, StatementFailure> {
    use serde_json::{json, Value};
    let actor = proof.actor().get();
    let rows = factory
        .run_admin_read_contract(proof, &sql::VERIFY_NOTARY, &[&channel, &actor])
        .await?;
    let notary = rows
        .first()
        .and_then(|r| r.try_get::<_, Option<String>>(0).ok().flatten())
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| {
            let checksum = v.get("checksum")?.as_str()?.to_owned();
            if checksum.is_empty() {
                return None;
            }
            let id = match v.get("id") {
                None | Some(Value::Null) => 0,
                Some(id) => id.as_i64()?,
            };
            Some(json!({"id": id, "checksum": checksum}))
        });
    let rows = factory
        .run_admin_read_contract(proof, &sql::VERIFY_LIVE_HEAD, &[&channel, &actor])
        .await?;
    let live = if let Some(row) = rows.first() {
        Some(json!({
            "id": row.try_get::<_, i64>(0).map_err(|_| result_error())?,
            "checksum": row.try_get::<_, String>(1).map_err(|_| result_error())?,
        }))
    } else {
        None
    };
    let mut truncated = false;
    if let Some(ref notary) = notary {
        let id = notary["id"].as_i64().ok_or_else(result_error)?;
        if live
            .as_ref()
            .and_then(|v| v["id"].as_i64())
            .is_none_or(|last| last < id)
        {
            truncated = true;
        } else {
            let rows = factory
                .run_admin_read_contract(proof, &sql::VERIFY_NOTARY_MATCH, &[&channel, &id, &actor])
                .await?;
            let sum = rows
                .first()
                .and_then(|r| r.try_get::<_, Option<String>>(0).ok().flatten());
            truncated = sum.as_deref() != notary["checksum"].as_str();
        }
    }
    let summary = chain_summary(factory, proof, channel).await?;
    let mut out = json!({
        "channelId": channel,
        "checked": summary.checked,
        "fromId": summary.from,
        "toId": summary.to,
        "chainValid": summary.valid,
        "firstInvalid": summary.first_invalid,
        "keyVersion": summary.key_version,
        "truncationDetected": truncated,
    });
    if let Some(notary) = notary {
        out["notarizedHead"] = notary;
    }
    if let Some(live) = live {
        out["liveHead"] = live;
    }
    if truncated || !summary.valid {
        return Ok(out);
    }
    let rows = factory
        .run_admin_read_contract(proof, &sql::VERIFY_ANCHORS, &[&channel, &actor])
        .await?;
    let mut anchors = Vec::new();
    for row in rows {
        anchors.push(json!({
            "anchorId": row.try_get::<_, i64>(0).map_err(|_| result_error())?,
            "idFrom": row.try_get::<_, i64>(1).map_err(|_| result_error())?,
            "idTo": row.try_get::<_, i64>(2).map_err(|_| result_error())?,
            "valid": row.try_get::<_, bool>(3).map_err(|_| result_error())?,
            "reconciledFromPurge": row.try_get::<_, i32>(4).map_err(|_| result_error())?,
            "revisionsUnchained": row.try_get::<_, i32>(5).map_err(|_| result_error())?,
        }));
    }
    out["anchors"] = anchors.into();
    Ok(out)
}

pub async fn enabled(factory: &TxFactory) -> Result<bool, StatementFailure> {
    let rows = factory
        .run_public_read_contract(&sql::COMPLIANCE_ENABLED, &[])
        .await?;
    rows.first()
        .ok_or_else(result_error)?
        .try_get(0)
        .map_err(|_| result_error())
}
