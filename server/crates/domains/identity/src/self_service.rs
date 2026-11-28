//! Mailserver-local F21 self-service queries. The verified principal is the owner;
//! HTTP input can never construct it. Contract: ../SELF_SERVICE.md.
use crate::issuance::object;
use crate::sql;
use serde_json::json;
use setjoin_authz::principals::{MutateCapability, ReadCapability, TxFactory, UserPrincipal};
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::CommandEnvelope,
    ids::{Digest, OperationId},
};
use setjoin_pg::{CommandOutcome, ReceiptCommand, StatementFailure};
use sha2::{Digest as _, Sha256};
use std::time::{Duration, Instant};

fn actor_bound_operation(operation: [u8; 16], actor: i64) -> OperationId {
    let mut op_hex = String::with_capacity(32);
    for b in operation {
        use std::fmt::Write as _;
        let _ = write!(&mut op_hex, "{b:02x}");
    }
    let digest = Sha256::digest(format!("{op_hex}:{actor}").as_bytes());
    let mut bound = [0u8; 16];
    bound.copy_from_slice(&digest[..16]);
    OperationId(bound)
}

fn preserve_operation_id<T>(
    outcome: CommandOutcome<T, StatementFailure>,
    operation: [u8; 16],
) -> CommandOutcome<T, StatementFailure> {
    match outcome {
        CommandOutcome::Committed(value) => CommandOutcome::Committed(value),
        CommandOutcome::RolledBack(error) => CommandOutcome::RolledBack(error),
        CommandOutcome::Unknown { .. } => CommandOutcome::Unknown {
            operation: OperationId(operation),
        },
    }
}

fn user_envelope(user: &UserPrincipal, operation: [u8; 16], tag: &str) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: actor_bound_operation(operation, user.user().get()),
        authority: AuthorityKey {
            actor: user.user(),
            scope: ResourceScope::User(user.user()),
            generation: user.generation(),
        },
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(tag.as_bytes()).into()),
        command: (),
    }
}

fn default_deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

/// Public certificate metadata only; the SELECT never reads private_key_enc.
pub struct UserCertificate {
    pub id: i64,
    pub label: String,
    pub pem: String,
    pub is_default: bool,
}

/// Parse independently of the uploaded certificate, as frozen Go does. Key
/// decoding/validation belongs to OpenSSL; no private arithmetic is implemented.
pub fn smime_private_key_parses(der: &[u8]) -> bool {
    use openssl::{
        nid::Nid,
        pkey::{Id, PKey},
    };
    let Ok(key) = PKey::private_key_from_der(der) else {
        return false;
    };
    match key.id() {
        Id::RSA => key.rsa().and_then(|rsa| rsa.check_key()).unwrap_or(false),
        Id::EC => key.ec_key().ok().is_some_and(|ec| {
            matches!(
                ec.group().curve_name(),
                Some(Nid::SECP224R1 | Nid::X9_62_PRIME256V1 | Nid::SECP384R1 | Nid::SECP521R1)
            )
        }),
        Id::ED25519 | Id::X25519 => true,
        _ => false,
    }
}

/// Frozen Go's whole upload transaction: one owned upsert. The key is encrypted
/// by pgcrypto under the executor's trusted configuration GUC, never a body key.
#[allow(clippy::too_many_arguments)]
pub async fn user_certificate_store(
    factory: &TxFactory,
    principal: &UserPrincipal,
    label: &str,
    cert: &str,
    key: &str,
    before: i64,
    after: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let user = principal.user().get();
    let envelope = user_envelope(principal, operation, "self-service.cert.store");
    factory
        .run_user_write_contract_pipelined(
            principal,
            &envelope,
            default_deadline(),
            &sql::SELF_SERVICE_L47,
            &[&user, &label, &cert, &key, &before, &after],
            Some(ReceiptCommand {
                family: "F21",
                command: "self-service.cert.store",
            }),
            |_| Ok(()),
        )
        .await
}

/// The reducer owns delete + survivor promotion as one atomic transaction.
/// Failed phase verdicts abort this outer transaction too, leaving no receipt.
pub async fn user_certificate_delete(
    factory: &TxFactory,
    principal: &UserPrincipal,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let user = principal.user().get();
    let envelope = user_envelope(principal, operation, "self-service.cert.delete");
    let receipt_op = envelope.operation;
    let outcome = factory
        .run_user_write(principal, &envelope, default_deadline(), async move |tx| {
            let rows = tx
                .query_contract(&sql::SELF_SERVICE_L67, &[&user, &id])
                .await?;
            let phase = rows
                .first()
                .and_then(|r| r.try_get::<_, String>(0).ok())
                .unwrap_or_else(|| "delete".into());
            if phase != "ok" {
                return Err(StatementFailure {
                    sqlstate: None,
                    message: phase,
                    hint: None,
                });
            }
            tx.record_receipt(
                receipt_op,
                ReceiptCommand {
                    family: "F21",
                    command: "self-service.cert.delete",
                },
            )
            .await?;
            Ok(())
        })
        .await;
    preserve_operation_id(outcome, operation)
}

pub async fn user_certificate_default(
    factory: &TxFactory,
    principal: &UserPrincipal,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let user = principal.user().get();
    let envelope = user_envelope(principal, operation, "self-service.cert.default");
    let receipt_op = envelope.operation;
    let outcome = factory
        .run_user_write(principal, &envelope, default_deadline(), async move |tx| {
            let rows = tx
                .query_contract(&sql::SELF_SERVICE_L83, &[&user, &id])
                .await?;
            let phase = rows
                .first()
                .and_then(|r| r.try_get::<_, String>(0).ok())
                .unwrap_or_else(|| "lookup".into());
            if phase != "ok" {
                return Err(StatementFailure {
                    sqlstate: None,
                    message: phase,
                    hint: None,
                });
            }
            tx.record_receipt(
                receipt_op,
                ReceiptCommand {
                    family: "F21",
                    command: "self-service.cert.default",
                },
            )
            .await?;
            Ok(())
        })
        .await;
    preserve_operation_id(outcome, operation)
}

pub async fn user_certificates(
    factory: &TxFactory,
    principal: &UserPrincipal,
) -> Result<Vec<UserCertificate>, StatementFailure> {
    let user = principal.user().get();
    let mut tx = factory.begin_user_read(principal).await?;
    let result = tx
        .query_iterated_contract(&sql::SELF_SERVICE_L94, &[&user])
        .await;
    let rows = match result {
        Ok(rows) => {
            let _ = tx.finish().await;
            rows
        }
        // Go ignores pgx's deferred permission failure and encodes a nil list.
        Err(error) if error.sqlstate.as_deref() == Some("42501") => Vec::new(),
        Err(error) => return Err(error),
    };
    Ok(rows
        .iter()
        .filter_map(|row| {
            Some(UserCertificate {
                id: row.try_get(0).ok()?,
                label: row.try_get(1).ok()?,
                pem: row.try_get(2).ok()?,
                is_default: row.try_get(3).ok()?,
            })
        })
        .collect())
}

/// Recipient metadata is user-owned; the PEM is used only for the capability hint.
pub struct RecipientCertificate {
    pub id: i64,
    pub email: String,
    pub label: String,
    pub source: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub fingerprint: String,
    pub pem: String,
}

pub async fn recipient_certificates(
    factory: &TxFactory,
    principal: &UserPrincipal,
) -> Result<Vec<RecipientCertificate>, StatementFailure> {
    let user = principal.user().get();
    let mut tx = factory.begin_user_read(principal).await?;
    let result = tx
        .query_iterated_contract(&sql::SELF_SERVICE_L124, &[&user])
        .await;
    let rows = match result {
        Ok(rows) => {
            let _ = tx.finish().await;
            rows
        }
        // Frozen pgx surfaces this at Rows.Next; Go omits Rows.Err.
        Err(error) if error.sqlstate.as_deref() == Some("42501") => Vec::new(),
        Err(error) => return Err(error),
    };
    Ok(rows
        .iter()
        .filter_map(|r| {
            Some(RecipientCertificate {
                id: r.try_get(0).ok()?,
                email: r.try_get(1).ok()?,
                label: r.try_get(2).ok()?,
                source: r.try_get(3).ok()?,
                before: r.try_get(4).ok()?,
                after: r.try_get(5).ok()?,
                fingerprint: r.try_get(6).ok()?,
                pem: r.try_get(7).ok()?,
            })
        })
        .collect())
}

/// Single owned dedup upsert; Go preserves original PEM/dates/first_seen on conflict.
#[allow(clippy::too_many_arguments)]
pub async fn recipient_certificate_store(
    factory: &TxFactory,
    principal: &UserPrincipal,
    email: &str,
    cert: &str,
    fingerprint: &str,
    before: i64,
    after: i64,
    label: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let user = principal.user().get();
    let envelope = user_envelope(principal, operation, "self-service.recipient.store");
    factory
        .run_user_write_contract_pipelined(
            principal,
            &envelope,
            default_deadline(),
            &sql::SELF_SERVICE_L150,
            &[&user, &email, &cert, &fingerprint, &before, &after, &label],
            Some(ReceiptCommand {
                family: "F21",
                command: "self-service.recipient.store",
            }),
            |_| Ok(()),
        )
        .await
}

/// One ownership-scoped DELETE; a missing row aborts the infrastructure receipt.
pub async fn recipient_certificate_delete(
    factory: &TxFactory,
    principal: &UserPrincipal,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let user = principal.user().get();
    let envelope = user_envelope(principal, operation, "self-service.recipient.delete");
    let receipt_op = envelope.operation;
    let outcome = factory
        .run_user_write(principal, &envelope, default_deadline(), async move |tx| {
            let rows = tx
                .query_contract(&sql::SELF_SERVICE_L164, &[&user, &id])
                .await?;
            match rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()) {
                Some(true) => {}
                other => {
                    return Err(StatementFailure {
                        sqlstate: None,
                        hint: None,
                        message: if other == Some(false) {
                            "not-found"
                        } else {
                            "invalid delete result"
                        }
                        .into(),
                    });
                }
            }
            tx.record_receipt(
                receipt_op,
                ReceiptCommand {
                    family: "F21",
                    command: "self-service.recipient.delete",
                },
            )
            .await?;
            Ok(())
        })
        .await;
    preserve_operation_id(outcome, operation)
}

/// Frozen Go's latest non-completed job. Every lookup remains actor-owned;
/// any query/scan error is the status:none projection, as in QueryRow.Scan.
pub async fn migration_status(factory: &TxFactory, principal: &UserPrincipal) -> Option<String> {
    let user = principal.user().get();
    let mut tx = factory.begin_user_read(principal).await.ok()?;
    let rows = tx
        .query_iterated_contract(&sql::SELF_SERVICE_L177, &[&user])
        .await
        .ok()?;
    let _ = tx.finish().await;
    let row = rows.first()?;
    let id: i64 = row.try_get(0).ok()?;
    let source: String = row.try_get(1).ok()?;
    let status: String = row.try_get(2).ok()?;
    let strategy: String = row.try_get(3).ok()?;
    let progress: Option<String> = row.try_get(4).ok()?;
    let errors: Option<String> = row.try_get(5).ok()?;
    let started: Option<String> = row.try_get(6).ok()?;
    let completed: Option<String> = row.try_get(7).ok()?;
    let created: String = row.try_get(8).ok()?;
    let quoted = |value: serde_json::Value| compact_raw(&value.to_string());
    Some(format!(
        "{{\"completed_at\":{},\"conflict_strategy\":{},\"created_at\":{},\"error_log\":{},\"id\":{},\"progress\":{},\"source_type\":{},\"started_at\":{},\"status\":{}}}\n",
        quoted(json!(completed)),
        quoted(json!(strategy)),
        quoted(json!(created)),
        compact_raw(errors.as_deref().unwrap_or("null")),
        id,
        compact_raw(progress.as_deref().unwrap_or("null")),
        quoted(json!(source)),
        quoted(json!(started)),
        quoted(json!(status))
    ))
}

/// One owned history deletion via owning migration reducer.
pub async fn migration_history_delete(
    factory: &TxFactory,
    principal: &UserPrincipal,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let user = principal.user().get();
    let envelope = user_envelope(principal, operation, "self-service.migration.delete");
    factory
        .run_user_write_contract_pipelined(
            principal,
            &envelope,
            default_deadline(),
            &sql::SELF_MIGRATION_HISTORY_DELETE,
            &[&user],
            Some(ReceiptCommand {
                family: "F21",
                command: "self-service.migration.delete",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get::<_, i64>(0).ok())
                    .ok_or_else(|| StatementFailure {
                        sqlstate: None,
                        hint: None,
                        message: "invalid history delete result".into(),
                    })
            },
        )
        .await
}

/// Frozen self-service start accepts any owned mailbox, including non-primary.
pub async fn migration_mailbox(factory: &TxFactory, principal: &UserPrincipal) -> Option<i64> {
    let user = principal.user().get();
    factory
        .run_user_read_contract(principal, &sql::SELF_SERVICE_L210, &[&user])
        .await
        .ok()?
        .first()?
        .try_get(0)
        .ok()
}

/// Control lookup errors project as no job, matching frozen Go's QueryRow.
pub async fn migration_cancel_job(factory: &TxFactory, principal: &UserPrincipal) -> Option<i64> {
    let user = principal.user().get();
    factory
        .run_user_read_contract(principal, &sql::SELF_SERVICE_L216, &[&user])
        .await
        .ok()?
        .first()?
        .try_get(0)
        .ok()
}

pub async fn migration_pause_job(factory: &TxFactory, principal: &UserPrincipal) -> Option<i64> {
    let user = principal.user().get();
    factory
        .run_user_read_contract(principal, &sql::SELF_SERVICE_L221, &[&user])
        .await
        .ok()?
        .first()?
        .try_get(0)
        .ok()
}

pub async fn migration_paused_job(factory: &TxFactory, principal: &UserPrincipal) -> Option<i64> {
    let user = principal.user().get();
    factory
        .run_user_read_contract(principal, &sql::SELF_SERVICE_L226, &[&user])
        .await
        .ok()?
        .first()?
        .try_get(0)
        .ok()
}

/// Upload accepts any job phase, but only an actor-owned job.
pub async fn migration_job_owned(factory: &TxFactory, principal: &UserPrincipal, job: i64) -> bool {
    let user = principal.user().get();
    factory
        .run_user_read_contract(principal, &sql::SELF_SERVICE_L232, &[&user, &job])
        .await
        .is_ok_and(|rows| !rows.is_empty())
}

#[allow(clippy::too_many_arguments)]
pub async fn migration_job_insert(
    factory: &TxFactory,
    principal: &UserPrincipal,
    source: &str,
    config: Option<&[u8]>,
    mailbox: i64,
    strategy: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let user = principal.user().get();
    let envelope = user_envelope(principal, operation, "self-service.migration.start");
    factory
        .run_user_write_contract_pipelined(
            principal,
            &envelope,
            default_deadline(),
            &sql::SELF_MIGRATION_JOB_INSERT,
            &[&user, &source, &config, &mailbox, &strategy],
            Some(ReceiptCommand {
                family: "F21",
                command: "self-service.migration.start",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get::<_, Option<i64>>(0).ok())
                    .flatten()
                    .ok_or_else(|| StatementFailure {
                        sqlstate: None,
                        hint: None,
                        message: "invalid migration insert result".into(),
                    })
            },
        )
        .await
}

/// Go's per-user webhook subscription ceiling (`maxUserWebhookSubscriptions`).
pub const MAX_WEBHOOK_SUBSCRIPTIONS_PER_USER: i64 = 20;

/// `requireWebhookCap` count: the caller's own rows, read on the request pool
/// before the handler decodes the body. Failure is fail-closed (503).
pub async fn webhook_count(
    factory: &TxFactory,
    principal: &UserPrincipal,
) -> Result<i64, StatementFailure> {
    let user = principal.user().get();
    let rows = factory
        .run_user_read_contract(principal, &sql::SELF_SERVICE_L255, &[&user])
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(|| StatementFailure {
            sqlstate: None,
            message: "missing webhook count".into(),
            hint: None,
        })
}

/// Self-service subscriptions expose metadata only. The creator comes from the
/// verified session; Go skips scan failures and ignores deferred iteration errors.
pub async fn webhooks(
    factory: &TxFactory,
    principal: &UserPrincipal,
) -> Result<String, StatementFailure> {
    let user = principal.user().get();
    let mut tx = factory.begin_user_read(principal).await?;
    let rows = match tx
        .query_iterated_contract(&sql::SELF_WEBHOOK_LIST, &[&user])
        .await
    {
        Ok(rows) => {
            let _ = tx.finish().await;
            rows
        }
        // pgx exposes the permission failure at Rows.Next, which this frozen
        // list handler never checks. Our driver may receive it before metadata.
        Err(error) if error.sqlstate.as_deref() == Some("42501") => Vec::new(),
        Err(error) => return Err(error),
    };
    let values = rows
        .iter()
        .filter_map(|row| {
            let types: String = row.try_get(2).ok()?;
            // json.Unmarshal into []string keeps a nil slice for non-arrays and
            // zero-value elements when a stored element is not a string.
            let types = match serde_json::from_str::<serde_json::Value>(&types).ok()? {
                serde_json::Value::Array(xs) => {
                    json!(xs
                        .iter()
                        .map(|x| x.as_str().unwrap_or(""))
                        .collect::<Vec<_>>())
                }
                _ => serde_json::Value::Null,
            };
            Some(object(&[
                ("id", json!(row.try_get::<_, i64>(0).ok()?)),
                ("url", json!(row.try_get::<_, String>(1).ok()?)),
                ("eventTypes", types),
                ("scope", json!(row.try_get::<_, String>(3).ok()?)),
                ("isActive", json!(row.try_get::<_, bool>(4).ok()?)),
                ("createdAt", json!(row.try_get::<_, String>(5).ok()?)),
                ("updatedAt", json!(row.try_get::<_, String>(6).ok()?)),
            ]))
        })
        .collect::<Vec<_>>();
    Ok(format!("[{}]\n", values.join(",")))
}

/// Go's whole webhook-create transaction via the owning webhook reducer.
#[allow(clippy::too_many_arguments)]
pub async fn webhook_create(
    factory: &TxFactory,
    principal: &UserPrincipal,
    url: &str,
    events: &str,
    sealed: &[u8],
    key: &str,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let user = principal.user().get();
    let envelope = user_envelope(principal, operation, "self-service.webhook.create");
    factory
        .run_user_write_contract_pipelined(
            principal,
            &envelope,
            default_deadline(),
            &sql::SELF_WEBHOOK_CREATE,
            &[&user, &url, &events, &sealed, &key],
            Some(ReceiptCommand {
                family: "F21",
                command: "self-service.webhook.create",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(|| StatementFailure {
                        sqlstate: None,
                        message: "missing webhook insert result".into(),
                        hint: None,
                    })
            },
        )
        .await
}

/// One owned DELETE via the owning webhook reducer.
pub async fn webhook_delete(
    factory: &TxFactory,
    principal: &UserPrincipal,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let user = principal.user().get();
    let envelope = user_envelope(principal, operation, "self-service.webhook.delete");
    factory
        .run_user_write_contract_pipelined(
            principal,
            &envelope,
            default_deadline(),
            &sql::SELF_WEBHOOK_DELETE,
            &[&user, &id],
            Some(ReceiptCommand {
                family: "F21",
                command: "self-service.webhook.delete",
            }),
            |rows| {
                Ok(rows
                    .first()
                    .and_then(|r| r.try_get::<_, bool>(0).ok())
                    .unwrap_or(false))
            },
        )
        .await
}

/// The authenticated user's active app passwords; no raw token or stored hash.
/// Frozen Go skips row-scan failures and ignores deferred iteration errors.
pub async fn app_passwords(
    factory: &TxFactory,
    principal: &UserPrincipal,
) -> Result<String, StatementFailure> {
    let user = principal.user().get();
    let mut tx = factory.begin_user_read(principal).await?;
    let rows = tx
        .query_iterated_contract(&sql::SELF_APP_PASSWORD_LIST, &[&user])
        .await?;
    let _ = tx.finish().await;
    let values = rows
        .iter()
        .filter_map(|row| {
            let id: i64 = row.try_get(0).ok()?;
            let name: String = row.try_get(1).ok()?;
            let created: String = row.try_get(2).ok()?;
            let used: Option<String> = row.try_get(3).ok()?;
            let expires: Option<String> = row.try_get(4).ok()?;
            let mut fields = vec![
                ("id", json!(id)),
                ("name", json!(name)),
                ("createdAt", json!(created)),
            ];
            if let Some(used) = used {
                fields.push(("lastUsedAt", json!(used)));
            }
            if let Some(expires) = expires {
                fields.push(("expiresAt", json!(expires)));
            }
            Some(object(&fields))
        })
        .collect::<Vec<_>>();
    Ok(format!("[{}]\n", values.join(",")))
}

/// Go's one-statement app-password creation. The plaintext is released only
/// after explicit COMMIT; the database stores its SHA-256 digest and owner.
/// Outer Err is entropy failure, before any database write.
#[allow(clippy::result_unit_err)]
pub async fn app_password_create(
    factory: &TxFactory,
    principal: &UserPrincipal,
    name: &str,
    label: &str,
    operation: [u8; 16],
) -> Result<CommandOutcome<String, StatementFailure>, ()> {
    use ring::rand::SecureRandom;
    let mut random = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| ())?;
    let token = format!(
        "mail-ap-{}",
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
    let user = principal.user().get();
    let envelope = user_envelope(principal, operation, "self-service.app.create");
    let outcome = factory
        .run_user_write_contract_pipelined(
            principal,
            &envelope,
            default_deadline(),
            &sql::SELF_SERVICE_L418,
            &[&user, &name, &label, &hash],
            Some(ReceiptCommand {
                family: "F21",
                command: "self-service.app.create",
            }),
            |_| Ok(()),
        )
        .await;
    Ok(match outcome {
        CommandOutcome::Committed(()) => CommandOutcome::Committed(token),
        CommandOutcome::RolledBack(error) => CommandOutcome::RolledBack(error),
        CommandOutcome::Unknown { .. } => CommandOutcome::Unknown {
            operation: OperationId(operation),
        },
    })
}

/// Soft-revoke only a live credential owned by the authenticated user.
/// A committed no-op is Go's 404; an uncertain transaction is never success.
pub async fn app_password_revoke(
    factory: &TxFactory,
    principal: &UserPrincipal,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let user = principal.user().get();
    let envelope = user_envelope(principal, operation, "self-service.app.revoke");
    factory
        .run_user_write_contract_pipelined(
            principal,
            &envelope,
            default_deadline(),
            &sql::SELF_SERVICE_L454,
            &[&user, &id],
            Some(ReceiptCommand {
                family: "F21",
                command: "self-service.app.revoke",
            }),
            |rows| Ok(!rows.is_empty()),
        )
        .await
}

/// Registered default-enabled compose switches. Go caches these shared rows;
/// a missing row uses its compiled default, and a failed advisory read is OFF.
pub async fn advisory_enabled(factory: &TxFactory, key: &str) -> bool {
    factory
        .run_public_read_contract(&sql::SELF_SERVICE_L465, &[&key])
        .await
        .ok()
        .map(|rows| {
            rows.first()
                .is_none_or(|row| row.try_get(0).unwrap_or(false))
        })
        .unwrap_or(false)
}

/// Resolve the account slot from the verified actor, never a body mailbox ID.
pub async fn primary_mailbox(factory: &TxFactory, principal: &UserPrincipal) -> Option<i64> {
    let user = principal.user().get();
    factory
        .run_user_read_contract(principal, &sql::SELF_SERVICE_L479, &[&user])
        .await
        .ok()?
        .first()?
        .try_get(0)
        .ok()
}

/// Read-only DLP advisory: the existing reducer is the send-time policy seam.
pub async fn dlp_check(
    factory: &TxFactory,
    cap: &ReadCapability,
    mailbox: i64,
    recipients: &str,
    subject: &str,
    text: &str,
    html: &str,
) -> Option<String> {
    factory
        .run_mailbox_read_contract(
            cap,
            &sql::SELF_SERVICE_L501,
            &[&mailbox, &recipients, &subject, &text, &html],
        )
        .await
        .ok()?
        .first()?
        .try_get(0)
        .ok()
}

/// `encoding/json` compacts RawMessage without sorting its nested object keys.
/// Input comes from PostgreSQL JSONB, so token validation belongs to PostgreSQL.
pub fn compact_raw(raw: &str) -> String {
    let (mut quoted, mut escaped) = (false, false);
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if quoted {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch == '"' {
            quoted = true;
            out.push(ch);
        } else if !matches!(ch, ' ' | '\t' | '\r' | '\n') {
            out.push(ch);
        }
    }
    out.replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// Format the org-chart JSON wire body from gateway-fetched worker rows.
pub fn format_org_chart(managers: &str, reports: &str, user: &str) -> String {
    format!(
        "{{\"managers\":{},\"reports\":{},\"user\":{}}}\n",
        compact_raw(managers),
        compact_raw(reports),
        compact_raw(user),
    )
}

/// Compose warnings are advisory. Preserve Go's warning-group order, duplicate
/// recipients, per-user preference, dates-only OOO seam and swallowed read errors.
pub async fn mailtips(
    factory: &TxFactory,
    principal: &UserPrincipal,
    mailbox_read: Option<(i64, &ReadCapability)>,
    recipients: &str,
    from: &str,
    delegate_send_as_allowed: bool,
) -> String {
    use std::collections::{HashMap, HashSet};
    let mut warnings = Vec::new();
    if recipients.is_empty() && from.is_empty() {
        return "{\"warnings\":[]}\n".into();
    }
    let clean = recipients
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    if clean.len() > 25 {
        warnings.push(json!({"type":"large_audience","message":format!("Your message will be sent to {} recipients",clean.len()),"count":clean.len()}));
    }
    if !clean.is_empty() {
        let user = principal.user().get();
        let external = advisory_enabled(factory, "feature.external_sender_warn").await
            && factory
                .run_user_read_contract(principal, &sql::SELF_SERVICE_L609, &[&user])
                .await
                .ok()
                .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
                .unwrap_or(false);
        if external {
            // Go ranges a map: ordering between distinct domains is unspecified.
            let mut groups = HashMap::<String, Vec<&str>>::new();
            for recipient in &clean {
                if let Some((_, domain)) = recipient.split_once('@') {
                    groups
                        .entry(setjoin_authz::address::lower(domain))
                        .or_default()
                        .push(recipient);
                }
            }
            if !groups.is_empty() {
                let names = groups.keys().cloned().collect::<Vec<_>>();
                let local = factory
                    .run_public_read_contract(&sql::SELF_SERVICE_L631, &[&names])
                    .await
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|r| r.try_get::<_, String>(0).ok())
                    .collect::<HashSet<_>>();
                for (domain, recipients) in groups {
                    if !local.contains(&domain) {
                        for recipient in recipients {
                            warnings.push(json!({"type":"external_recipient","recipient":recipient,"domain":domain}));
                        }
                    }
                }
            }
        }
        if let Some((mailbox, cap)) = mailbox_read {
            let emails = json!(clean).to_string();
            if let Ok(rows) = factory
                .run_mailbox_read_contract(cap, &sql::SELF_SERVICE_L653, &[&mailbox, &emails])
                .await
            {
                if let Some(raw) = rows.first().and_then(|r| r.try_get::<_, String>(0).ok()) {
                    #[derive(serde::Deserialize)]
                    struct Ooo {
                        #[serde(default)]
                        email: Option<String>,
                        until: Option<String>,
                    }
                    if let Ok(rows) = serde_json::from_str::<Vec<Ooo>>(&raw) {
                        for row in rows {
                            warnings.push(json!({"type":"ooo","recipient":row.email.unwrap_or_default(),"until":row.until}));
                        }
                    }
                }
            }
        }
    }
    if !from.is_empty() && !delegate_send_as_allowed && from != principal.audit_meta().email {
        warnings.push(json!({"type":"no_send_as","message":format!("You don't have permission to send as {from}"),"from":from}));
    }
    object(&[("warnings", json!(warnings))]) + "\n"
}

/// Mailbox-keyed MDN publication. Policy, message ownership, deduplication and
/// queue/receipt writes remain in the existing send_read_receipt transaction.
pub async fn read_receipt(
    factory: &TxFactory,
    cap: &MutateCapability,
    mailbox: &setjoin_authz::principals::MailboxPrincipal,
    message: i64,
    consent: bool,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let mb_id = mailbox.mailbox().get();
    let email = mailbox.audit_meta().email.as_str();
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: AuthorityKey {
            actor: mailbox.actor(),
            scope: ResourceScope::Mailbox(mailbox.mailbox()),
            generation: mailbox.generation(),
        },
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(
            Sha256::digest(format!("{message}:{consent}:{email}").as_bytes()).into(),
        ),
        command: (),
    };
    factory
        .run_mailbox_write_contract_pipelined(
            cap,
            &envelope,
            default_deadline(),
            &sql::SELF_READ_RECEIPT_SEND,
            &[&mb_id, &message, &email, &consent],
            Some(ReceiptCommand {
                family: "F21",
                command: "self-service.read-receipt",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get::<_, String>(0).ok())
                    .ok_or_else(|| StatementFailure {
                        sqlstate: None,
                        hint: None,
                        message: "invalid read-receipt result".into(),
                    })
            },
        )
        .await
}
