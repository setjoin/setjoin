//! EmailSubmission request translation (#317, #328), using the submission capability.
use super::envelope::single_call_with_capability;
use super::get::parse_id;
use super::submission_input::{self, Failure};
use serde_json::Value;

pub const CAPABILITY: &str = "urn:ietf:params:jmap:submission";
pub(crate) struct SubmissionRequest {
    pub raw_account_id: String,
    #[allow(dead_code)]
    pub client_id: String,
    pub args: Arguments,
}
pub(crate) enum Arguments {
    Rejected {
        method: &'static str,
        error: Failure,
        early: bool,
    },
    Get {
        ids: Option<Vec<i64>>,
        bad: Vec<String>,
    },
    Cancel(Result<i64, &'static str>),
    Set(Result<Option<String>, String>),
    Query {
        filter: Option<String>,
        position: i32,
        limit: i32,
    },
}
impl Arguments {
    pub fn method(&self) -> &'static str {
        match self {
            Self::Rejected { method, .. } => method,
            Self::Get { .. } => "EmailSubmission/get",
            Self::Cancel(_) => "EmailSubmission/cancel",
            Self::Set(_) => "EmailSubmission/set",
            Self::Query { .. } => "EmailSubmission/query",
        }
    }
}
impl SubmissionRequest {
    pub(super) fn early_error(&self) -> Option<&Failure> {
        match &self.args {
            Arguments::Rejected {
                error, early: true, ..
            } => Some(error),
            _ => None,
        }
    }
}
#[allow(dead_code)]
pub(crate) fn classify(body: &[u8]) -> Option<SubmissionRequest> {
    let (method, call) = [
        "EmailSubmission/set",
        "EmailSubmission/cancel",
        "EmailSubmission/get",
        "EmailSubmission/query",
    ]
    .into_iter()
    .find_map(|method| {
        single_call_with_capability(body, method, CAPABILITY).map(|call| (method, call))
    })?;
    classify_call(method, &call.raw_args, &call.client_id)
}

pub(crate) fn classify_call(
    method: &str,
    raw_args: &str,
    client_id: &str,
) -> Option<SubmissionRequest> {
    let method: &'static str = match method {
        "EmailSubmission/set" => "EmailSubmission/set",
        "EmailSubmission/cancel" => "EmailSubmission/cancel",
        "EmailSubmission/get" => "EmailSubmission/get",
        "EmailSubmission/query" => "EmailSubmission/query",
        _ => return None,
    };
    let rejected = |error| SubmissionRequest {
        raw_account_id: String::new(),
        client_id: client_id.to_owned(),
        args: Arguments::Rejected {
            method,
            error,
            early: true,
        },
    };
    let input = match submission_input::decode(method, raw_args) {
        Ok(v) => v,
        Err(e) => return Some(rejected(e)),
    };
    let raw_account_id = input.account;
    let args = match method {
        "EmailSubmission/get" => {
            let raw = input.ids.unwrap_or_default();
            let mut ids = Vec::new();
            let mut bad = Vec::new();
            for id in &raw {
                match parse_id(id) {
                    Some(id) => ids.push(id),
                    None => bad.push(id.clone()),
                }
            }
            Arguments::Get {
                ids: (!raw.is_empty()).then_some(ids),
                bad,
            }
        }
        "EmailSubmission/query" => match i32::try_from(input.position) {
            Ok(position) => Arguments::Query {
                filter: input.filter,
                position,
                limit: if (1..=256).contains(&input.limit) {
                    input.limit as i32
                } else {
                    50
                },
            },
            Err(_) => Arguments::Rejected {
                method,
                error: Failure {
                    kind: "serverFail",
                    status: 500,
                    detail: "database error".into(),
                },
                early: false,
            },
        },
        "EmailSubmission/cancel" => Arguments::Cancel(if input.email.is_empty() {
            Err("emailId is required")
        } else {
            parse_id(&input.email).ok_or("invalid emailId")
        }),
        "EmailSubmission/set" => {
            let create = match input.create {
                None => Ok(None),
                Some(raw) if raw == "null" => Ok(Some("{}".into())),
                Some(raw) => match serde_json::from_str::<Value>(&raw).ok()? {
                    Value::Object(_) => Ok(Some(raw)),
                    value => {
                        let kind = match value {
                            Value::Array(_) => "array",
                            Value::String(_) => "string",
                            Value::Bool(_) => "bool",
                            _ => "number",
                        };
                        Err(format!("json: cannot unmarshal {kind} into Go value of type map[string]json.RawMessage"))
                    }
                },
            };
            Arguments::Set(create)
        }
        _ => unreachable!(),
    };
    Some(SubmissionRequest {
        raw_account_id,
        client_id: client_id.to_owned(),
        args,
    })
}

/// Render a claimed call for batch/single dispatch (`(name, payload_json)`).
/// Once claimed, a database failure is a native JMAP error; an ambiguous
/// commit carries its operation ID and is never replayed.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn response_call(
    tx_factory: &setjoin_authz::principals::TxFactory,
    read_cap: &setjoin_authz::principals::ReadCapability,
    submit_cap: &setjoin_authz::principals::SubmitCapability,
    auth: &setjoin_pg::MailboxAuthContext,
    worker: &setjoin_pg::ScopedExecutor,
    services: Option<&super::JmapServices>,
    request: SubmissionRequest,
    operation: [u8; 16],
    digest: [u8; 32],
) -> (&'static str, String) {
    use super::reply;
    let method = request.args.method();
    let raw = match request.args {
        Arguments::Rejected { error, .. } => {
            return (
                "error",
                reply::jmap_error_json(error.kind, error.status, &error.detail),
            )
        }
        Arguments::Get { ids, bad } => {
            setjoin_jmap::submission::get(tx_factory, read_cap, ids.as_deref())
                .await
                .and_then(|raw| {
                    super::get::add_not_found(&raw, &bad).ok_or_else(|| {
                        setjoin_pg::StatementFailure {
                            hint: None,
                            sqlstate: None,
                            message: "invalid EmailSubmission/get JSON".into(),
                        }
                    })
                })
        }
        Arguments::Query {
            filter,
            position,
            limit,
        } => {
            setjoin_jmap::submission::query(
                tx_factory,
                read_cap,
                filter.as_deref(),
                position,
                limit,
            )
            .await
        }
        Arguments::Set(Err(detail)) => {
            return (
                "error",
                reply::jmap_error_json("invalidArguments", 400, &detail),
            )
        }
        Arguments::Set(Ok(create)) => {
            let processed = match create.as_deref() {
                Some(raw_create) => {
                    let key_worker = services.map(|s| &s.worker).unwrap_or(worker);
                    let store = services.and_then(|s| s.store.as_deref());
                    let algorithm = services
                        .map_or_else(setjoin_smtp::smime::EncryptAlgorithm::from_env, |s| {
                            s.encrypt_algorithm
                        });
                    Some(
                        super::smime_outbound::process_submissions(
                            key_worker, store, algorithm, auth, raw_create,
                        )
                        .await,
                    )
                }
                None => None,
            };
            let modified_create = processed.as_ref().map(|p| p.modified_create_json.as_str());
            let processed_refs = processed
                .as_ref()
                .and_then(|p| p.processed_refs_json.as_deref());
            let is_encrypted = processed
                .as_ref()
                .and_then(|p| p.is_encrypted_json.as_deref());
            let processed_sizes: &[setjoin_jmap::submission::ProcessedSize] = processed
                .as_ref()
                .map_or(&[], |p| p.processed_sizes.as_slice());
            match worker_submission_create(
                worker,
                submit_cap,
                setjoin_contracts::ids::OperationId(operation),
                modified_create,
                processed_refs,
                is_encrypted,
                processed_sizes,
            )
            .await
            {
                setjoin_pg::CommandOutcome::Committed(raw) => Ok(match &processed {
                    Some(p) if !p.not_created.is_empty() => {
                        super::smime_outbound::merge_not_created(&raw, &p.not_created)
                    }
                    _ => raw,
                }),
                setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(
                    failure,
                )) => Err(failure),
                setjoin_pg::CommandOutcome::RolledBack(_) => {
                    return (
                        "error",
                        reply::jmap_error_json("serverFail", 500, "database error"),
                    )
                }
                setjoin_pg::CommandOutcome::Unknown { operation } => {
                    return (
                        "error",
                        reply::jmap_error_json(
                            "serverFail",
                            500,
                            &format!(
                                "commit outcome unknown; look up operation {}",
                                setjoin_pg::operation_hex(operation)
                            ),
                        ),
                    )
                }
            }
        }
        Arguments::Cancel(Err(detail)) => {
            return (
                "error",
                reply::jmap_error_json("invalidArguments", 400, detail),
            )
        }
        Arguments::Cancel(Ok(email_id)) => {
            let envelope = setjoin_contracts::command::CommandEnvelope {
                operation: setjoin_contracts::ids::OperationId(operation),
                authority: auth.authority(),
                binding: setjoin_db::lifecycle::accepted_contract(),
                payload_digest: setjoin_contracts::ids::Digest(digest),
                command: setjoin_jmap::submission::Submission,
            };
            match setjoin_jmap::submission::cancel(
                tx_factory,
                submit_cap,
                &envelope,
                std::time::Instant::now() + super::COMMAND_DEADLINE,
                email_id,
            )
            .await
            {
                setjoin_pg::CommandOutcome::Committed(raw) => Ok(raw),
                setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(
                    failure,
                )) => Err(failure),
                setjoin_pg::CommandOutcome::RolledBack(_) => {
                    return (
                        "error",
                        reply::jmap_error_json("serverFail", 500, "database error"),
                    )
                }
                setjoin_pg::CommandOutcome::Unknown { operation } => {
                    return (
                        "error",
                        reply::jmap_error_json(
                            "serverFail",
                            500,
                            &format!(
                                "commit outcome unknown; look up operation {}",
                                setjoin_pg::operation_hex(operation)
                            ),
                        ),
                    )
                }
            }
        }
    };
    match raw {
        Ok(raw) => (method, raw),
        Err(failure) if failure.sqlstate.as_deref() == Some("BZ020") => {
            ("error", reply::jmap_error_json("notFound", 500, "notFound"))
        }
        Err(failure) => (
            "error",
            reply::failure_json(setjoin_jmap::classify_failure(&failure))
                .unwrap_or_else(|| reply::jmap_error_json("serverFail", 500, "database error")),
        ),
    }
}

/// Cross-mailbox local-recipient fan-out in `jmap_email_submission_set` (`send` -> `deliver`)
/// executes `SqlScope::WorkerBypass` contracts on `WorkerPool` strictly after the caller
/// proved [`setjoin_authz::principals::SubmitCapability`].
async fn worker_submission_create(
    worker: &setjoin_pg::ScopedExecutor,
    submit_cap: &setjoin_authz::principals::SubmitCapability,
    operation: setjoin_contracts::ids::OperationId,
    create: Option<&str>,
    processed_refs: Option<&str>,
    is_encrypted: Option<&str>,
    processed_sizes: &[setjoin_jmap::submission::ProcessedSize],
) -> setjoin_pg::CommandOutcome<String, setjoin_pg::StatementFailure> {
    let Some(pool) = worker.try_worker_pool() else {
        return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Unavailable);
    };
    let mut tx = match pool.begin_read_write().await {
        Ok(tx) => tx,
        Err(e) => {
            return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(e));
        }
    };
    let mailbox = submit_cap.mailbox().get();
    let actor = submit_cap.actor().get();
    let body: Result<String, setjoin_pg::StatementFailure> = async {
        let res_text = if processed_sizes.is_empty() {
            let rows = tx
                .query_contract(
                    &setjoin_jmap::sql::SUBMISSION_SET,
                    &[&mailbox, &actor, &create, &processed_refs, &is_encrypted],
                )
                .await?;
            setjoin_jmap::submission::decode_submission_result(&rows)?
        } else {
            // Acquire canonical #481 parent locks (`users FOR KEY SHARE -> mailboxes FOR UPDATE`)
            // strictly before locking/updating any child draft `messages` rows (`SUBMISSION_LOCK_DRAFT`),
            // preventing AB-BA deadlocks with concurrent `send()` / mailbox-delete transactions.
            let _ = tx
                .query_contract(&setjoin_jmap::sql::SUBMISSION_PRELOCK_USER, &[&mailbox])
                .await?;
            let _ = tx
                .query_contract(&setjoin_jmap::sql::SUBMISSION_PRELOCK_MAILBOX, &[&mailbox])
                .await?;
            let mut orig_sizes: Vec<(String, i64, String, i64)> = Vec::new();
            for item in processed_sizes {
                let rows = tx
                    .query_contract(
                        &setjoin_jmap::sql::SUBMISSION_LOCK_DRAFT,
                        &[&item.email_id, &mailbox],
                    )
                    .await?;
                if let Some((orig_ref, orig_size)) =
                    setjoin_jmap::submission::decode_draft_lock(&rows)?
                {
                    tx.execute_contract(
                        &setjoin_jmap::sql::SUBMISSION_UPDATE_DRAFT_SIZE,
                        &[&item.size_bytes, &item.email_id, &mailbox],
                    )
                    .await?;
                    orig_sizes.push((item.creation_id.clone(), item.email_id, orig_ref, orig_size));
                }
            }
            let rows = tx
                .query_contract(
                    &setjoin_jmap::sql::SUBMISSION_SET_WITH_NOT_CREATED,
                    &[&mailbox, &actor, &create, &processed_refs, &is_encrypted],
                )
                .await?;
            let (res_text, not_created_keys) =
                setjoin_jmap::submission::decode_submission_with_not_created(&rows)?;
            for (cid, email_id, orig_ref, orig_size) in orig_sizes {
                if not_created_keys.iter().any(|k| k == &cid) {
                    tx.execute_contract(
                        &setjoin_jmap::sql::SUBMISSION_RESTORE_DRAFT_SIZE,
                        &[&orig_size, &email_id, &mailbox, &orig_ref],
                    )
                    .await?;
                }
            }
            res_text
        };
        tx.record_receipt(
            operation,
            setjoin_pg::ReceiptCommand {
                family: "jmap",
                command: "submission.set",
            },
        )
        .await?;
        Ok(res_text)
    }
    .await;
    match body {
        Ok(res_text) => match tx.commit().await {
            Ok(()) => setjoin_pg::CommandOutcome::Committed(res_text),
            Err(e) => {
                if let Some(code) = e.sqlstate.as_deref() {
                    if setjoin_pg::commit_failure_observation(Some(code))
                        == setjoin_contracts::command::CommitObservation::RolledBack
                    {
                        return setjoin_pg::CommandOutcome::RolledBack(
                            setjoin_pg::Rejection::CommitRefused(code.to_owned()),
                        );
                    }
                }
                setjoin_pg::CommandOutcome::Unknown { operation }
            }
        },
        Err(e) => {
            let _ = tx.rollback().await;
            setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(e))
        }
    }
}
