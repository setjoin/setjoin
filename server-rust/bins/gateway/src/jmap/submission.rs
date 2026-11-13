//! EmailSubmission request translation (#317), using the submission capability.
use super::envelope::single_call_with_capability;
use super::get::parse_id;
use super::submission_input::{self, Failure};
use serde_json::value::RawValue;
use serde_json::Value;
use std::collections::BTreeMap;

pub const CAPABILITY: &str = "urn:ietf:params:jmap:submission";
pub(crate) struct SubmissionRequest {
    pub account_id: i64,
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
    pub(super) async fn needs_preprocessing(
        &self,
        exec: &setjoin_pg::ScopedExecutor,
        auth: &setjoin_pg::MailboxAuthContext,
    ) -> Result<bool, setjoin_pg::StatementFailure> {
        let Arguments::Set(Ok(Some(raw))) = &self.args else {
            return Ok(false);
        };
        // Already validated by classify, retaining raw nested Go key semantics.
        let map: BTreeMap<String, Box<RawValue>> =
            serde_json::from_str(raw).expect("classified creation map");
        let mut ids = Vec::new();
        for raw in map.values() {
            let Some(email) = submission_input::attachment_email_id(raw.get()) else {
                continue;
            };
            if email.is_empty() {
                continue;
            }
            let Ok(id) = email.parse::<i64>() else {
                // Go's MIME helper owns load-draft failures as notCreated too.
                return Ok(true);
            };
            ids.push(id);
        }
        if ids.is_empty() {
            return Ok(false);
        }
        setjoin_jmap::submission::has_attachments(exec, auth, &ids).await
    }
    pub(super) fn early_error(&self) -> Option<&Failure> {
        match &self.args {
            Arguments::Rejected {
                error, early: true, ..
            } => Some(error),
            _ => None,
        }
    }
}
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
    let rejected = |error| SubmissionRequest {
        account_id: 0,
        client_id: call.client_id.clone(),
        args: Arguments::Rejected {
            method,
            error,
            early: true,
        },
    };
    let input = match submission_input::decode(method, &call.raw_args) {
        Ok(v) => v,
        Err(e) => return Some(rejected(e)),
    };
    let account_id = match parse_id(&input.account) {
        Some(v) => v,
        None => {
            return Some(rejected(Failure::account(if input.account.is_empty() {
                "accountId is required"
            } else {
                "invalid accountId"
            })))
        }
    };
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
                    Value::Object(_) => {
                        // Preserve duplicate nested fields and Go's folded
                        // probe semantics before the whole-map #328 boundary.
                        let map: BTreeMap<String, Box<RawValue>> =
                            serde_json::from_str(&raw).ok()?;
                        if map
                            .values()
                            .any(|v| submission_input::smime_requested(v.get()))
                        {
                            return None;
                        }
                        Ok(Some(raw))
                    }
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
        account_id,
        client_id: call.client_id,
        args,
    })
}

/// Render a claimed call. Once claimed, a database failure is a native JMAP
/// error; an ambiguous commit carries its operation ID and is never replayed.
pub(crate) async fn response(
    exec: &setjoin_pg::ScopedExecutor,
    auth: &setjoin_pg::MailboxAuthContext,
    worker: &setjoin_pg::ScopedExecutor,
    request: SubmissionRequest,
    session: &str,
    operation: [u8; 16],
    digest: [u8; 32],
) -> String {
    use super::reply;
    let method = request.args.method();
    let raw = match request.args {
        Arguments::Rejected { error, .. } => {
            return reply::method_error(
                session,
                error.kind,
                error.status,
                &error.detail,
                &request.client_id,
            )
        }
        Arguments::Get { ids, bad } => setjoin_jmap::submission::get(exec, auth, ids.as_deref())
            .await
            .map(|raw| super::get::add_not_found(&raw, &bad).expect("reducer JSON")),
        Arguments::Query {
            filter,
            position,
            limit,
        } => setjoin_jmap::submission::query(exec, auth, filter.as_deref(), position, limit).await,
        Arguments::Set(Err(detail)) => {
            return reply::method_error(
                session,
                "invalidArguments",
                400,
                &detail,
                &request.client_id,
            )
        }
        Arguments::Set(Ok(create)) => {
            let envelope = setjoin_contracts::command::CommandEnvelope {
                operation: setjoin_contracts::ids::OperationId(operation),
                authority: auth.authority(),
                binding: setjoin_db::lifecycle::accepted_contract(),
                payload_digest: setjoin_contracts::ids::Digest(digest),
                command: setjoin_jmap::submission::Submission,
            };
            match setjoin_jmap::submission::create(
                worker,
                auth,
                &envelope,
                std::time::Instant::now() + super::COMMAND_DEADLINE,
                create.as_deref(),
            )
            .await
            {
                setjoin_pg::CommandOutcome::Committed(raw) => Ok(raw),
                setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(
                    failure,
                )) => Err(failure),
                setjoin_pg::CommandOutcome::RolledBack(_) => {
                    return reply::method_error(
                        session,
                        "serverFail",
                        500,
                        "database error",
                        &request.client_id,
                    )
                }
                setjoin_pg::CommandOutcome::Unknown { operation } => {
                    return reply::method_error(
                        session,
                        "serverFail",
                        500,
                        &format!(
                            "commit outcome unknown; look up operation {}",
                            setjoin_pg::operation_hex(operation)
                        ),
                        &request.client_id,
                    )
                }
            }
        }
        Arguments::Cancel(Err(detail)) => {
            return reply::method_error(
                session,
                "invalidArguments",
                400,
                detail,
                &request.client_id,
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
                exec,
                auth,
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
                    return reply::method_error(
                        session,
                        "serverFail",
                        500,
                        "database error",
                        &request.client_id,
                    )
                }
                setjoin_pg::CommandOutcome::Unknown { operation } => {
                    return reply::method_error(
                        session,
                        "serverFail",
                        500,
                        &format!(
                            "commit outcome unknown; look up operation {}",
                            setjoin_pg::operation_hex(operation)
                        ),
                        &request.client_id,
                    )
                }
            }
        }
    };
    match raw {
        Ok(raw) => {
            let mut body = reply::method_response(session, method, &raw, &request.client_id)
                .expect("reducer JSON");
            if method == "EmailSubmission/set" {
                // Go's dispatcher accumulates every /set response's created IDs
                // into the final envelope, sorted as an encoding/json map.
                let result: Value = serde_json::from_str(&raw).expect("reducer JSON");
                if let Some(created) = result
                    .get("created")
                    .and_then(Value::as_object)
                    .filter(|m| !m.is_empty())
                {
                    let ids: BTreeMap<&str, &str> = created
                        .iter()
                        .map(|(key, item)| {
                            (
                                key.as_str(),
                                item.get("id").and_then(Value::as_str).unwrap_or(""),
                            )
                        })
                        .collect();
                    let ids = reply::go_compact(&serde_json::to_string(&ids).expect("string map"))
                        .expect("string map");
                    body.truncate(body.len() - 2);
                    body.push_str(&format!(",\"createdIds\":{ids}}}\n"));
                }
            }
            body
        }
        Err(failure) if failure.sqlstate.as_deref() == Some("BZ020") => {
            reply::method_error(session, "notFound", 500, "notFound", &request.client_id)
        }
        Err(failure) => reply::failure_error(
            session,
            setjoin_jmap::classify_failure(&failure),
            &request.client_id,
        )
        .unwrap_or_else(|| {
            reply::method_error(
                session,
                "serverFail",
                500,
                "database error",
                &request.client_id,
            )
        }),
    }
}
