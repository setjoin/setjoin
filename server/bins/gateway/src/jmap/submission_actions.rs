//! The submission family's mounted REST actions (#317). The body has no
//! meaning to Go's handlers; identity and resource scope come from admission.
use super::{reply, JmapCommands};
use crate::{Body, RequestContext};
use hyper::{Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_contracts::{
    command::CommandEnvelope,
    ids::{ActorId, Digest, MailboxId, OperationId},
};
use setjoin_pg::{CommandOutcome, MailboxAuthContext, Rejection};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    Undo,
    Recall,
}
pub(super) fn target(path: &str) -> Option<(Action, String)> {
    let tail = path.strip_prefix("/api/messages/")?;
    let (action, id) = if let Some(id) = tail.strip_suffix("/undo") {
        (Action::Undo, id)
    } else {
        (Action::Recall, tail.strip_suffix("/recall")?)
    };
    if id.is_empty() || id.contains('/') {
        return None;
    }
    Some((
        action,
        String::from_utf8_lossy(&crate::inventory::unescape(id)).into_owned(),
    ))
}

impl<K: KeySource> JmapCommands<K> {
    pub(super) async fn serve_action(
        &self,
        req: Request<Body>,
        ctx: RequestContext,
    ) -> Response<Body> {
        let (req, authorized) = match self.admit_http(req, &ctx, crate::deny::Scope::Member).await {
            Ok(ok) => ok,
            Err(response) => return response,
        };
        let (parts, _) = req.into_parts();
        self.try_action(&parts, &ctx, &authorized).await
    }
    async fn try_action(
        &self,
        parts: &hyper::http::request::Parts,
        ctx: &RequestContext,
        authorized: &setjoin_authz::Authorized,
    ) -> Response<Body> {
        let fallback_id = reply::request_id(parts.headers.get("x-request-id"), [0; 16]);
        let Some((action, raw)) = target(parts.uri.path()) else {
            return crate::mailboxes::bare(404, "not found", ctx, &fallback_id);
        };
        let Ok(rand_bytes) = super::random_bytes() else {
            return crate::mailboxes::bare(500, "internal error", ctx, &fallback_id);
        };
        let request_id = reply::request_id(parts.headers.get("x-request-id"), rand_bytes);
        let identity = authorized.context();
        let email_id = raw
            .parse::<i64>()
            .ok()
            .filter(|id| action == Action::Recall || *id > 0);
        let Some(email_id) = email_id else {
            return crate::mailboxes::bare(400, "invalid message id", ctx, &request_id);
        };
        if ActorId::new(identity.user_id()).is_err() {
            return crate::mailboxes::bare(500, "internal error", ctx, &request_id);
        }
        if action == Action::Undo && identity.mailbox_id() == 0 {
            return crate::mailboxes::bare(404, "mailbox not found", ctx, &request_id);
        }
        let auth = identity.database_scope();
        let Ok(op_bytes) = super::random_bytes() else {
            return crate::mailboxes::bare(500, "internal error", ctx, &request_id);
        };
        let envelope = CommandEnvelope {
            operation: OperationId(op_bytes),
            authority: auth.authority(),
            binding: setjoin_db::lifecycle::accepted_contract(),
            payload_digest: Digest(Sha256::digest(parts.uri.to_string().as_bytes()).into()),
            command: setjoin_jmap::submission::Submission,
        };
        if action == Action::Recall {
            return self
                .recall_action(
                    &auth,
                    authorized,
                    identity.email(),
                    email_id,
                    envelope,
                    ctx,
                    &request_id,
                )
                .await;
        }
        let Some(tx) = self.tx_factory() else {
            return crate::mailboxes::bare(500, "undo failed", ctx, &request_id);
        };
        let Ok(mb) = tx
            .mint_primary_mailbox_from_authorized(authorized, &ctx.identity.client_ip.to_string())
            .await
        else {
            return crate::mailboxes::bare(404, "mailbox not found", ctx, &request_id);
        };
        let Ok(submit_cap) = mb.require_submit() else {
            return crate::mailboxes::bare(403, "forbidden", ctx, &request_id);
        };
        match setjoin_jmap::submission::undo(
            &tx,
            &submit_cap,
            &envelope,
            std::time::Instant::now() + super::COMMAND_DEADLINE,
            email_id,
        )
        .await
        {
            CommandOutcome::Committed(raw) => match reply::go_compact(&raw) {
                Some(raw) => reply::response(raw + "\n", ctx.identity.proto, request_id),
                None => crate::mailboxes::bare(500, "undo failed", ctx, &request_id),
            },
            CommandOutcome::Unknown { operation } => {
                crate::mailboxes::unknown_outcome(operation, ctx, &request_id)
            }
            CommandOutcome::RolledBack(Rejection::Statement(failure)) => {
                let (status, detail) = match failure.sqlstate.as_deref() {
                    Some("BZ021") => (404, "message not found"),
                    Some("BZ022") => (410, "undo window has expired"),
                    other => (reducer_status(other), "undo failed"),
                };
                crate::mailboxes::bare(status, detail, ctx, &request_id)
            }
            CommandOutcome::RolledBack(_) => {
                crate::mailboxes::bare(500, "undo failed", ctx, &request_id)
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    async fn recall_action(
        &self,
        primary: &MailboxAuthContext,
        authorized: &setjoin_authz::Authorized,
        email: &str,
        id: i64,
        mut envelope: CommandEnvelope<setjoin_jmap::submission::Submission>,
        ctx: &RequestContext,
        request_id: &str,
    ) -> Response<Body> {
        let worker = self.worker.as_ref().unwrap_or(&self.exec);
        let actor_id = primary.actor().get();
        let source = match super::worker_read_contract(
            worker,
            &setjoin_jmap::sql::SUBMISSION_RECALL_SOURCE,
            &[&id, &actor_id],
        )
        .await
        .and_then(|rows| setjoin_jmap::submission::decode_recall_source(&rows))
        {
            Ok(Some(source)) => source,
            _ => return crate::mailboxes::bare(404, "message not found", ctx, request_id),
        };
        let Some(tx) = self.tx_factory() else {
            return crate::mailboxes::bare(500, "database error", ctx, request_id);
        };
        let client_ip = ctx.identity.client_ip.to_string();
        let Ok(user) = tx.mint_user_from_authorized(authorized, &client_ip).await else {
            return crate::mailboxes::bare(500, "database error", ctx, request_id);
        };
        if source.from != email
            && !setjoin_jmap::submission::sender_alias(&tx, &user, &source.from).await
        {
            return crate::mailboxes::bare(
                403,
                "only the sender can recall this message",
                ctx,
                request_id,
            );
        }
        if std::time::SystemTime::now()
            .duration_since(source.received_at)
            .is_ok_and(|age| age > std::time::Duration::from_secs(300))
        {
            return crate::mailboxes::bare(410, "recall window has expired", ctx, request_id);
        }
        let Ok(mailbox) = MailboxId::new(source.mailbox) else {
            return crate::mailboxes::bare(500, "database error", ctx, request_id);
        };
        let Ok(mb) = tx
            .mint_mailbox_from_authorized(authorized, mailbox, &client_ip)
            .await
        else {
            return crate::mailboxes::bare(404, "message not found", ctx, request_id);
        };
        let Ok(owner_cap) = mb.require_owner() else {
            return crate::mailboxes::bare(
                403,
                "only the sender can recall this message",
                ctx,
                request_id,
            );
        };
        let recall_actor = owner_cap.actor().get();
        let recall_mailbox = owner_cap.mailbox().get();
        let op = envelope.operation;
        let _ = &mut envelope;
        let outcome: CommandOutcome<String, setjoin_pg::StatementFailure> = match worker
            .try_worker_pool()
        {
            Some(pool) => match pool.begin_read_write().await {
                Ok(mut wtx) => {
                    let op_hex = setjoin_pg::operation_hex(op);
                    let body: Result<String, setjoin_pg::StatementFailure> = async {
                            let rows = wtx
                                .query_contract(
                                    &setjoin_jmap::sql::SUBMISSION_RECALL,
                                    &[&source.message_id, &recall_actor, &recall_mailbox],
                                )
                                .await?;
                            let raw = rows
                                .first()
                                .and_then(|r| r.try_get::<_, String>(0).ok())
                                .ok_or_else(|| setjoin_pg::StatementFailure {
                                    hint: None,
                                    sqlstate: None,
                                    message: "recall reducer returned no row".into(),
                                })?;
                            wtx.execute(
                                "INSERT INTO public.rust_operation_receipts(operation_id, family, command) \
                                 VALUES ($1::text::uuid, $2, $3)",
                                &[
                                    (&op_hex, setjoin_pg::Type::TEXT),
                                    (&"jmap", setjoin_pg::Type::TEXT),
                                    (&"email_submission.recall", setjoin_pg::Type::TEXT),
                                ],
                            )
                            .await?;
                            Ok(raw)
                        }
                        .await;
                    match body {
                        Ok(raw) => match wtx.commit().await {
                            Ok(()) => CommandOutcome::Committed(raw),
                            Err(_) => CommandOutcome::Unknown { operation: op },
                        },
                        Err(e) => {
                            let _ = wtx.rollback().await;
                            CommandOutcome::RolledBack(Rejection::Statement(e))
                        }
                    }
                }
                Err(e) => CommandOutcome::RolledBack(Rejection::Statement(e)),
            },
            None => CommandOutcome::RolledBack(Rejection::Unavailable),
        };
        match outcome {
            CommandOutcome::Committed(raw) => {
                #[derive(serde::Deserialize)]
                struct Verdict {
                    #[serde(rename = "type")]
                    kind: String,
                    #[serde(default)]
                    recalled: bool,
                }
                let Ok(verdict) = serde_json::from_str::<Verdict>(&raw) else {
                    return crate::mailboxes::bare(500, "database error", ctx, request_id);
                };
                let status = match verdict.kind.as_str() {
                    "success" => 200,
                    "notFound" | "disabled" => 404,
                    "alreadyRecalled" => 409,
                    _ => return crate::mailboxes::bare(500, "database error", ctx, request_id),
                };
                let body = format!(
                    "{{\"recalled\":{},\"status\":{}}}\n",
                    verdict.recalled,
                    crate::problem::go_string(&verdict.kind)
                );
                let mut response = reply::response(body, ctx.identity.proto, request_id.to_owned());
                *response.status_mut() =
                    hyper::StatusCode::from_u16(status).expect("static status");
                response
            }
            CommandOutcome::Unknown { operation } => {
                crate::mailboxes::unknown_outcome(operation, ctx, request_id)
            }
            CommandOutcome::RolledBack(Rejection::Statement(failure)) => crate::mailboxes::bare(
                reducer_status(failure.sqlstate.as_deref()),
                "database error",
                ctx,
                request_id,
            ),
            CommandOutcome::RolledBack(_) => {
                crate::mailboxes::bare(500, "database error", ctx, request_id)
            }
        }
    }
}

// Go's shared reducererr status projection for codes reachable through mail.
pub(super) fn reducer_status(code: Option<&str>) -> u16 {
    match code {
        Some("BZ001" | "BZ004" | "BZ009") => 507,
        Some("BZ002" | "BZ003" | "BZ005") => 403,
        Some("BZ006" | "BZ007" | "BZ020" | "BZ021") => 404,
        Some("BZ011" | "BZ022") => 409,
        _ => 500,
    }
}
