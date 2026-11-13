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
        let (parts, body) = req.into_parts();
        match self.try_action(&parts, &ctx).await {
            Ok(response) => response,
            Err(_) => {
                ctx.upstream
                    .forward(Request::from_parts(parts, body), &ctx.identity)
                    .await
            }
        }
    }
    async fn try_action(
        &self,
        parts: &hyper::http::request::Parts,
        ctx: &RequestContext,
    ) -> Result<Response<Body>, &'static str> {
        let (action, raw) = target(parts.uri.path()).ok_or("unsupported submission action")?;
        let authorized = setjoin_authz::authorize_request(
            &self.exec,
            &self.keys,
            &self.issuer,
            &parts.headers,
            ctx.identity.proto,
        )
        .await
        .ok_or("unported identity admission (#331)")?;
        let identity = authorized.context();
        if let Some(denylist) = &self.denylist {
            let issued =
                chrono::DateTime::from_timestamp(authorized.issued_at(), 0).ok_or("token iat")?;
            if !denylist.loaded()
                || denylist.is_revoked(
                    identity.user_id(),
                    authorized.token_id(),
                    authorized.token_family(),
                    issued,
                )
            {
                return Err("unported identity admission (#331)");
            }
        }
        let request_id = reply::request_id(
            parts.headers.get("x-request-id"),
            super::random().ok_or("rng unavailable")?,
        );
        let email_id = raw
            .parse::<i64>()
            .ok()
            .filter(|id| action == Action::Recall || *id > 0);
        let Some(email_id) = email_id else {
            return Ok(crate::mailboxes::bare(
                400,
                "invalid message id",
                ctx,
                &request_id,
            ));
        };
        let auth = MailboxAuthContext::from_authenticated_session(
            ActorId::new(identity.user_id()).map_err(|_| "actor")?,
            MailboxId::new(identity.mailbox_id()).map_err(|_| "mailbox")?,
            super::REQUEST_AUTHORITY_GENERATION,
        );
        let envelope = CommandEnvelope {
            operation: OperationId(super::random().ok_or("rng unavailable")?),
            authority: auth.authority(),
            binding: setjoin_db::lifecycle::accepted_contract(),
            payload_digest: Digest(Sha256::digest(parts.uri.to_string().as_bytes()).into()),
            command: setjoin_jmap::submission::Submission,
        };
        if action == Action::Recall {
            return Ok(self
                .recall_action(
                    &auth,
                    identity.email(),
                    email_id,
                    envelope,
                    ctx,
                    &request_id,
                )
                .await);
        }
        let response = match setjoin_jmap::submission::undo(
            &self.exec,
            &auth,
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
        };
        Ok(response)
    }
    async fn recall_action(
        &self,
        primary: &MailboxAuthContext,
        email: &str,
        id: i64,
        mut envelope: CommandEnvelope<setjoin_jmap::submission::Submission>,
        ctx: &RequestContext,
        request_id: &str,
    ) -> Response<Body> {
        let exec = self.worker.as_ref().unwrap_or(&self.exec);
        let source = match setjoin_jmap::submission::recall_source(exec, primary, id).await {
            Ok(Some(source)) => source,
            _ => return crate::mailboxes::bare(404, "message not found", ctx, request_id),
        };
        if source.from != email
            && !setjoin_jmap::submission::sender_alias(exec, primary, &source.from).await
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
        let scope = MailboxAuthContext::from_authenticated_session(
            primary.actor(),
            mailbox,
            super::REQUEST_AUTHORITY_GENERATION,
        );
        envelope.authority = scope.authority();
        match setjoin_jmap::submission::recall(
            exec,
            &scope,
            &envelope,
            std::time::Instant::now() + super::COMMAND_DEADLINE,
            &source.message_id,
        )
        .await
        {
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
