//! Mailbox lifecycle and purge console: Go's `UsersHandler.Mailbox*` routes.
//!
//! Every route is one reducer call on the worker credential (Go's `workerPool`);
//! the reducers own the audit, state and notify effects. Reads return the
//! reducer's `jsonb` text verbatim, as Go writes the raw bytes. A write runs in
//! one receipted command, so a refusal (BZ business error) rolls back with no
//! receipt and an Unknown outcome never reports success.
use super::{deadline, envelope, invalid, scope, FAMILY};
use setjoin_authz::AuthContext;
use setjoin_pg::{
    CommandOutcome, ReceiptCommand, Rejection, Row, ScopedExecutor, StatementFailure, Type,
};
use sha2::{Digest as _, Sha256};

fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: FAMILY,
        command: name,
    }
}

fn text(rows: &[Row]) -> Result<String, StatementFailure> {
    match rows {
        [row] => row.try_get::<_, String>(0).map_err(|_| invalid()),
        _ => Err(invalid()),
    }
}

/// `GET /admin/mailboxes/{id}/lifecycle/preview`.
pub async fn preview(
    worker: &ScopedExecutor,
    actor: i64,
    mailbox: i64,
) -> Result<String, StatementFailure> {
    text(
        &worker
            .read(
                "SELECT mailbox_lifecycle_preview($1,$2)::text",
                &[(&actor, Type::INT8), (&mailbox, Type::INT8)],
            )
            .await?,
    )
}

/// `GET /admin/mailboxes/retained`: Go's fixed page size is 200.
pub async fn retained(
    worker: &ScopedExecutor,
    actor: i64,
    domain_scope: i64,
) -> Result<String, StatementFailure> {
    text(
        &worker
            .read(
                "SELECT mailbox_retained_list($1,$2,200)::text",
                &[(&actor, Type::INT8), (&domain_scope, Type::INT8)],
            )
            .await?,
    )
}

/// `GET /admin/mailboxes/lifecycle/parity`.
pub async fn parity(worker: &ScopedExecutor) -> Result<String, StatementFailure> {
    text(
        &worker
            .read("SELECT mailbox_lifecycle_parity_report()::text", &[])
            .await?,
    )
}

/// Go's `json.Marshal` string: HTML-escaped, ` `/` ` escaped.
fn go_string(value: &str) -> String {
    serde_json::to_string(value)
        .expect("string")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

fn digest(json: &str) -> String {
    Sha256::digest(json.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The decoded body of `POST /admin/mailboxes/{id}/lifecycle`.
#[derive(Default, Clone)]
pub struct TransitionRequest {
    pub action: String,
    pub expected_generation: String,
    pub idempotency_key: String,
    pub reason: String,
    pub target_user_id: String,
    pub evidence_kind: String,
    pub identity_link_id: String,
    pub link_generation: String,
    pub source_key_digest: String,
    pub delivery: String,
    pub redirect_address: String,
}

impl TransitionRequest {
    /// `mailboxLifecycleDigest(req)`: SHA-256 of Go's `json.Marshal` of the struct.
    pub fn digest(&self) -> String {
        let mut out = format!(
            "{{\"action\":{},\"expectedGeneration\":{},\"idempotencyKey\":{},\"reason\":{}",
            go_string(&self.action),
            go_string(&self.expected_generation),
            go_string(&self.idempotency_key),
            go_string(&self.reason)
        );
        for (name, value) in [
            ("targetUserId", &self.target_user_id),
            ("evidenceKind", &self.evidence_kind),
            ("identityLinkId", &self.identity_link_id),
            ("linkGeneration", &self.link_generation),
            ("sourceKeyDigest", &self.source_key_digest),
            ("delivery", &self.delivery),
            ("redirectAddress", &self.redirect_address),
        ] {
            if !value.is_empty() {
                out += &format!(",\"{name}\":{}", go_string(value));
            }
        }
        digest(&(out + "}"))
    }
}

/// The decoded body of `POST /admin/mailboxes/{id}/purge`.
#[derive(Default, Clone)]
pub struct PurgeRequest {
    pub expected_generation: String,
    pub preview_digest: String,
    pub idempotency_key: String,
    pub reason: String,
    pub approver_user_id: String,
}

impl PurgeRequest {
    pub fn digest(&self) -> String {
        digest(&format!(
            "{{\"expectedGeneration\":{},\"previewDigest\":{},\"idempotencyKey\":{},\"reason\":{},\"approverUserId\":{}}}",
            go_string(&self.expected_generation),
            go_string(&self.preview_digest),
            go_string(&self.idempotency_key),
            go_string(&self.reason),
            go_string(&self.approver_user_id)
        ))
    }
}

/// `{idempotencyKey, reason}`: the body of purge execute and cancel.
pub fn keyed_digest(idempotency_key: &str, reason: &str) -> String {
    digest(&format!(
        "{{\"idempotencyKey\":{},\"reason\":{}}}",
        go_string(idempotency_key),
        go_string(reason)
    ))
}

/// The reducer's `jsonb` answer, or the refusal it raised.
fn answer(rows: &[Row]) -> Result<String, StatementFailure> {
    text(rows)
}

/// Parsed, validated arguments of `mailbox_lifecycle_transition` after Go's
/// handler checks; `key` is the canonical UUID text.
pub struct Transition<'a> {
    pub mailbox: i64,
    pub key: &'a str,
    pub action: &'a str,
    pub generation: i64,
    pub digest: &'a str,
    pub reason: &'a str,
    pub target: Option<i64>,
    pub evidence_kind: Option<&'a str>,
    pub link_id: Option<i64>,
    pub link_generation: Option<i64>,
    pub source_key_digest: Option<&'a str>,
    pub auth_time: Option<i64>,
    pub delivery: Option<&'a str>,
}

pub async fn transition(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    t: &Transition<'_>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("mailbox.lifecycle.transition"),
        &envelope(
            &auth,
            operation,
            &format!("{}:{}:{}", t.mailbox, t.key, t.digest),
        ),
        &auth,
        deadline(),
        "SELECT mailbox_lifecycle_transition($2,$4,$5::text::uuid,$6,$7,$8,$9,$10,$11,$12,$13,$14,\
         to_timestamp($15::bigint),$16,NULL::text)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&t.mailbox, Type::INT8),
            (&t.key, Type::TEXT),
            (&t.action, Type::TEXT),
            (&t.generation, Type::INT8),
            (&t.digest, Type::TEXT),
            (&t.reason, Type::TEXT),
            (&t.target, Type::INT8),
            (&t.evidence_kind, Type::TEXT),
            (&t.link_id, Type::INT8),
            (&t.link_generation, Type::INT8),
            (&t.source_key_digest, Type::TEXT),
            (&t.auth_time, Type::INT8),
            (&t.delivery, Type::TEXT),
        ],
        answer,
    )
    .await
}

pub struct Purge<'a> {
    pub mailbox: i64,
    pub key: &'a str,
    pub generation: i64,
    pub preview_digest: &'a str,
    pub digest: &'a str,
    pub reason: &'a str,
    pub approver: i64,
}

pub async fn purge_schedule(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    p: &Purge<'_>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("mailbox.purge.schedule"),
        &envelope(
            &auth,
            operation,
            &format!("{}:{}:{}", p.mailbox, p.key, p.digest),
        ),
        &auth,
        deadline(),
        "SELECT mailbox_purge_schedule($2,$4,$5::text::uuid,$6,$7,$8,$9,$10)::text \
         WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&p.mailbox, Type::INT8),
            (&p.key, Type::TEXT),
            (&p.generation, Type::INT8),
            (&p.preview_digest, Type::TEXT),
            (&p.digest, Type::TEXT),
            (&p.reason, Type::TEXT),
            (&p.approver, Type::INT8),
        ],
        answer,
    )
    .await
}

pub async fn purge_approval(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    request: i64,
    decision: &str,
    comment: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("mailbox.purge.approval"),
        &envelope(&auth, operation, &format!("{request}:{decision}:{comment}")),
        &auth,
        deadline(),
        "SELECT mailbox_purge_approval_apply($4,$2,$5,$6)::text \
         WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&request, Type::INT8),
            (&decision, Type::TEXT),
            (&comment, Type::TEXT),
        ],
        answer,
    )
    .await
}

pub async fn purge_execute(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    purge: &str,
    key: &str,
    digest: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("mailbox.purge.execute"),
        &envelope(&auth, operation, &format!("{purge}:{key}:{digest}")),
        &auth,
        deadline(),
        "SELECT mailbox_purge_execute($2,$4::text::uuid,$5::text::uuid,$6)::text \
         WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&purge, Type::TEXT),
            (&key, Type::TEXT),
            (&digest, Type::TEXT),
        ],
        answer,
    )
    .await
}

pub async fn purge_cancel(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    purge: &str,
    key: &str,
    digest: &str,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("mailbox.purge.cancel"),
        &envelope(&auth, operation, &format!("{purge}:{key}:{digest}")),
        &auth,
        deadline(),
        "SELECT mailbox_purge_cancel($2,$4::text::uuid,$5::text::uuid,$6,$7)::text \
         WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&purge, Type::TEXT),
            (&key, Type::TEXT),
            (&digest, Type::TEXT),
            (&reason, Type::TEXT),
        ],
        answer,
    )
    .await
}

/// Go's `reducererr` projection of a BZ business error, as the problem fields.
pub struct Classified {
    pub status: u16,
    pub detail: String,
    pub remediation: &'static str,
    pub code: String,
}

/// The lifecycle-range codes (BZ300–BZ313) Go classifies; anything else is Go's
/// generic 500 for the route.
pub fn classify(error: &Rejection<StatementFailure>) -> Option<Classified> {
    let (Rejection::Statement(e) | Rejection::Body(e)) = error else {
        return None;
    };
    classify_failure(e)
}

pub fn classify_failure(e: &StatementFailure) -> Option<Classified> {
    let code = e.sqlstate.as_deref()?;
    let message = e.message.clone();
    let (status, detail, remediation): (u16, String, &'static str) = match code {
        "BZ300" | "BZ302" | "BZ310" => (
            404,
            "notFound".into(),
            "Refresh the target identifier and retry only if the resource still exists.",
        ),
        "BZ301" => (
            400,
            "invalidArguments".into(),
            "Correct the request fields and retry.",
        ),
        "BZ303" | "BZ304" | "BZ309" => (
            409,
            "stateMismatch".into(),
            "Refresh current state, resolve the conflict, and retry.",
        ),
        "BZ305" | "BZ306" | "BZ312" | "BZ313" | "BZ315" | "BZ328" => (
            409,
            "conflict".into(),
            "Refresh current state, resolve the conflict, and retry.",
        ),
        "BZ307" | "BZ308" | "BZ311" | "BZ314" => (
            403,
            "forbidden".into(),
            "Complete the required authorization, approval, or recovery step before retrying.",
        ),
        // The approval decision codes surface the reducer's own message.
        "BZ106" | "BZ108" | "BZ110" => (
            409,
            message,
            "Refresh current state, resolve the conflict, and retry.",
        ),
        "BZ107" => (
            403,
            message,
            "Complete the required authorization, approval, or recovery step before retrying.",
        ),
        "BZ109" => (
            422,
            message,
            "Correct the requested operation using the documented runbook and retry.",
        ),
        _ => return None,
    };
    Some(Classified {
        status,
        detail,
        remediation,
        code: code.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference values come from frozen Go's `json.Marshal` + SHA-256 of the same structs.
    #[test]
    fn request_digests_equal_go_json_marshal() {
        let plain = TransitionRequest {
            action: "suspend".into(),
            expected_generation: "1".into(),
            idempotency_key: "k".into(),
            reason: "plain reason".into(),
            ..Default::default()
        };
        assert_eq!(
            plain.digest(),
            "b2b9f898592ec53c34034059c05a0086e67da91ed53207f9065bf2fd0ba80ba7"
        );
        let full = TransitionRequest {
            action: "reconnect".into(),
            expected_generation: "7".into(),
            idempotency_key: "k".into(),
            reason: "a <b> & \u{2028} é \u{1} \" \\".into(),
            target_user_id: "5".into(),
            evidence_kind: "local_user".into(),
            identity_link_id: "2".into(),
            link_generation: "3".into(),
            source_key_digest: "abc".into(),
            delivery: "rejecting".into(),
            redirect_address: String::new(),
        };
        assert_eq!(
            full.digest(),
            "372099cbda9ad934e42bd720450b689db9b8d20b6efab653d403b852ffcf206a"
        );
        let purge = PurgeRequest {
            expected_generation: "2".into(),
            preview_digest: "AB".into(),
            idempotency_key: "k".into(),
            reason: "why <not>".into(),
            approver_user_id: "9".into(),
        };
        assert_eq!(
            purge.digest(),
            "ad57ffaefc6aa96904475f6266dc1a02f22ad76bee1877258b932fd49c1e5532"
        );
        assert_eq!(
            keyed_digest("k", "go \u{7f} ÿ"),
            "0791627592a7bb3d4845cbaf2ee6b6ac53c087686046a5feceaa0eff3726abac"
        );
    }

    #[test]
    fn bz_codes_project_like_reducererr() {
        let failure = |code: &str| StatementFailure {
            sqlstate: Some(code.into()),
            message: "m".into(),
            hint: None,
        };
        let got = |code: &str| classify_failure(&failure(code)).map(|k| (k.status, k.detail));
        assert_eq!(got("BZ302"), Some((404, "notFound".into())));
        assert_eq!(got("BZ304"), Some((409, "stateMismatch".into())));
        assert_eq!(got("BZ305"), Some((409, "conflict".into())));
        assert_eq!(got("BZ307"), Some((403, "forbidden".into())));
        assert_eq!(got("BZ107"), Some((403, "m".into())));
        assert_eq!(got("BZ013"), None, "intentional 500s are not classified");
        assert_eq!(got("23505"), None);
    }
}
