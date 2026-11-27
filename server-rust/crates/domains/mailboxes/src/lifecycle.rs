//! Mailbox lifecycle and purge console: Go's `UsersHandler.Mailbox*` routes.
//!
//! Every route is one reducer call on `TxFactory`; the reducers own the audit,
//! state and notify effects. Reads return the reducer's `jsonb` text verbatim,
//! as Go writes the raw bytes. A write runs in one receipted command, so a
//! refusal (BZ business error) rolls back with no receipt and an Unknown
//! outcome never reports success.
use super::{command, deadline, envelope, invalid, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, Rejection, Row, StatementFailure};
use sha2::{Digest as _, Sha256};

fn text(rows: &[Row]) -> Result<String, StatementFailure> {
    match rows {
        [row] => row.try_get::<_, String>(0).map_err(|_| invalid()),
        _ => Err(invalid()),
    }
}

/// `GET /admin/mailboxes/{id}/lifecycle/preview`.
pub async fn preview(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    mailbox: i64,
) -> Result<String, StatementFailure> {
    let actor = proof.actor().get();
    text(
        &factory
            .run_admin_read_contract(proof, &sql::LIFECYCLE_PREVIEW, &[&actor, &mailbox])
            .await?,
    )
}

/// `GET /admin/mailboxes/retained`: Go's fixed page size is 200.
pub async fn retained(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    domain_scope: i64,
) -> Result<String, StatementFailure> {
    let actor = proof.actor().get();
    text(
        &factory
            .run_admin_read_contract(proof, &sql::LIFECYCLE_RETAINED, &[&actor, &domain_scope])
            .await?,
    )
}

/// `GET /admin/mailboxes/lifecycle/parity`.
pub async fn parity(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    text(
        &factory
            .run_admin_read_contract(proof, &sql::LIFECYCLE_PARITY, &[])
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
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    t: &Transition<'_>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let env = envelope(
        proof.actor(),
        proof.generation(),
        operation,
        &format!("{}:{}:{}", t.mailbox, t.key, t.digest),
    );
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::LIFECYCLE_TRANSITION,
            &[
                &t.mailbox,
                &t.key,
                &t.action,
                &t.generation,
                &t.digest,
                &t.reason,
                &t.target,
                &t.evidence_kind,
                &t.link_id,
                &t.link_generation,
                &t.source_key_digest,
                &t.auth_time,
                &t.delivery,
            ],
            Some(command("mailbox.lifecycle.transition")),
            |rows, _| answer(&rows),
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
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    p: &Purge<'_>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let env = envelope(
        proof.actor(),
        proof.generation(),
        operation,
        &format!("{}:{}:{}", p.mailbox, p.key, p.digest),
    );
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::LIFECYCLE_PURGE_SCHEDULE,
            &[
                &p.mailbox,
                &p.key,
                &p.generation,
                &p.preview_digest,
                &p.digest,
                &p.reason,
                &p.approver,
            ],
            Some(command("mailbox.purge.schedule")),
            |rows, _| answer(&rows),
        )
        .await
}

pub async fn purge_approval(
    factory: &TxFactory,
    user: &UserPrincipal,
    request: i64,
    decision: &str,
    comment: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let actor = user.user().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{request}:{decision}:{comment}"),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::LIFECYCLE_PURGE_APPROVAL,
            &[&request, &actor, &decision, &comment],
            Some(command("mailbox.purge.approval")),
            |rows| answer(&rows),
        )
        .await
}

pub async fn purge_execute(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    purge: &str,
    key: &str,
    digest: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let env = envelope(
        proof.actor(),
        proof.generation(),
        operation,
        &format!("{purge}:{key}:{digest}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::LIFECYCLE_PURGE_EXECUTE,
            &[&purge, &key, &digest],
            Some(command("mailbox.purge.execute")),
            |rows, _| answer(&rows),
        )
        .await
}

pub async fn purge_cancel(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    purge: &str,
    key: &str,
    digest: &str,
    reason: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let env = envelope(
        proof.actor(),
        proof.generation(),
        operation,
        &format!("{purge}:{key}:{digest}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::LIFECYCLE_PURGE_CANCEL,
            &[&purge, &key, &digest, &reason],
            Some(command("mailbox.purge.cancel")),
            |rows, _| answer(&rows),
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
