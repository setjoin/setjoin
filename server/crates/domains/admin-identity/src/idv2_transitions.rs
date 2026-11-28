//! Admin identity (F01) slice `idv2-transitions`: the identity v2 transition reads, the
//! preview, the step-up challenge and every transition command.
use super::idv2::Refusal;
use super::sql;
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_pg::StatementFailure;
use setjoin_sql_catalog::SqlContract;
use sha2::{Digest as _, Sha256};

fn failed(detail: &str) -> Refusal {
    Refusal {
        status: 500,
        detail: detail.to_owned(),
        reducer: None,
    }
}

/// `COALESCE((SELECT admin_can_reach($1,t.user_id) FROM identity_transitions t WHERE t.id=$2), false)`.
pub async fn reachable(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    actor: i64,
    transition: &str,
) -> Result<bool, Refusal> {
    let rows = factory
        .run_admin_read_contract(
            admin,
            &sql::IDV2_TRANSITION_REACHABLE,
            &[&actor, &transition],
        )
        .await
        .map_err(|_| failed("identity transition scope check failed"))?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(|| failed("identity transition scope check failed"))
}

/// `SELECT admin_can_reach($1,$2)` for a person (the preview's scope check).
pub async fn person_reachable(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    actor: i64,
    user: i64,
) -> Result<bool, Refusal> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::IDV2_PERSON_REACHABLE, &[&actor, &user])
        .await
        .map_err(|_| failed("identity transition scope check failed"))?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(|| failed("identity transition scope check failed"))
}

/// `SELECT identity_transition_read($1,$2)`: the jsonb text verbatim.
pub async fn read(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    actor: i64,
    transition: &str,
) -> Result<Option<String>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::IDV2_TRANSITION_READ, &[&actor, &transition])
        .await?;
    Ok(rows
        .first()
        .and_then(|r| r.try_get::<_, Option<String>>(0).ok().flatten()))
}

/// `GET .../transitions/{id}/report`: Go's one `jsonb_build_object` query; `None` is 404.
pub async fn report(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    actor: i64,
    transition: &str,
) -> Result<Option<String>, Refusal> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::IDV2_TRANSITION_REPORT, &[&transition, &actor])
        .await
        .map_err(|_| failed("identity transition report failed"))?;
    Ok(rows
        .first()
        .and_then(|r| r.try_get::<_, Option<String>>(0).ok().flatten()))
}

/// The reducer a transition command calls (Go's `SELECT identity_transition_...`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Request,
    Approve,
    Deny,
    Execute,
    Rollback,
    Cancel,
    RollbackPreview,
    Retry,
    ChallengeIssue,
    ChallengeComplete,
}

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::Request => "identity_transition_request",
            Op::Approve => "identity_transition_approve",
            Op::Deny => "identity_transition_deny",
            Op::Execute => "identity_transition_execute",
            Op::Rollback => "identity_transition_rollback",
            Op::Cancel => "identity_transition_cancel",
            Op::RollbackPreview => "identity_transition_rollback_preview",
            Op::Retry => "identity_transition_retry",
            Op::ChallengeIssue => "identity_transition_challenge_issue",
            Op::ChallengeComplete => "identity_transition_challenge_complete",
        }
    }

    pub fn contract(self) -> &'static SqlContract {
        match self {
            Op::Request => &sql::IDV2_TRANSITION_REQUEST,
            Op::Approve => &sql::IDV2_TRANSITION_APPROVE,
            Op::Deny => &sql::IDV2_TRANSITION_DENY,
            Op::Execute => &sql::IDV2_TRANSITION_EXECUTE,
            Op::Rollback => &sql::IDV2_TRANSITION_ROLLBACK,
            Op::Cancel => &sql::IDV2_TRANSITION_CANCEL,
            Op::RollbackPreview => &sql::IDV2_TRANSITION_ROLLBACK_PREVIEW,
            Op::Retry => &sql::IDV2_TRANSITION_RETRY,
            Op::ChallengeIssue => &sql::IDV2_TRANSITION_CHALLENGE_ISSUE,
            Op::ChallengeComplete => &sql::IDV2_TRANSITION_CHALLENGE_COMPLETE,
        }
    }
}

/// Go's `validIdentityDigest`: 64 lowercase hex characters.
pub fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `jwtutil.VerifyFreshAAL2` with `CurrentFreshAAL2Policy` over a verified token.
#[allow(clippy::too_many_arguments)]
pub fn step_up_bindings(
    user: i64,
    jti: &str,
    issued_at: i64,
    acr: &str,
    amr: &[String],
    transition: &str,
    challenge: &str,
    digest: &str,
    now: f64,
) -> Option<(Vec<u8>, Vec<u8>, Vec<String>)> {
    if !valid_digest(digest) || user <= 0 || jti.is_empty() {
        return None;
    }
    if acr != "aal2" {
        return None;
    }
    let issued = issued_at as f64;
    if now < issued - 30.0 || now - issued > 300.0 {
        return None;
    }
    let mut seen: Vec<&str> = Vec::new();
    let (mut factors, mut mfa) = (0, false);
    for method in amr {
        if method.is_empty() || seen.contains(&method.as_str()) {
            continue;
        }
        seen.push(method);
        if seen.len() > 16 {
            return None;
        }
        if method == "mfa" {
            mfa = true;
        }
        if matches!(method.as_str(), "pwd" | "otp" | "hwk" | "swk") {
            factors += 1;
        }
    }
    if !mfa || factors < 2 {
        return None;
    }
    let mut sorted: Vec<String> = seen.iter().map(|m| (*m).to_owned()).collect();
    sorted.sort();
    let stamp = rfc3339(issued_at);
    let session = Sha256::digest(
        format!("setjoin-identity-transition-session-v1\n{user}\n{jti}\n{stamp}").as_bytes(),
    );
    let factor = Sha256::digest(
        format!(
            "setjoin-identity-transition-factor-v1\n{user}\n{transition}\n{challenge}\n{digest}\n{acr}\n{}\n{jti}",
            sorted.join(",")
        )
        .as_bytes(),
    );
    Some((session.to_vec(), factor.to_vec(), sorted))
}

fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rest = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_matches_known_instants() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_799_999_000), "2027-01-15T07:43:20Z");
    }

    #[test]
    fn step_up_needs_aal2_two_factors_and_freshness() {
        let digest = "a".repeat(64);
        let amr: Vec<String> = ["pwd", "otp", "mfa"].map(String::from).to_vec();
        let ok = |acr: &str, amr: &[String], iat: i64, now: f64| {
            step_up_bindings(7, "j", iat, acr, amr, "t", "c", &digest, now).is_some()
        };
        assert!(ok("aal2", &amr, 1000, 1100.0));
        assert!(!ok("aal1", &amr, 1000, 1100.0));
        assert!(!ok("aal2", &amr, 1000, 1301.0), "older than five minutes");
        assert!(ok("aal2", &amr, 1000, 1300.0));
        assert!(!ok("aal2", &amr, 1000, 969.0), "issued in the future");
        assert!(!ok("aal2", &amr[..2], 1000, 1100.0), "no mfa marker");
        assert!(!ok("aal2", &["pwd".into(), "mfa".into()], 1000, 1100.0));
    }
}
