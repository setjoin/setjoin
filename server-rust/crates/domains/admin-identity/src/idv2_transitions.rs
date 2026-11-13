//! Admin identity (F01) slice `idv2-transitions`: the identity v2 transition reads, the
//! preview, the step-up challenge and every transition command. Go calls one existing
//! `identity_transition_*` reducer per route after an `admin_can_reach` check; here the
//! reach check and the reducer are one receipted statement (verdict 404 before the
//! reducer), and the actor is always the verified token's user (`$2`).
use super::idv2::Refusal;
use super::idv2_writes::{command, verdict, Verdict};
use super::{deadline, envelope, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, Param, ScopedExecutor, StatementFailure, Type};
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
    worker: &ScopedExecutor,
    actor: i64,
    transition: &str,
) -> Result<bool, Refusal> {
    let rows = worker
        .read(
            "SELECT COALESCE((SELECT admin_can_reach($1,t.user_id) FROM identity_transitions t WHERE t.id=$2::text::uuid),false)",
            &[(&actor, Type::INT8), (&transition, Type::TEXT)],
        )
        .await
        .map_err(|_| failed("identity transition scope check failed"))?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(|| failed("identity transition scope check failed"))
}

/// `SELECT admin_can_reach($1,$2)` for a person (the preview's scope check).
pub async fn person_reachable(
    worker: &ScopedExecutor,
    actor: i64,
    user: i64,
) -> Result<bool, Refusal> {
    let rows = worker
        .read(
            "SELECT admin_can_reach($1,$2)",
            &[(&actor, Type::INT8), (&user, Type::INT8)],
        )
        .await
        .map_err(|_| failed("identity transition scope check failed"))?;
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(|| failed("identity transition scope check failed"))
}

/// `SELECT identity_transition_read($1,$2)`: the jsonb text verbatim; a failed statement
/// is returned for classification like `reducererr.WriteClassified`.
pub async fn read(
    worker: &ScopedExecutor,
    actor: i64,
    transition: &str,
) -> Result<Option<String>, StatementFailure> {
    let rows = worker
        .read(
            "SELECT identity_transition_read($1,$2::text::uuid)::text",
            &[(&actor, Type::INT8), (&transition, Type::TEXT)],
        )
        .await?;
    Ok(rows
        .first()
        .and_then(|r| r.try_get::<_, Option<String>>(0).ok().flatten()))
}

/// `GET .../transitions/{id}/report`: Go's one `jsonb_build_object` query; `None` is 404.
pub async fn report(
    worker: &ScopedExecutor,
    actor: i64,
    transition: &str,
) -> Result<Option<String>, Refusal> {
    let rows = worker
        .read(
            "SELECT jsonb_build_object( \
               'schemaVersion',1, \
               'generatedAt',statement_timestamp(), \
               'transition',(to_jsonb(t)-'preview_digest') || jsonb_build_object( \
                 'approval_request_id',CASE WHEN t.approval_request_id IS NULL THEN NULL ELSE t.approval_request_id::text END, \
                 'rollback_approval_request_id',CASE WHEN t.rollback_approval_request_id IS NULL THEN NULL ELSE t.rollback_approval_request_id::text END \
               ), \
               'effects',COALESCE(( \
                 SELECT jsonb_agg(to_jsonb(e) ORDER BY e.effect_kind) \
                   FROM identity_transition_effects e WHERE e.transition_id=t.id \
               ),'[]'::jsonb), \
               'events',COALESCE(( \
                 SELECT jsonb_agg(ev.row ORDER BY ev.occurred_at,ev.id) \
                   FROM ( \
                     SELECT occurred_at,id,jsonb_build_object( \
                       'occurredAt',occurred_at,'action',action, \
                       'reason',reason,'correlationId',correlation_id, \
                       'metadata',metadata \
                     ) AS row \
                       FROM identity_link_events \
                      WHERE transition_id=t.id \
                      ORDER BY occurred_at,id \
                      LIMIT 100 \
                   ) ev \
               ),'[]'::jsonb) \
             )::text \
             FROM identity_transitions t \
             WHERE t.id=$1::text::uuid AND admin_can_reach($2,t.user_id)",
            &[(&transition, Type::TEXT), (&actor, Type::INT8)],
        )
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
    fn name(self) -> &'static str {
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
    /// The reducer call; `$2` is the actor and `$4` the transition, as the receipt
    /// statement binds them. Names and shapes are code constants.
    fn call(self) -> &'static str {
        match self {
            Op::Request => "identity_transition_request($2,$4::text::uuid,$5,$6::text::uuid,$7,$8::text::uuid)",
            Op::Approve => "identity_transition_approve($2,$4::text::uuid,$5,$6::text::uuid,$7,$8::text::uuid)",
            Op::Deny => "identity_transition_deny($2,$4::text::uuid,$5,$6::text::uuid,$7,$8::text::uuid)",
            Op::Execute => "identity_transition_execute($2,$4::text::uuid,$5,$6::text::uuid,$7::bigint,$8,$9::text::uuid)",
            Op::Rollback => "identity_transition_rollback($2,$4::text::uuid,$5,$6::text::uuid,$7::bigint,$8,$9::text::uuid)",
            Op::Cancel => "identity_transition_cancel($2,$4::text::uuid,$5::bigint,$6,$7::text::uuid)",
            Op::RollbackPreview => "identity_transition_rollback_preview($2,$4::text::uuid,$5::bigint,$6,$7::text::uuid)",
            Op::Retry => "identity_transition_retry($2,$4::text::uuid,$5::bigint,$6::text::uuid,$7,$8::text::uuid)",
            Op::ChallengeIssue => "identity_transition_challenge_issue($2,$4::text::uuid,$5,$6::text::uuid)",
            Op::ChallengeComplete => "identity_transition_challenge_complete($2,$4::text::uuid,$5::text::uuid,$6,$7::bytea,$8::bytea,$9::text[],$10,$11::text::uuid)",
        }
    }
}

/// One transition command: the reach check (`404` verdict) and the reducer in one
/// receipted statement on the worker credential. `params` bind from `$5`.
pub async fn run(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    op: Op,
    transition: &str,
    params: &[Param<'_>],
    payload: &str,
    operation: [u8; 16],
) -> CommandOutcome<Verdict, StatementFailure> {
    let auth = scope(actor);
    let sql = format!(
        "SELECT q.s, CASE WHEN q.s = 200 THEN {}::text END \
         FROM (SELECT CASE WHEN COALESCE((SELECT admin_can_reach($2,t.user_id) FROM identity_transitions t WHERE t.id=$4::text::uuid),false) THEN 200 ELSE 404 END AS s \
               WHERE $1::bigint > 0 AND $3::text <> '') q",
        op.call()
    );
    let mut bound: Vec<Param<'_>> = vec![(&transition, Type::TEXT)];
    bound.extend(params.iter().map(|(value, ty)| (*value, ty.clone())));
    setjoin_pg::run_receipted_command(
        worker,
        command(op.name()),
        &envelope(
            &auth,
            operation,
            &format!("{}:{transition}:{payload}", op.name()),
        ),
        &auth,
        deadline(),
        &sql,
        &bound,
        verdict,
    )
    .await
}

/// `POST .../transitions/preview`: `identity_transition_preview` (or the rebind preview
/// with a target link) behind the person reach check, as one receipted statement.
pub async fn preview(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    user: i64,
    target_link: Option<i64>,
    reason: &str,
    key: &str,
    operation: [u8; 16],
) -> CommandOutcome<Verdict, StatementFailure> {
    let auth = scope(actor);
    let call = if target_link.is_some() {
        "identity_source_rebind_preview($2,$4::bigint,$5::bigint,$6,$7::text::uuid)"
    } else {
        "identity_transition_preview($2,$4::bigint,$6,$7::text::uuid)"
    };
    let sql = format!(
        "SELECT q.s, CASE WHEN q.s = 200 THEN {call}::text END \
         FROM (SELECT CASE WHEN admin_can_reach($2,$4::bigint) THEN 200 ELSE 404 END AS s \
               WHERE $1::bigint > 0 AND $3::text <> '') q"
    );
    setjoin_pg::run_receipted_command(
        worker,
        command("identity_transition_preview"),
        &envelope(
            &auth,
            operation,
            &format!("preview:{user}:{target_link:?}:{key}:{reason}"),
        ),
        &auth,
        deadline(),
        &sql,
        &[
            (&user, Type::INT8),
            (&target_link, Type::INT8),
            (&reason, Type::TEXT),
            (&key, Type::TEXT),
        ],
        verdict,
    )
    .await
}

/// Go's `validIdentityDigest`: 64 lowercase hex characters.
pub fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `jwtutil.VerifyFreshAAL2` with `CurrentFreshAAL2Policy` over a verified token, then the
/// two SHA-256 bindings the challenge-complete reducer stores (`identityTransitionStepUpBindings`).
/// `None` is Go's 403. `now` is Unix seconds with fractions.
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
    // ACRSatisfies(acr, "aal2"): only aal2 ranks at the requirement.
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

/// `time.Unix(secs,0).UTC().Format(time.RFC3339Nano)`.
fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rest = secs.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
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
