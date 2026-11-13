//! Typed identity response validation mirrors frozen Go; unknown additive fields are ignored.
use crate::{
    client::Failure,
    part_b::{array, number, text, uuid},
};
use serde_json::Value;
pub(super) fn positive(s: &str) -> bool {
    !s.is_empty() && !s.starts_with(['0', '+', '-']) && s.parse::<u64>().is_ok_and(|n| n > 0)
}
pub(super) fn valid_uuid(s: &str) -> bool {
    uuid(s).is_some_and(|s| s != "00000000-0000-0000-0000-000000000000")
}
pub(super) fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn time(s: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(s).is_ok() && s.get(17..19).is_some_and(|s| s < "60")
}
fn opt_time(v: &Value) -> bool {
    v.is_null() || v.as_str().is_some_and(time)
}
fn bounded(v: &Value, k: &str, max: usize) -> bool {
    let s = text(v, k);
    !s.is_empty() && s.len() <= max
}
fn nonnegative(v: &Value, k: &str) -> bool {
    v[k].as_i64().is_some_and(|n| n >= 0)
}
fn kind(s: &str) -> bool {
    ["local", "ad", "ldap", "scim", "saml", "oidc"].contains(&s)
}
fn source_state(s: &str) -> bool {
    ["draft", "validated", "active", "paused", "error", "retired"].contains(&s)
}
pub(super) fn validate(shape: &str, v: &Value) -> Result<(), Failure> {
    match shape {
        "identitySourceList" => {
            let items = v["items"]
                .as_array()
                .ok_or("identity response is missing required field \"items\"")?;
            if items.len() > 200 {
                return Err(format!(
                    "identity source response has {} items; maximum is 200",
                    items.len()
                )
                .into());
            }
            for (i, r) in items.iter().enumerate() {
                if !bounded(r, "sourceKey", 64)
                    || !bounded(r, "displayName", 255)
                    || !kind(text(r, "kind"))
                    || !source_state(text(r, "state"))
                    || !positive(text(r, "generation"))
                    || !r["capabilities"].is_object()
                    || !nonnegative(r, "attentionCount")
                    || !opt_time(&r["lastSuccessAt"])
                    || !opt_time(&r["lastFailureAt"])
                {
                    return Err(format!("identity source response item {i} is missing or has an invalid required field").into());
                }
            }
        }
        "identityPeopleList" => {
            for (i, r) in list_items(v, "people")?.iter().enumerate() {
                if !positive(text(r, "userId"))
                    || !email(text(r, "email"))
                    || !r["enabled"].is_boolean()
                    || !["local", "source"].contains(&text(r, "lifecycleAuthority"))
                    || !(0..=8).contains(&number(r, "activeLinks"))
                    || number(r, "detachedLinks") < 0
                {
                    return Err(format!("identity people response item {i} is missing or has an invalid required field").into());
                }
            }
        }
        "identityConflictList" => {
            for (i, r) in list_items(v, "conflict")?.iter().enumerate() {
                if !valid_uuid(text(r, "id"))
                    || !bounded(r, "sourceKey", 64)
                    || !["hard", "composite", "soft", "conflict"]
                        .contains(&text(r, "evidenceClass"))
                    || ![
                        "pending", "linked", "new", "rejected", "deferred", "expired",
                    ]
                    .contains(&text(r, "state"))
                    || !positive(text(r, "generation"))
                    || !bounded(r, "explanation", 1024)
                    || (!text(r, "createdAt").is_empty() && !time(text(r, "createdAt")))
                    || (!text(r, "expiresAt").is_empty() && !time(text(r, "expiresAt")))
                {
                    return Err(format!("identity conflict response item {i} is missing or has an invalid required field").into());
                }
            }
        }
        "identityTransitionList" => {
            for (i, r) in list_items(v, "transition")?.iter().enumerate() {
                if !valid_uuid(text(r, "id"))
                    || !positive(text(r, "userId"))
                    || text(r, "kind") != "directory_to_local"
                    || text(r, "state").is_empty()
                    || !bounded(r, "sourceKey", 64)
                    || !r["protected"].is_boolean()
                    || !nonnegative(r, "pendingEffects")
                    || number(r, "pendingEffects") > 3
                    || (!text(r, "createdAt").is_empty() && !time(text(r, "createdAt")))
                    || (!text(r, "updatedAt").is_empty() && !time(text(r, "updatedAt")))
                {
                    return Err(format!("identity transition response item {i} is missing or has an invalid required field").into());
                }
            }
        }
        "identityEventList" => {
            for (i, r) in list_items(v, "event")?.iter().enumerate() {
                if !positive(text(r, "id"))
                    || !time(text(r, "occurredAt"))
                    || text(r, "action").is_empty()
                    || !bounded(r, "reason", 1024)
                    || !valid_uuid(text(r, "correlationId"))
                    || ["userId", "linkId"]
                        .iter()
                        .any(|k| !r[*k].is_null() && !positive(text(r, k)))
                    || (!r["transitionId"].is_null() && !valid_uuid(text(r, "transitionId")))
                    || (!r["sourceKey"].is_null() && !bounded(r, "sourceKey", 64))
                {
                    return Err(format!("identity event response item {i} is missing or has an invalid required field").into());
                }
            }
        }
        "identitySourceDetail" => {
            if !bounded(v, "sourceKey", 64)
                || !bounded(v, "displayName", 128)
                || !kind(text(v, "kind"))
                || !source_state(text(v, "state"))
                || !positive(text(v, "generation"))
                || !positive(text(v, "mappingVersion"))
                || !v["capabilities"].is_object()
                || !v["document"].is_object()
                || !v["secretConfigured"].is_object()
                || !opt_time(&v["lastSuccessAt"])
                || !opt_time(&v["lastFailureAt"])
            {
                return Err(
                    "identity source detail is missing or has an invalid required field".into(),
                );
            }
            if v["secretConfigured"]
                .as_object()
                .unwrap()
                .keys()
                .any(|k| k.is_empty() || k.len() > 64)
            {
                return Err("identity source detail has an invalid secret name".into());
            }
        }
        "identitySourcePlanResult" => {
            if !bounded(v, "sourceKey", 64)
                || !v["create"].is_boolean()
                || !v["changed"].is_boolean()
                || !v["desired"].is_object()
                || !v["operations"].is_array()
                || array(&v["operations"]).len() > 2
                || (!v["currentGeneration"].is_null() && !positive(text(v, "currentGeneration")))
            {
                return Err(
                    "identity source plan is missing or has an invalid required field".into(),
                );
            }
            if array(&v["operations"]).iter().any(|x| {
                ![
                    "create_draft",
                    "update_draft_config",
                    "increment_generation",
                ]
                .contains(&x.as_str().unwrap_or(""))
            }) {
                return Err("identity source plan contains an unknown operation".into());
            }
        }
        "identitySourceMutationResult" => {
            if v["valid"] == false {
                if !bounded(v, "sourceKey", 64)
                    || !["not_required", "reachable", "failed"].contains(&text(v, "transport"))
                    || v["personWrites"].as_i64() != Some(0)
                    || !v["blockers"].is_array()
                    || !secret_posture(&v["secretConfigured"])
                {
                    return Err("identity source dry-run blocker response is invalid".into());
                }
                return Ok(());
            }
            if !text(v, "sourceId").is_empty() && !positive(text(v, "sourceId")) {
                return Err("identity source mutation has an invalid sourceId".into());
            }
            if !bounded(v, "sourceKey", 64)
                || !source_state(text(v, "state"))
                || !positive(text(v, "generation"))
                || !v["replayed"].is_boolean()
            {
                return Err(
                    "identity source mutation is missing or has an invalid required field".into(),
                );
            }
            if !text(v, "secretName").is_empty() && v["secretConfigured"] != true {
                return Err(
                    "identity source secret mutation has invalid configured posture".into(),
                );
            }
            if !v["valid"].is_null() && !secret_posture(&v["secretConfigured"]) {
                return Err("identity source dry-run has invalid secret posture".into());
            }
            if !v["personWrites"].is_null() && number(v, "personWrites") != 0 {
                return Err("identity source dry-run reported person writes".into());
            }
        }
        "identityPersonDetail" => {
            let life = &v["lifecycleAuthority"];
            let recovery = &v["recovery"];
            if !positive(text(v, "userId"))
                || !email(text(v, "email"))
                || !v["enabled"].is_boolean()
                || !v["protected"].is_boolean()
                || text(v, "relationship") != "member"
                || !["local", "source"].contains(&text(life, "kind"))
                || !positive(text(life, "generation"))
                || !recovery["hasLocalPassword"].is_boolean()
                || !nonnegative(recovery, "passkeyCount")
                || !nonnegative(recovery, "activeAuthenticationLinks")
                || number(recovery, "activeAuthenticationLinks") > 8
                || [
                    ("links", 100),
                    ("fieldAuthority", 64),
                    ("entitlementProvenance", 500),
                    ("transitionHistory", 50),
                    ("linkHistory", 100),
                ]
                .iter()
                .any(|(k, n)| !v[*k].is_array() || array(&v[*k]).len() > *n)
            {
                return Err(
                    "identity person detail is missing or has an invalid required field".into(),
                );
            }
            if text(life, "kind") == "local" {
                if !life["linkId"].is_null() || !life["sourceKey"].is_null() {
                    return Err(
                        "identity person detail has an invalid local lifecycle authority".into(),
                    );
                }
            } else if !positive(text(life, "linkId")) || !bounded(life, "sourceKey", 64) {
                return Err(
                    "identity person detail has an invalid source lifecycle authority".into(),
                );
            }
            for r in array(&v["links"]) {
                if !positive(text(r, "id"))
                    || !bounded(r, "sourceKey", 64)
                    || !kind(text(r, "sourceKind"))
                    || array(&r["purposes"]).is_empty()
                    || array(&r["purposes"]).len() > 2
                    || ![
                        "candidate",
                        "active",
                        "suspended",
                        "detaching",
                        "detached",
                        "conflict",
                    ]
                    .contains(&text(r, "state"))
                    || !positive(text(r, "generation"))
                    || !["backfill", "jit", "connector", "operator", "transition"]
                        .contains(&text(r, "linkMethod"))
                    || !hex(text(r, "subjectFingerprint"), 16)
                    || !time(text(r, "firstSeenAt"))
                    || !time(text(r, "lastSeenAt"))
                    || !opt_time(&r["detachedAt"])
                {
                    return Err("identity person detail contains an invalid link".into());
                }
                let p = array(&r["purposes"]);
                if p.iter().enumerate().any(|(i, v)| {
                    !["authenticate", "provision"].contains(&v.as_str().unwrap_or(""))
                        || p[..i].contains(v)
                }) {
                    return Err("identity person detail contains invalid link purposes".into());
                }
            }
            for r in array(&v["fieldAuthority"]) {
                if !bounded(r, "field", 64)
                    || !["local", "source"].contains(&text(r, "authorityKind"))
                    || !positive(text(r, "generation"))
                    || (!r["linkId"].is_null() && !positive(text(r, "linkId")))
                    || (!r["sourceKey"].is_null() && !bounded(r, "sourceKey", 64))
                    || !["none", "override", "writeback_pending", "conflict"]
                        .contains(&text(r, "localOverrideState"))
                {
                    return Err("identity person detail contains invalid field authority".into());
                }
            }
            for r in array(&v["entitlementProvenance"]) {
                if ["id", "targetId", "entitlementId", "sourceGeneration"]
                    .iter()
                    .any(|k| !positive(text(r, k)))
                    || (!r["linkId"].is_null() && !positive(text(r, "linkId")))
                    || !opt_time(&r["validUntil"])
                    || !opt_time(&r["revokedAt"])
                {
                    return Err(
                        "identity person detail contains invalid entitlement provenance".into(),
                    );
                }
            }
            for r in array(&v["transitionHistory"]) {
                if !valid_uuid(text(r, "id"))
                    || !positive(text(r, "generation"))
                    || !time(text(r, "createdAt"))
                    || !time(text(r, "updatedAt"))
                    || !opt_time(&r["completedAt"])
                {
                    return Err("identity person detail contains invalid transition history".into());
                }
            }
            for r in array(&v["linkHistory"]) {
                if !positive(text(r, "id"))
                    || !time(text(r, "occurredAt"))
                    || !bounded(r, "reason", 1024)
                    || !valid_uuid(text(r, "correlationId"))
                    || (!r["linkId"].is_null() && !positive(text(r, "linkId")))
                {
                    return Err("identity person detail contains invalid link history".into());
                }
            }
        }

        "identityConflictDetail" => {
            let s = &v["source"];
            if !valid_uuid(text(v, "id"))
                || !bounded(s, "sourceKey", 64)
                || !bounded(s, "displayName", 128)
                || !kind(text(s, "kind"))
                || !source_state(text(s, "state"))
                || !positive(text(s, "generation"))
                || !hex(text(v, "subjectFingerprint"), 16)
                || !["hard", "composite", "soft", "conflict"].contains(&text(v, "evidenceClass"))
                || !hex(text(v, "evidenceDigest"), 64)
                || !bounded(v, "explanation", 512)
                || ![
                    "pending", "linked", "new", "rejected", "deferred", "expired",
                ]
                .contains(&text(v, "state"))
                || !positive(text(v, "generation"))
                || !time(text(v, "createdAt"))
                || !time(text(v, "expiresAt"))
                || !opt_time(&v["decidedAt"])
                || !v["allowedDecisions"].is_array()
                || array(&v["allowedDecisions"]).len() > 3
                || !v["decisionHistory"].is_array()
                || array(&v["decisionHistory"]).len() > 50
            {
                return Err(
                    "identity conflict detail is missing or has an invalid required field".into(),
                );
            }
            let p = &v["candidatePerson"];
            if !p.is_null()
                && (!positive(text(p, "userId"))
                    || !email(text(p, "email"))
                    || !p["enabled"].is_boolean()
                    || !p["protected"].is_boolean())
            {
                return Err("identity conflict detail has an invalid candidate person".into());
            }
            let d = array(&v["allowedDecisions"]);
            if d.iter().enumerate().any(|(i, v)| {
                !["link", "create", "reject", "defer"].contains(&v.as_str().unwrap_or(""))
                    || d[..i].contains(v)
            }) {
                return Err("identity conflict detail has invalid allowed decisions".into());
            }
            for r in array(&v["decisionHistory"]) {
                if !positive(text(r, "id"))
                    || !["link", "create", "reject", "defer"].contains(&text(r, "decision"))
                    || !bounded(r, "reason", 1024)
                    || ["personId", "linkId"]
                        .iter()
                        .any(|k| !r[*k].is_null() && !positive(text(r, k)))
                    || !positive(text(r, "decidedBy"))
                    || !time(text(r, "occurredAt"))
                {
                    return Err("identity conflict detail contains invalid decision history".into());
                }
            }
        }

        "identityConflictDecisionResult" => {
            if !valid_uuid(text(v, "id"))
                || !["linked", "new", "rejected", "deferred"].contains(&text(v, "state"))
                || !positive(text(v, "generation"))
                || !v["replayed"].is_boolean()
                || ["personId", "linkId"]
                    .iter()
                    .any(|k| !v[*k].is_null() && !positive(text(v, k)))
            {
                return Err("identity conflict decision response is missing or invalid".into());
            }
            if ["linked", "new"].contains(&text(v, "state"))
                && (v["personId"].is_null() || v["linkId"].is_null())
            {
                return Err(
                    "identity conflict decision response is missing its resulting link".into(),
                );
            }
        }
        "identityTransitionPreview" => {
            if !valid_uuid(text(v, "transitionId"))
                || !transition_state(text(v, "state"))
                || !hex(text(v, "previewDigest"), 64)
                || [
                    "transitionGeneration",
                    "previewVersion",
                    "sourceGeneration",
                    "linkGeneration",
                    "lifecycleGeneration",
                ]
                .iter()
                .any(|k| !positive(text(v, k)))
                || !time(text(v, "previewExpiresAt"))
                || !v["protected"].is_boolean()
                || !v["recoveryReady"].is_boolean()
            {
                return Err("identity transition preview response is missing or has an invalid required field".into());
            }
        }
        "identityTransitionDetail" => {
            if !valid_uuid(text(v, "transitionId"))
                || !valid_uuid(text(v, "correlationId"))
                || !positive(text(v, "personId"))
                || text(v, "type") != "directory_to_local"
                || !transition_state(text(v, "state"))
                || !positive(text(v, "transitionGeneration"))
                || !positive(text(v, "previewVersion"))
                || !hex(text(v, "previewDigest"), 64)
                || !time(text(v, "previewExpiresAt"))
                || !v["protected"].is_boolean()
                || (!v["approvalRequestId"].is_null() && !positive(text(v, "approvalRequestId")))
                || text(&v["rollback"], "boundary").is_empty()
                || array(&v["steps"]).len() > 15
                || array(&v["effects"]).len() > 6
            {
                return Err("identity transition detail response is missing or has an invalid required field".into());
            }
            let r = &v["rollback"];
            if ![
                "not_committed",
                "reversible",
                "new_login_observed",
                "irreversible_effect",
                "window_expired",
                "rolled_back",
            ]
            .contains(&text(r, "boundary"))
                || (!r["previewDigest"].is_null() && !hex(text(r, "previewDigest"), 64))
                || !opt_time(&r["previewExpiresAt"])
                || (!r["approvalRequestId"].is_null() && !positive(text(r, "approvalRequestId")))
            {
                return Err("identity transition detail has an invalid rollback state".into());
            }
            if array(&v["steps"]).iter().any(|s| !s.is_object()) {
                return Err("identity transition detail steps must be objects".into());
            }
            for e in array(&v["effects"]) {
                if !valid_uuid(text(e, "effectId"))
                    || ![
                        "auth_sessions",
                        "livekit_sessions",
                        "subscriber_notice",
                        "rollback_auth_sessions",
                        "rollback_livekit_sessions",
                        "rollback_subscriber_notice",
                    ]
                    .contains(&text(e, "kind"))
                    || !["pending", "running", "completed", "failed", "disposed"]
                        .contains(&text(e, "state"))
                    || !(0..=20).contains(&number(e, "attemptCount"))
                    || !time(text(e, "nextAttemptAt"))
                    || !opt_time(&e["completedAt"])
                {
                    return Err("identity transition detail contains an invalid effect".into());
                }
            }
        }

        "identityTransitionChallenge" => {
            if !valid_uuid(text(v, "challengeId"))
                || !valid_uuid(text(v, "transitionId"))
                || !positive(text(v, "transitionGeneration"))
                || !hex(text(v, "previewDigest"), 64)
                || !time(text(v, "expiresAt"))
                || text(v, "handoffMethod") != "browser"
                || text(v, "displayCode").len() != 8
                || !v["completed"].is_boolean()
                || !v["invalidated"].is_boolean()
            {
                return Err("identity transition challenge response is missing or invalid".into());
            }
        }
        "identityTransitionElevation" => {
            if ["challengeId", "elevationId", "transitionId"]
                .iter()
                .any(|k| !valid_uuid(text(v, k)))
                || !positive(text(v, "transitionGeneration"))
                || !time(text(v, "expiresAt"))
                || ["consumed", "invalidated", "replayed"]
                    .iter()
                    .any(|k| !v[*k].is_boolean())
            {
                return Err("identity transition elevation response is missing or invalid".into());
            }
        }
        "identityDoctor" => {
            if !time(text(v, "generatedAt"))
                || !v["passed"].is_boolean()
                || !nonnegative(v, "blockingCount")
                || array(&v["checks"]).is_empty()
                || array(&v["checks"]).len() > 32
                || (!v["sourceKey"].is_null() && !bounded(v, "sourceKey", 64))
            {
                return Err(
                    "identity doctor response is missing or has an invalid required field".into(),
                );
            }
            let mut blockers = 0;
            for (i, c) in array(&v["checks"]).iter().enumerate() {
                doctor_check(c).map_err(|e| format!("identity doctor check {i}: {e}"))?;
                if text(c, "severity") == "blocker" && c["passed"] == false {
                    blockers += 1;
                }
            }
            if blockers != number(v, "blockingCount") || v["passed"] != (blockers == 0) {
                return Err("identity doctor response has inconsistent blocker totals".into());
            }
        }
        "identityJob" => {
            if !valid_uuid(text(v, "jobId"))
                || !valid_uuid(text(v, "snapshotId"))
                || !["upgrade_backfill", "diagnostics", "cohort_preview"].contains(&text(v, "kind"))
                || ![
                    "queued",
                    "running",
                    "completed",
                    "completed_with_failures",
                    "failed",
                    "cancelled",
                    "expired",
                ]
                .contains(&text(v, "state"))
                || !time(text(v, "createdAt"))
                || !time(text(v, "expiresAt"))
                || !v["progress"].is_object()
                || !bounded(v, "nextAction", 256)
                || !v["terminal"].is_boolean()
                || !v["cancelRequested"].is_boolean()
                || (!v["sourceKey"].is_null() && !bounded(v, "sourceKey", 64))
                || (!v["transitionId"].is_null() && !valid_uuid(text(v, "transitionId")))
            {
                return Err(
                    "identity job response is missing or has an invalid required field".into(),
                );
            }
            let terminal = [
                "completed",
                "completed_with_failures",
                "failed",
                "cancelled",
                "expired",
            ]
            .contains(&text(v, "state"));
            if v["terminal"] != terminal {
                return Err("identity job response has an inconsistent terminal state".into());
            }
            if !v["byteCount"].is_null() && !(0..=(25 << 20)).contains(&number(v, "byteCount")) {
                return Err("identity job response has an invalid byte count".into());
            }
            if !text(v, "sha256").is_empty() && !hex(text(v, "sha256"), 64) {
                return Err("identity job response has an invalid checksum".into());
            }
            if !["", "1"].contains(&text(v, "manifestVersion")) {
                return Err("identity job response has an unsupported manifest version".into());
            }
            if let Some(o) = v["redactionCounts"].as_object() {
                if o.len() > 16 {
                    return Err("identity job response exceeds the redaction-count bound".into());
                }
                if o.values().any(|v| v.as_i64().unwrap_or(0) < 0) {
                    return Err("identity job response has a negative redaction count".into());
                }
            }
            if text(v, "kind") == "diagnostics"
                && text(v, "state") == "completed"
                && (text(v, "manifestVersion") != "1"
                    || v["byteCount"].is_null()
                    || text(v, "sha256").is_empty())
            {
                return Err("completed identity diagnostic job is missing artifact facts".into());
            }
        }

        "identityJobResults" => {
            if !v["items"].is_array()
                || array(&v["items"]).len() > 500
                || (!v["nextSequence"].is_null() && !positive(text(v, "nextSequence")))
            {
                return Err("identity job results response is missing or invalid".into());
            }
            let mut last = 0;
            for (i, r) in array(&v["items"]).iter().enumerate() {
                let seq = text(r, "sequence").parse::<u64>().ok();
                if seq.is_none_or(|n| n == 0 || n <= last)
                    || (!r["userId"].is_null() && !positive(text(r, "userId")))
                    || !["completed", "failed", "skipped", "blocked"].contains(&text(r, "state"))
                    || !r["result"].is_object()
                    || !time(text(r, "createdAt"))
                {
                    return Err(format!("identity job result {i} is invalid").into());
                }
                last = seq.unwrap();
            }
            if let Some(r) = array(&v["items"]).last() {
                if text(v, "nextSequence") != text(r, "sequence") {
                    return Err("identity job results response has an invalid next sequence".into());
                }
            }
        }
        "identityUpgradeStatus" => {
            if number(v, "schemaVersion") < 164
                || [
                    "masterEnabled",
                    "normalizedReadsEnabled",
                    "transitionsEnabled",
                ]
                .iter()
                .any(|k| !v[*k].is_boolean())
                || ["total", "shadow", "canary", "normalized", "cohortMembers"]
                    .iter()
                    .any(|k| !nonnegative(&v["sources"], k))
                || ["criticalDivergences", "pendingCandidates", "pendingEffects"]
                    .iter()
                    .any(|k| !nonnegative(&v["blockers"], k))
            {
                return Err(
                    "identity upgrade status response is missing or has an invalid required field"
                        .into(),
                );
            }
        }
        "identityUpgradePreflight" => {
            if text(v, "manifestVersion") != "1"
                || !time(text(v, "generatedAt"))
                || text(v, "phase") != "preflight"
                || array(&v["checks"]).is_empty()
                || array(&v["checks"]).len() > 32
                || !v["blockers"].is_array()
                || array(&v["blockers"]).len() > 32
                || !v["safeToBackfill"].is_boolean()
                || ["identityModelV2", "normalizedReads", "transitions"]
                    .iter()
                    .any(|k| !v["featureFlags"][*k].is_boolean())
                || !nonnegative(&v["estimates"], "people")
                || v["estimates"]["maximumBatchSize"] != 500
                || v["estimates"]["maximumDurationSeconds"] != 900
                || !hex(text(v, "sha256"), 64)
            {
                return Err("identity upgrade preflight response is missing or invalid".into());
            }
            let mut failed = std::collections::BTreeSet::new();
            for (i, c) in array(&v["checks"]).iter().enumerate() {
                doctor_check(c)
                    .map_err(|e| format!("identity upgrade preflight check {i}: {e}"))?;
                if text(c, "severity") == "blocker" && c["passed"] == false {
                    failed.insert(text(c, "name"));
                }
            }
            if v["safeToBackfill"] != array(&v["blockers"]).is_empty()
                || failed.len() != array(&v["blockers"]).len()
            {
                return Err("identity upgrade preflight has inconsistent blocker totals".into());
            }
            for b in array(&v["blockers"]) {
                if !failed.contains(b.as_str().unwrap_or("")) {
                    return Err("identity upgrade preflight names an unknown blocker".into());
                }
            }
        }
        "identityUpgradeShadow" => {
            if !bounded(v, "sourceKey", 64)
                || !v["eligible"].is_boolean()
                || !nonnegative(v, "completedSyncs")
                || v["requiredSyncs"] != 7
                || number(v, "completedSyncs") > number(v, "requiredSyncs")
                || v["windowHours"].as_f64().is_none_or(|n| n < 0.0)
                || v["requiredWindowHours"] != 24
                || [
                    "criticalDivergences",
                    "missingProjections",
                    "undispositionedAmbiguities",
                ]
                .iter()
                .any(|k| !nonnegative(v, k))
                || !opt_time(&v["windowStartedAt"])
                || !bounded(v, "nextAction", 256)
            {
                return Err("identity upgrade shadow response is missing or invalid".into());
            }
        }
        "identityUpgradeCanaryResult" => {
            if !bounded(v, "sourceKey", 64)
                || !positive(text(v, "generation"))
                || !["shadow", "canary"].contains(&text(v, "readMode"))
                || !nonnegative(v, "cohortSize")
                || number(v, "cohortSize") > 500
            {
                return Err(
                    "identity canary response is missing or has an invalid required field".into(),
                );
            }
        }
        "identityUpgradeRollbackResult" => {
            if v["rolledBack"] != true || !nonnegative(v, "pendingEffects") {
                return Err(
                    "identity rollback response is missing or has an invalid required field".into(),
                );
            }
        }
        "identityUpgradeRetirementCheck" => {
            if !v["ready"].is_boolean()
                || v["destructiveMigrationIncluded"] != false
                || array(&v["checks"]).is_empty()
                || array(&v["checks"]).len() > 16
                || !bounded(v, "nextAction", 256)
            {
                return Err("identity upgrade retirement response is missing or invalid".into());
            }
            let mut passed = true;
            for (i, c) in array(&v["checks"]).iter().enumerate() {
                if !bounded(c, "name", 128)
                    || !c["passed"].is_boolean()
                    || !bounded(c, "nextAction", 256)
                {
                    return Err(format!("identity retirement check {i} is invalid").into());
                }
                passed &= c["passed"] == true;
            }
            if v["ready"] != passed {
                return Err(
                    "identity upgrade retirement response has inconsistent readiness".into(),
                );
            }
        }
        "identityTransitionReport" => {
            if v["schemaVersion"] != 1
                || !time(text(v, "generatedAt"))
                || v["transition"].is_null()
                || !v["effects"].is_array()
                || !v["events"].is_array()
            {
                return Err("identity transition report response is missing or has an invalid required field".into());
            }
            if array(&v["effects"]).len() > 6 || array(&v["events"]).len() > 100 {
                return Err(
                    "identity transition report exceeds the documented response bounds".into(),
                );
            }
            if !v["transition"].is_object() {
                return Err("identity transition report transition must be an object".into());
            }
            if array(&v["effects"]).iter().any(|x| !x.is_object()) {
                return Err("identity transition report effects must be objects".into());
            }
            if array(&v["events"]).iter().any(|x| !x.is_object()) {
                return Err("identity transition report events must be objects".into());
            }
        }
        "identityInventoryExport" => {
            if text(v, "manifestVersion") != "1"
                || number(v, "schemaVersion") < 167
                || !time(text(v, "generatedAt"))
                || text(v, "redactionPolicy") != "identity-inventory-v1"
                || !hex(text(v, "sha256"), 64)
                || ["sources", "people", "conflicts"]
                    .iter()
                    .any(|k| !v[*k].is_array() || array(&v[*k]).len() > 10000)
                || [
                    "emailsOmitted",
                    "externalSubjectsOmitted",
                    "candidateSubjectsOmitted",
                    "secretsOmitted",
                ]
                .iter()
                .any(|k| !nonnegative(&v["redactionCounts"], k))
            {
                return Err(
                    "identity inventory export is missing or has an invalid required field".into(),
                );
            }
            for (i, s) in array(&v["sources"]).iter().enumerate() {
                if !bounded(s, "sourceKey", 64)
                    || !kind(text(s, "kind"))
                    || text(s, "state").is_empty()
                    || !positive(text(s, "generation"))
                    || !["legacy", "shadow", "canary", "normalized"].contains(&text(s, "readMode"))
                    || !nonnegative(s, "activeLinks")
                    || !nonnegative(s, "openConflicts")
                {
                    return Err(format!("identity inventory source {i} is invalid").into());
                }
            }
            for (i, p) in array(&v["people"]).iter().enumerate() {
                if !positive(text(p, "userId"))
                    || !p["enabled"].is_boolean()
                    || !["member", "guest", "unclassified"].contains(&text(p, "accountClass"))
                    || (!p["lifecycleAuthority"].is_null()
                        && !["local", "source"].contains(&text(p, "lifecycleAuthority")))
                    || !nonnegative(p, "activeLinks")
                    || !nonnegative(p, "detachedLinks")
                {
                    return Err(format!("identity inventory person {i} is invalid").into());
                }
            }
            for (i, c) in array(&v["conflicts"]).iter().enumerate() {
                if !valid_uuid(text(c, "id"))
                    || text(c, "sourceKey").is_empty()
                    || !["hard", "composite", "soft", "conflict"]
                        .contains(&text(c, "evidenceClass"))
                    || text(c, "state").is_empty()
                    || !positive(text(c, "generation"))
                    || !time(text(c, "createdAt"))
                    || !time(text(c, "expiresAt"))
                {
                    return Err(format!("identity inventory conflict {i} is invalid").into());
                }
            }
        }
        // identity validation shapes
        _ => {}
    }
    Ok(())
}

fn list_items<'a>(v: &'a Value, label: &str) -> Result<&'a [Value], Failure> {
    let a = v["items"]
        .as_array()
        .ok_or("identity response is missing required field \"items\"")?;
    if a.len() > 200 {
        return Err(format!(
            "identity {label} response has {} items; maximum is 200",
            a.len()
        )
        .into());
    }
    Ok(a)
}
fn email(s: &str) -> bool {
    let Some((local, domain)) = s.rsplit_once('@') else {
        return false;
    };
    if local.is_empty()
        || domain.is_empty()
        || domain.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return false;
    }
    if local.starts_with('"') {
        if !local.ends_with('"') || local.len() < 2 {
            return false;
        }
    } else if local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || local
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "()<>[]:;\\,\"@".contains(c))
    {
        return false;
    }
    domain.starts_with('[') && domain.ends_with(']')
        || domain
            .split('.')
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_alphanumeric() || c == '-'))
}

fn secret_posture(v: &Value) -> bool {
    v.as_object().is_some_and(|o| {
        o.len() <= 1
            && o.iter()
                .all(|(k, v)| !k.is_empty() && k.len() <= 64 && v.is_boolean())
    })
}

fn transition_state(s: &str) -> bool {
    [
        "draft",
        "previewed",
        "awaiting_approval",
        "authorized",
        "executing",
        "authority_committed",
        "effects_pending",
        "completed",
        "failed_precommit",
        "failed_recoverable",
        "rollback_previewed",
        "rolling_back",
        "rolled_back",
        "cancelled",
        "expired",
    ]
    .contains(&s)
}

fn doctor_check(v: &Value) -> Result<(), Failure> {
    if !bounded(v, "name", 128)
        || !["info", "warning", "blocker"].contains(&text(v, "severity"))
        || !v["passed"].is_boolean()
        || !v["facts"].is_object()
        || !bounded(v, "nextAction", 256)
    {
        Err("identity doctor check is missing or has an invalid required field".into())
    } else {
        Ok(())
    }
}
