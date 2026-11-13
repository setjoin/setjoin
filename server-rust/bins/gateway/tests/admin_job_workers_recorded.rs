//! #412: seed-plus-one-tick oracle for the four Admin identity job workers.
//! Frozen Go's real worker (overlays in `tests/conformance/admin-workers/`, run
//! with `go test -overlay` in the CI image) runs one iteration over a seeded
//! database; the Rust worker must leave the same rows, audit rows, NOTIFY
//! payloads, LiveKit calls and (for diagnostics) the same artifact entries.
//! Replay needs no Go.
//!
//! Record: `GOFREE_RECORD_JOBS=all|label,label` (+ `GOFREE_GO_SOURCE`); each case
//! is recorded from Go, then re-seeded and run through Rust and compared
//! unmasked before the golden is written. Goldens are never replaced (delete
//! one to re-record it). `GOFREE_JOBS_LEARN=1` runs Rust only and prints the
//! observation. `GOFREE_JOBS_ONLY=label,label` filters both modes.
mod common;
use common::BoxError;
use serde_json::{json, Map, Value};
use setjoin_conformance::harness::{Db, Listener};
use setjoin_gateway::admin_job_workers::{
    BulkRoleJobs, EapJobs, IdentityOperations, IdentityTransitions, Rooms,
};
use setjoin_pg::workers::WorkerDatabase;
use std::sync::{Arc, Mutex};
use tokio_postgres::{Client, SimpleQueryMessage};

const HMAC: &str = "gofree-admin-jobs-oracle-hmac-key";
const LK_KEY: &str = "oracle-key";
const LK_SECRET: &str = "oracle-secret-oracle-secret-oracle";
const CHANNELS: [&str; 3] = ["identity_transition", "session_revoke", "config_changed"];
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Clone, Copy, PartialEq, Debug)]
enum Lk {
    /// No LiveKit client (the worker has none configured).
    Unset,
    Ok,
    Missing,
    Unavailable,
}

struct Case {
    worker: &'static str,
    label: &'static str,
    seed: Vec<String>,
    lk: Lk,
}

#[derive(Clone)]
struct Ids {
    act: i64,
    t: [i64; 3],
    dom: i64,
    dom2: i64,
    mb: [i64; 3],
    mba: i64,
    person: i64,
}

fn sub(sql: &str, ids: &Ids) -> String {
    sql.replace("$DOM2", &ids.dom2.to_string())
        .replace("$DOM", &ids.dom.to_string())
        .replace("$ACT", &ids.act.to_string())
        .replace("$T1", &ids.t[0].to_string())
        .replace("$T2", &ids.t[1].to_string())
        .replace("$T3", &ids.t[2].to_string())
        .replace("$MBA", &ids.mba.to_string())
        .replace("$MB1", &ids.mb[0].to_string())
        .replace("$MB2", &ids.mb[1].to_string())
        .replace("$MB3", &ids.mb[2].to_string())
        .replace("$P", &ids.person.to_string())
}

/// Fixture ids are far above every counter and count in the observations, so a
/// digit run equal to one is that id.
fn mask(text: &str, ids: &Ids) -> String {
    let names = [
        (ids.act, "<act>"),
        (ids.t[0], "<t1>"),
        (ids.t[1], "<t2>"),
        (ids.t[2], "<t3>"),
        (ids.dom, "<dom>"),
        (ids.dom2, "<dom2>"),
        (ids.mb[0], "<mb1>"),
        (ids.mb[1], "<mb2>"),
        (ids.mb[2], "<mb3>"),
        (ids.mba, "<mba>"),
        (ids.person, "<person>"),
    ];
    let mut out = String::new();
    let mut digits = String::new();
    let flush = |digits: &mut String, out: &mut String| {
        if digits.is_empty() {
            return;
        }
        match names.iter().find(|(id, _)| id.to_string() == *digits) {
            Some((_, name)) => out.push_str(name),
            None => out.push_str(digits),
        }
        digits.clear();
    };
    for c in text.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
        } else {
            flush(&mut digits, &mut out);
            out.push(c);
        }
    }
    flush(&mut digits, &mut out);
    out
}

const BULK_RESET: &str = "DELETE FROM bulk_role_jobs WHERE id BETWEEN 880000 AND 880099; DELETE FROM admin_role_assignments WHERE role_group_id BETWEEN 880000 AND 880099; DELETE FROM admin_role_groups WHERE id BETWEEN 880000 AND 880099";
const EAP_RESET: &str = "DELETE FROM eap_apply_jobs WHERE id BETWEEN 880000 AND 880099; DELETE FROM email_address_policies WHERE id BETWEEN 880000 AND 880099; DELETE FROM aliases WHERE mailbox_id IN ($MB1,$MB2,$MB3,$MBA); DELETE FROM field_policy WHERE user_id IN ($T1,$T2,$T3,$ACT); UPDATE mailboxes m SET email=u.username||'@'||d.name FROM users u, domains d WHERE m.user_id=u.id AND d.id=m.domain_id AND u.username LIKE 'gofree-ajw-%'; UPDATE users SET email=username||'@'||(SELECT name FROM domains WHERE id=users.domain_id) WHERE username LIKE 'gofree-ajw-%'; UPDATE domains SET is_local=true WHERE id IN ($DOM,$DOM2)";
const OPS_RESET: &str = "BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM identity_job_results WHERE job_id::text LIKE 'aaaaaaaa-0000-4000-8000-%'; DELETE FROM identity_jobs WHERE id::text LIKE 'aaaaaaaa-0000-4000-8000-%'; DELETE FROM identity_sources WHERE source_key='gofree-ajw-src'; COMMIT";
const TRANSITIONS_RESET: &str = "BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM identity_link_events WHERE transition_id::text LIKE 'bbbbbbbb-0000-4000-8000-%'; DELETE FROM identity_source_inbox i WHERE i.applied_event_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM identity_link_events e WHERE e.id=i.applied_event_id); DELETE FROM identity_sync_log WHERE source_id IN (SELECT id FROM identity_sources WHERE source_key LIKE 'legacy:%'); UPDATE identity_sources SET last_success_at=NULL WHERE source_key LIKE 'legacy:%' AND last_success_at IS NOT NULL; DELETE FROM identity_transition_effect_targets WHERE transition_id::text LIKE 'bbbbbbbb-0000-4000-8000-%'; DELETE FROM identity_transition_effects WHERE transition_id::text LIKE 'bbbbbbbb-0000-4000-8000-%'; DELETE FROM identity_transition_steps WHERE transition_id::text LIKE 'bbbbbbbb-0000-4000-8000-%'; DELETE FROM identity_transitions WHERE id::text LIKE 'bbbbbbbb-0000-4000-8000-%'; DELETE FROM identity_session_eviction_intents WHERE reason LIKE 'gofree-ajw%'; COMMIT";

fn reset_sql(worker: &str) -> &'static str {
    match worker {
        "bulk-role-jobs" => BULK_RESET,
        "email-address-policy-jobs" => EAP_RESET,
        "identity-operations" => OPS_RESET,
        _ => TRANSITIONS_RESET,
    }
}

fn observe_sql(worker: &str) -> Vec<(&'static str, &'static str)> {
    match worker {
        "bulk-role-jobs" => vec![
            ("jobs", "SELECT id||':'||status||':'||processed||'/'||total||':'||coalesce(error,'')||':'||results::text FROM bulk_role_jobs WHERE id BETWEEN 880000 AND 880099 ORDER BY id"),
            ("assignments", "SELECT user_id||':'||role_group_id||':'||(granted_by=$ACT)||':'||(expires_at IS NULL) FROM admin_role_assignments WHERE role_group_id BETWEEN 880000 AND 880099 AND user_id<>$ACT ORDER BY 1"),
        ],
        "email-address-policy-jobs" => vec![
            ("jobs", "SELECT id||':'||status||':'||applied||':'||(total IS NOT NULL)||':'||coalesce(error,'') FROM eap_apply_jobs WHERE id BETWEEN 880000 AND 880099 ORDER BY id"),
            ("mailboxes", "SELECT m.email FROM mailboxes m JOIN users u ON u.id=m.user_id WHERE u.username LIKE 'gofree-ajw-%' ORDER BY 1"),
            ("users", "SELECT email FROM users WHERE username LIKE 'gofree-ajw-%' ORDER BY 1"),
            ("aliases", "SELECT email FROM aliases WHERE mailbox_id IN ($MB1,$MB2,$MB3,$MBA) ORDER BY 1"),
            ("field-policy", "SELECT user_id||':'||field||':'||policy FROM field_policy WHERE user_id IN ($T1,$T2,$T3,$ACT) ORDER BY 1"),
        ],
        "identity-operations" => vec![
            ("jobs", "SELECT id||':'||kind||':'||state||':'||attempt_count||':'||failure_count||':'||(worker_id IS NULL)||':'||next_action||':'||(progress-'bytes')::text||':'||(artifact IS NOT NULL)||':'||coalesce((artifact_manifest-'createdAt')::text,'')||':'||coalesce(redaction_counts::text,'')||':'||(completed_at IS NOT NULL) FROM identity_jobs WHERE id::text LIKE 'aaaaaaaa-0000-4000-8000-%' ORDER BY id"),
            ("results", "SELECT job_id||':'||sequence||':'||coalesce(user_id::text,'')||':'||state||':'||result::text FROM identity_job_results WHERE job_id::text LIKE 'aaaaaaaa-0000-4000-8000-%' ORDER BY job_id,sequence"),
        ],
        _ => vec![
            ("transitions", "SELECT id||':'||state||':'||coalesce(failure_code,'') FROM identity_transitions WHERE id::text LIKE 'bbbbbbbb-0000-4000-8000-%' ORDER BY id"),
            ("effects", "SELECT transition_id||':'||effect_kind||':'||state||':'||attempt_count||':'||coalesce(last_error_code,'')||':'||(worker_id IS NULL)||':'||(completed_at IS NOT NULL) FROM identity_transition_effects WHERE transition_id::text LIKE 'bbbbbbbb-0000-4000-8000-%' ORDER BY 1"),
            ("targets", "SELECT transition_id||':'||effect_kind||':'||target_key||':'||(completed_at IS NOT NULL)||':'||coalesce(last_error,'') FROM identity_transition_effect_targets WHERE transition_id::text LIKE 'bbbbbbbb-0000-4000-8000-%' ORDER BY 1"),
            ("steps", "SELECT transition_id||':'||stage||':'||state||':'||attempt_count||':'||coalesce(error_code,'') FROM identity_transition_steps WHERE transition_id::text LIKE 'bbbbbbbb-0000-4000-8000-%' ORDER BY 1"),
            ("events", "SELECT transition_id||':'||action||':'||reason FROM identity_link_events WHERE transition_id::text LIKE 'bbbbbbbb-0000-4000-8000-%' ORDER BY id"),
            ("intents", "SELECT identity||':'||attempt_count||':'||(completed_at IS NOT NULL)||':'||(next_attempt_at='infinity')||':'||CASE WHEN next_attempt_at='infinity' OR last_attempt_at IS NULL THEN -1 ELSE floor(extract(epoch FROM next_attempt_at-last_attempt_at)+0.01) END||':'||coalesce(last_error,'') FROM identity_session_eviction_intents WHERE reason LIKE 'gofree-ajw%' ORDER BY identity"),
        ],
    }
}

fn package(worker: &str) -> (&'static str, &'static str) {
    match worker {
        "bulk-role-jobs" => ("bulkroles", "bulkroles_tick_test.go.txt"),
        "email-address-policy-jobs" => ("eapjobs", "eapjobs_tick_test.go.txt"),
        "identity-operations" => ("identityops", "identityops_tick_test.go.txt"),
        _ => ("identitytransition", "identitytransition_tick_test.go.txt"),
    }
}

// ------------------------------------------------------------------ cases

fn job(id: u32, op: &str, role: u32, users: &str, status: &str, minute: u32) -> String {
    format!("INSERT INTO bulk_role_jobs(id,op,role_id,actor_id,user_ids,status,total,created_at) VALUES ({},'{op}',{role},$ACT,ARRAY[{users}]::bigint[],'{status}',cardinality(ARRAY[{users}]::bigint[]),'2026-10-01 10:{minute:02}:00+00')", 880000 + id)
}

fn bulk_setup(actor_domain: &str) -> Vec<String> {
    vec![
        format!("INSERT INTO admin_role_groups(id,name,permissions,domain_scope) OVERRIDING SYSTEM VALUE VALUES (880001,'gofree-ajw-actor','{{users.read,roles.manage}}',{actor_domain}),(880002,'gofree-ajw-target','{{users.read}}',NULL)"),
        "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES ($ACT,880001,$ACT)".into(),
    ]
}

fn eap_setup(policy_domain: &str) -> Vec<String> {
    vec![
        "UPDATE feature_toggles SET enabled=true WHERE key='feature.email_address_policy'".into(),
        format!("INSERT INTO email_address_policies(id,priority,name,enabled,primary_template,cond_domain_ids,created_at,updated_at) VALUES (880001,880001,'gofree-ajw-policy',true,'{{username}}.eap@{{domain}}',ARRAY[{policy_domain}]::bigint[],'2026-10-01T12:00:00Z','2026-10-01T12:00:00Z')"),
    ]
}

fn eap_job(id: u32, policy: &str, status: &str) -> String {
    format!("INSERT INTO eap_apply_jobs(id,policy_id,status,created_at,updated_at) VALUES ({},{policy},'{status}','2026-10-01 10:{:02}:00+00','2026-10-01 10:{:02}:00+00')", 880000 + id, id, id)
}

fn ops_job(n: u32, kind: &str, source: &str, request: &str, progress: &str) -> String {
    let progress = if progress.starts_with('{') {
        format!("'{progress}'::jsonb")
    } else {
        progress.to_owned()
    };
    format!("INSERT INTO identity_jobs(id,kind,actor_user_id,source_id,idempotency_key,request_digest,request,progress,reason,created_at) VALUES ('aaaaaaaa-0000-4000-8000-{n:012}','{kind}',$ACT,{source},gen_random_uuid(),decode(repeat('33',32),'hex'),'{request}'::jsonb,{progress},'gofree oracle',statement_timestamp()-interval '{} seconds')", 60 - n)
}

const OPS_SOURCE: &str = "INSERT INTO identity_sources(id,source_key,display_name,kind,capabilities,state,read_mode,created_at,updated_at) VALUES (880001,'gofree-ajw-src','Gofree Admin Jobs Source','local','{\"authenticate\":true}','active','shadow','2026-10-01T12:00:00Z','2026-10-01T12:00:00Z')";
const OPS_SRC: &str = "(SELECT id FROM identity_sources WHERE source_key='gofree-ajw-src')";

fn transition(n: u32, state: &str, effects: &[(&str, &[(&str, &str)])]) -> Vec<String> {
    let id = format!("bbbbbbbb-0000-4000-8000-{n:012}");
    let mut sql = vec![format!(
        "INSERT INTO identity_transitions(id,user_id,kind,state,source_id,link_id,source_generation,link_generation,lifecycle_generation,preview_digest,preview_snapshot,preview_expires_at,actor_user_id,reason,idempotency_key,request_digest) SELECT '{id}',$P,'directory_to_local','{state}',l.source_id,l.id,1,1,1,decode(repeat('11',32),'hex'),'{{}}'::jsonb,now()+interval '1 hour',$ACT,'gofree oracle',gen_random_uuid(),decode(repeat('22',32),'hex') FROM user_identity_links l WHERE l.user_id=$P LIMIT 1"
    )];
    for (ordinal, (kind, targets)) in effects.iter().enumerate() {
        sql.push(format!("INSERT INTO identity_transition_steps(transition_id,ordinal,stage,state) VALUES ('{id}',{},'{kind}','pending')", ordinal + 4));
        sql.push(format!(
            "INSERT INTO identity_transition_effects(transition_id,effect_kind) VALUES ('{id}','{kind}')"
        ));
        for (key, until) in *targets {
            sql.push(format!("INSERT INTO identity_transition_effect_targets(transition_id,effect_kind,target_key,evict_until) VALUES ('{id}','{kind}','{key}',{until})"));
        }
    }
    sql
}

fn intent(user: &str, attempts: i32, retry_until: &str) -> String {
    format!("INSERT INTO identity_session_eviction_intents(event_id,user_id,reason,room_name,identity,transition_at,retry_until,attempt_count,next_attempt_at) VALUES (gen_random_uuid(),{user},'gofree-ajw','room-{user}','u:'||{user},now()-interval '10 minutes',{retry_until},{attempts},now()-interval '1 second')")
}

fn cases() -> Vec<Case> {
    let mut all = Vec::new();
    let w = "bulk-role-jobs";
    let mut seed = bulk_setup("$DOM");
    seed.extend([
        job(1, "assign", 880002, "$T1,$T2,$T3", "queued", 0),
        job(2, "revoke", 880002, "$T1", "queued", 1),
        job(3, "assign", 880002, "$T2", "done", 2),
        job(4, "assign", 880002, "$T2", "error", 3),
    ]);
    all.push(Case { worker: w, label: "drain-assign-revoke", seed, lk: Lk::Unset });
    let mut seed = bulk_setup("NULL");
    seed.extend([job(1, "assign", 880002, "$T1,999999999", "queued", 0), job(2, "assign", 880002, "$T2", "queued", 1)]);
    all.push(Case { worker: w, label: "reducer-raise-marks-error", seed, lk: Lk::Unset });
    let mut seed = bulk_setup("$DOM");
    seed.extend([job(1, "assign", 880099, "$T1", "queued", 0), job(2, "assign", 880002, "$T1", "queued", 1)]);
    all.push(Case { worker: w, label: "role-deleted", seed, lk: Lk::Unset });
    let mut seed = bulk_setup("$DOM");
    seed.extend([job(1, "assign", 880002, "$T1,$T2", "running", 0)]);
    all.push(Case { worker: w, label: "stale-running-reclaimed", seed, lk: Lk::Unset });
    let mut seed = bulk_setup("$DOM");
    seed.extend([
        "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES ($T1,880002,$ACT),($T2,880002,$ACT)".into(),
        job(1, "revoke", 880002, "$T1,$T2,$T3", "queued", 0),
        "INSERT INTO admin_role_groups(id,name,permissions,domain_scope) OVERRIDING SYSTEM VALUE VALUES (880003,'gofree-ajw-broad','{users.read,users.write}',NULL)".into(),
        job(2, "assign", 880003, "$T1", "queued", 1),
    ]);
    all.push(Case { worker: w, label: "revoke-members-and-actor-lacks-perms", seed, lk: Lk::Unset });
    all.push(Case { worker: w, label: "empty-queue", seed: bulk_setup("$DOM"), lk: Lk::Unset });

    let w = "email-address-policy-jobs";
    let mut seed = eap_setup("$DOM");
    seed.extend([eap_job(1, "880001", "queued"), eap_job(2, "NULL", "queued"), eap_job(3, "NULL", "done")]);
    all.push(Case { worker: w, label: "apply-and-drain", seed, lk: Lk::Unset });
    let mut seed = eap_setup("$DOM2");
    seed.extend(["UPDATE domains SET is_local=false WHERE id=$DOM2".into(), eap_job(1, "NULL", "queued"), eap_job(2, "NULL", "queued")]);
    all.push(Case { worker: w, label: "reducer-error-marks-error", seed, lk: Lk::Unset });
    let mut seed = eap_setup("$DOM");
    seed.extend(["UPDATE feature_toggles SET enabled=false WHERE key='feature.email_address_policy'".into(), eap_job(1, "NULL", "queued")]);
    all.push(Case { worker: w, label: "toggle-off-applies-nothing", seed, lk: Lk::Unset });
    let mut seed = eap_setup("$DOM");
    seed.extend([eap_job(1, "NULL", "running")]);
    all.push(Case { worker: w, label: "stale-running-reclaimed", seed, lk: Lk::Unset });
    all.push(Case { worker: w, label: "empty-queue", seed: eap_setup("$DOM"), lk: Lk::Unset });

    let w = "identity-operations";
    let cursor = "{\"processed\":7,\"linksObserved\":3,\"conflictsRecorded\":0,\"nextAfterUserId\":\"9999999999\"}";
    all.push(Case { worker: w, label: "backfill-accumulates-cursor", seed: vec![ops_job(1, "upgrade_backfill", "NULL", "{}", cursor)], lk: Lk::Unset });
    all.push(Case { worker: w, label: "backfill-items", seed: vec![ops_job(1, "upgrade_backfill", "NULL", "{}", "jsonb_build_object('processed',0,'linksObserved',0,'conflictsRecorded',0,'nextAfterUserId',($P-1)::text)")], lk: Lk::Unset });
    all.push(Case { worker: w, label: "backfill-invalid-cursor-fails-retryable", seed: vec![ops_job(1, "upgrade_backfill", "NULL", "{}", "{\"nextAfterUserId\":\"not-a-number\"}")], lk: Lk::Unset });
    all.push(Case { worker: w, label: "diagnostics-source-artifact", seed: vec![OPS_SOURCE.into(), ops_job(1, "diagnostics", OPS_SRC, "{\"sinceSeconds\":3600}", "{\"processed\":0,\"failed\":0}")], lk: Lk::Unset });
    all.push(Case { worker: w, label: "diagnostics-bad-scope-fails", seed: vec![OPS_SOURCE.into(), ops_job(1, "diagnostics", OPS_SRC, "{\"sinceSeconds\":0}", "{\"processed\":0,\"failed\":0}")], lk: Lk::Unset });
    all.push(Case { worker: w, label: "diagnostics-failure-budget-exhausted", seed: vec![OPS_SOURCE.into(), ops_job(1, "diagnostics", OPS_SRC, "{\"sinceSeconds\":86401}", "{\"processed\":0,\"failed\":0}"), "UPDATE identity_jobs SET failure_count=20 WHERE id::text LIKE 'aaaaaaaa-0000-4000-8000-%'".into()], lk: Lk::Unset });
    all.push(Case { worker: w, label: "oldest-first-one-per-tick", seed: vec![ops_job(2, "upgrade_backfill", "NULL", "{}", cursor), ops_job(1, "upgrade_backfill", "NULL", "{}", cursor)], lk: Lk::Unset });
    all.push(Case { worker: w, label: "empty-queue", seed: vec![], lk: Lk::Unset });

    let w = "identity-transitions";
    let mut seed = transition(1, "effects_pending", &[("auth_sessions", &[]), ("subscriber_notice", &[])]);
    seed.extend(transition(2, "rolling_back", &[("rollback_auth_sessions", &[]), ("rollback_subscriber_notice", &[])]));
    seed.extend(transition(3, "completed", &[("subscriber_notice", &[])]));
    seed.extend(transition(4, "effects_pending", &[("auth_sessions", &[])]));
    seed.push("UPDATE identity_transition_effects SET state='completed',completed_at=now() WHERE transition_id='bbbbbbbb-0000-4000-8000-000000000004'".into());
    all.push(Case { worker: w, label: "notice-and-sessions-settle", seed, lk: Lk::Unset });
    let past = "now()-interval '1 minute'";
    let mut seed = transition(1, "effects_pending", &[("livekit_sessions", &[("room-a|u:1", past), ("room-b|u:2", "NULL")])]);
    all.push(Case { worker: w, label: "livekit-evicts-targets", seed: seed.clone(), lk: Lk::Ok });
    all.push(Case { worker: w, label: "livekit-participant-missing-is-success", seed: seed.clone(), lk: Lk::Missing });
    all.push(Case { worker: w, label: "livekit-unavailable-fails-effect", seed: seed.clone(), lk: Lk::Unavailable });
    all.push(Case { worker: w, label: "livekit-not-configured-fails-effect", seed, lk: Lk::Unset });
    let seed = transition(2, "effects_pending", &[("livekit_sessions", &[("bad-target-without-separator", "NULL")])]);
    all.push(Case { worker: w, label: "livekit-bad-target", seed, lk: Lk::Ok });
    let mut seed = transition(1, "effects_pending", &[("livekit_sessions", &[])]);
    seed.extend(transition(2, "effects_pending", &[("rollback_auth_sessions", &[])]));
    all.push(Case { worker: w, label: "no-targets-and-wrong-phase", seed, lk: Lk::Unset });
    let seed = vec![
        intent("$T1", 0, "now()-interval '1 minute'"),
        intent("$T2", 0, "now()+interval '1 hour'"),
        intent("$T3", 2, "now()-interval '1 minute'"),
    ];
    all.push(Case { worker: w, label: "session-evictions-ok", seed: seed.clone(), lk: Lk::Ok });
    all.push(Case { worker: w, label: "session-evictions-missing", seed: seed.clone(), lk: Lk::Missing });
    let seed = vec![
        intent("$T1", 0, "now()+interval '1 hour'"),
        intent("$T2", 2, "now()+interval '1 hour'"),
        intent("$T3", 19, "now()+interval '1 hour'"),
        intent("$ACT", 59, "now()+interval '1 hour'"),
    ];
    all.push(Case { worker: w, label: "session-evictions-unavailable", seed: seed.clone(), lk: Lk::Unavailable });
    all.push(Case { worker: w, label: "session-evictions-not-configured", seed, lk: Lk::Unset });
    all
}

// ---------------------------------------------------------------- fixture

async fn fixture(owner: &Client) -> Result<Ids, BoxError> {
    owner.batch_execute("DELETE FROM mailboxes WHERE email LIKE 'gofree-ajw-%'; DELETE FROM users WHERE username LIKE 'gofree-ajw-%'; DELETE FROM domains WHERE name LIKE 'gofree-ajw%.test'").await?;
    for table in ["users", "domains", "mailboxes"] {
        owner
            .simple_query(&format!(
                "SELECT setval(pg_get_serial_sequence('{table}','id'), GREATEST((SELECT last_value FROM {0}), 900000000))",
                match table {
                    "users" => "users_id_seq",
                    "domains" => "domains_id_seq",
                    _ => "mailboxes_id_seq",
                }
            ))
            .await?;
    }
    let mut domains = Vec::new();
    for name in ["gofree-ajw.test", "gofree-ajw2.test"] {
        let id: i64 = owner
            .query_one("INSERT INTO domains(name) VALUES ($1) RETURNING id", &[&name])
            .await?
            .get(0);
        domains.push(id);
    }
    let mut users = Vec::new();
    for (name, domain) in [("act", 0), ("t1", 0), ("t2", 0), ("t3", 1)] {
        let username = format!("gofree-ajw-{name}");
        let domain_name = if domain == 0 { "gofree-ajw.test" } else { "gofree-ajw2.test" };
        let email = format!("{username}@{domain_name}");
        let user: i64 = owner.query_one("INSERT INTO users(username,domain_id,email,display_name) VALUES ($1,$2,$3,$1) RETURNING id", &[&username, &domains[domain], &email]).await?.get(0);
        let mailbox: i64 = owner.query_one("INSERT INTO mailboxes(user_id,domain_id,email,display_name,is_primary) VALUES ($1,$2,$3,$4,true) RETURNING id", &[&user, &domains[domain], &email, &username]).await?.get(0);
        users.push((user, mailbox));
    }
    Ok(Ids {
        act: users[0].0,
        t: [users[1].0, users[2].0, users[3].0],
        dom: domains[0],
        dom2: domains[1],
        mb: [users[1].1, users[2].1, users[3].1],
        mba: users[0].1,
        person: 0,
    })
}

async fn person(owner: &Client) -> Result<i64, BoxError> {
    let (id, generation): (i64, i64) = {
        let row = owner
            .query_one(
                "SELECT id,generation FROM identity_sources WHERE source_key='legacy:scim'",
                &[],
            )
            .await?;
        (row.get(0), row.get(1))
    };
    let applied = owner
        .query_one(
            &format!("SELECT identity_source_scim_apply({id},{generation},gen_random_uuid(),'gofree-ajw-subject','{{\"operation\":\"upsert\",\"email\":\"gofree-ajw-person@gofree-ajw.test\",\"displayName\":\"Gofree Ajw Person\",\"enabled\":true}}'::jsonb)::text"),
            &[],
        )
        .await?;
    let value: Value = serde_json::from_str(&applied.get::<_, String>(0))?;
    let user: i64 = value["userId"].as_str().ok_or("no userId")?.parse()?;
    Ok(user)
}

async fn drop_person(owner: &Client, user: i64) -> Result<(), BoxError> {
    owner.batch_execute(&format!(
        "BEGIN; SET LOCAL session_replication_role=replica; \
         DELETE FROM identity_job_results WHERE user_id={user}; \
         DELETE FROM identity_link_events WHERE user_id={user} OR actor_user_id={user} OR link_id IN (SELECT id FROM user_identity_links WHERE user_id={user}); DELETE FROM identity_source_inbox i WHERE i.applied_event_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM identity_link_events e WHERE e.id=i.applied_event_id); DELETE FROM identity_sync_log WHERE source_id IN (SELECT id FROM identity_sources WHERE source_key LIKE 'legacy:%'); UPDATE identity_sources SET last_success_at=NULL WHERE source_key LIKE 'legacy:%' AND last_success_at IS NOT NULL; \
         DELETE FROM identity_attribute_authority WHERE user_id={user}; DELETE FROM identity_entitlement_grants WHERE user_id={user}; \
         DELETE FROM user_lifecycle_authorities WHERE user_id={user}; DELETE FROM user_identity_links WHERE user_id={user}; DELETE FROM sessions WHERE user_id={user}; COMMIT; \
         DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id={user}); DELETE FROM mailboxes WHERE user_id={user}; DELETE FROM users WHERE id={user};"
    )).await?;
    Ok(())
}

// ------------------------------------------------------------------ run

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_job_workers_seed_plus_one_tick() -> Result<(), BoxError> {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(db) = Db::for_case("admin-job-workers-tick") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let record = std::env::var("GOFREE_RECORD_JOBS").ok();
    let only = std::env::var("GOFREE_JOBS_ONLY").ok();
    let learn = std::env::var("GOFREE_JOBS_LEARN").is_ok();
    let listed = |filter: &Option<String>, case: &Case| {
        filter.as_deref().is_none_or(|f| {
            f == "all"
                || f.split(',')
                    .any(|t| t == case.label || t == case.worker || t == case.label_key())
        })
    };
    let toggles: Vec<(String, bool)> = owner
        .query("SELECT key,enabled FROM feature_toggles WHERE key IN ('feature.email_address_policy','feature.identity_model_v2','feature.identity_transitions')", &[])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let mut ids = fixture(&owner).await?;
    owner.execute("UPDATE feature_toggles SET enabled=true WHERE key IN ('feature.identity_model_v2','feature.identity_transitions')", &[]).await?;
    ids.person = person(&owner).await?;
    let mut failures = Vec::new();
    let mut ran = 0;
    for case in cases() {
        let exists = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/conformance/admin-workers/goldens")
            .join(format!("{}__{}.json", case.worker, case.label))
            .exists();
        // A recorded golden is immutable: recording skips it (delete it to re-record).
        let recording = record.is_some() && listed(&record, &case) && !exists;
        if (record.is_some() && !recording) || !listed(&only, &case) {
            continue;
        }
        ran += 1;
        let result = run_case(&db, &owner, &case, &ids, recording, learn).await;
        let _ = reset(&owner, &case, &ids).await;
        if let Err(error) = result {
            failures.push(format!("{}/{}: {error}", case.worker, case.label));
        }
    }
    for sql in [
        "BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM identity_link_events WHERE transition_id::text LIKE 'bbbbbbbb-0000-4000-8000-%'; DELETE FROM identity_source_inbox i WHERE i.applied_event_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM identity_link_events e WHERE e.id=i.applied_event_id); DELETE FROM identity_sync_log WHERE source_id IN (SELECT id FROM identity_sources WHERE source_key LIKE 'legacy:%'); UPDATE identity_sources SET last_success_at=NULL WHERE source_key LIKE 'legacy:%' AND last_success_at IS NOT NULL; COMMIT".to_owned(),
        BULK_RESET.to_owned(),
        sub(EAP_RESET, &ids),
    ] {
        let _ = owner.batch_execute(&sub(&sql, &ids)).await;
    }
    let _ = drop_person(&owner, ids.person).await;
    for (key, enabled) in toggles {
        owner.execute("UPDATE feature_toggles SET enabled=$2 WHERE key=$1", &[&key, &enabled]).await?;
    }
    owner.batch_execute(&format!(
        "DELETE FROM admin_role_assignments WHERE user_id IN ({0},{1},{2},{3}); DELETE FROM mailboxes WHERE user_id IN ({0},{1},{2},{3}); DELETE FROM users WHERE id IN ({0},{1},{2},{3}); DELETE FROM domains WHERE id IN ({4},{5})",
        ids.act, ids.t[0], ids.t[1], ids.t[2], ids.dom, ids.dom2
    )).await?;
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(ran > 0, "no case selected");
    Ok(())
}

impl Case {
    fn label_key(&self) -> String {
        format!("{}:{}", self.worker, self.label)
    }
}

async fn reset(owner: &Client, case: &Case, ids: &Ids) -> Result<(), BoxError> {
    // Effects of a transition that completed leave link events; the reset removes them too.
    owner
        .batch_execute(&sub(reset_sql(case.worker), ids))
        .await
        .map_err(|e| format!("reset: {}", db_text(&e)))?;
    Ok(())
}

async fn seed(owner: &Client, case: &Case, ids: &Ids) -> Result<(), BoxError> {
    reset(owner, case, ids).await?;
    for sql in &case.seed {
        if sql.is_empty() {
            continue;
        }
        owner
            .simple_query(&sub(sql, ids))
            .await
            .map_err(|e| format!("seed `{sql}`: {}", db_text(&e)))?;
    }
    Ok(())
}

struct Sfu {
    calls: Arc<Mutex<Vec<String>>>,
    addr: std::net::SocketAddr,
}

async fn sfu(mode: Lk) -> Sfu {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let capture = calls.clone();
    let addr = common::fake_upstream(move |request| {
        let capture = capture.clone();
        async move {
            use http_body_util::BodyExt;
            let authorized = request.headers().contains_key("authorization");
            let path = request.uri().path().to_owned();
            let bytes = request.into_body().collect().await.unwrap().to_bytes();
            let mut fields = Vec::new();
            let mut rest = bytes.as_ref();
            while rest.len() >= 2 {
                let length = rest[1] as usize;
                if rest.len() < 2 + length {
                    break;
                }
                fields.push(String::from_utf8_lossy(&rest[2..2 + length]).into_owned());
                rest = &rest[2 + length..];
            }
            capture.lock().unwrap().push(format!(
                "{path}:{}:auth={authorized}",
                fields.join("|")
            ));
            match mode {
                Lk::Unavailable => hyper::Response::builder()
                    .status(503)
                    .header("content-type", "application/json")
                    .body(common::full("{\"code\":\"unavailable\",\"msg\":\"SFU unavailable\"}"))
                    .unwrap(),
                Lk::Missing => hyper::Response::builder()
                    .status(404)
                    .header("content-type", "application/json")
                    .body(common::full("{\"code\":\"not_found\",\"msg\":\"participant missing\"}"))
                    .unwrap(),
                _ => hyper::Response::builder()
                    .header("content-type", "application/protobuf")
                    .body(common::full(""))
                    .unwrap(),
            }
        }
    })
    .await;
    Sfu { calls, addr }
}

async fn run_case(
    db: &Db,
    owner: &Client,
    case: &Case,
    ids: &Ids,
    recording: bool,
    learn: bool,
) -> Result<(), BoxError> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/admin-workers/goldens")
        .join(format!("{}__{}.json", case.worker, case.label));
    let golden = if recording || learn {
        None
    } else {
        let bytes = std::fs::read(&path).map_err(|e| format!("no golden {}: {e}", path.display()))?;
        Some(serde_json::from_slice::<Value>(&bytes)?)
    };
    let observe = |sfu: Arc<Mutex<Vec<String>>>, base, mask_metrics| {
        let ids = ids.clone();
        let worker = case.worker;
        async move { observe_all(db, owner, worker, &ids, base, sfu, mask_metrics).await }
    };
    let go = if recording {
        seed(owner, case, ids).await?;
        let server = sfu(case.lk).await;
        let mut listeners = Vec::new();
        for channel in CHANNELS {
            listeners.push(db.listen(channel).await?);
        }
        let base = audit_base(owner).await?;
        let before = observe(server.calls.clone(), base, false).await?;
        drain_listeners(owner, &mut listeners).await?;
        let go_url = (case.lk != Lk::Unset).then(|| format!("ws://{}", server.addr));
        record_go_tick(db, case, go_url.as_deref())?;
        let after = observe(server.calls.clone(), base, false).await?;
        let notifies = drain_listeners(owner, &mut listeners).await?;
        Some((before, after, notifies))
    } else {
        None
    };
    seed(owner, case, ids).await?;
    let server = sfu(case.lk).await;
    let mut listeners = Vec::new();
    for channel in CHANNELS {
        listeners.push(db.listen(channel).await?);
    }
    let base = audit_base(owner).await?;
    let before = observe(server.calls.clone(), base, false).await?;
    drain_listeners(owner, &mut listeners).await?;
    native_tick(db, case, (case.lk != Lk::Unset).then_some(server.addr)).await?;
    let after = observe(server.calls.clone(), base, false).await?;
    let notifies = drain_listeners(owner, &mut listeners).await?;
    let mut observation = json!({"before": before, "after": after, "notifies": notifies});
    if let Some((go_before, go_after, go_notifies)) = go {
        let go_observation = json!({"before": go_before, "after": go_after, "notifies": go_notifies});
        setjoin_conformance::golden::compare(&go_observation, &observation)
            .map_err(|e| format!("Rust differs from frozen Go: {e}"))?;
        // The recorded golden masks the database-wide diagnostic metrics.
        let masked = json!({"before": mask_metrics(&go_observation["before"]), "after": mask_metrics(&go_observation["after"]), "notifies": go_observation["notifies"]});
        setjoin_conformance::golden::record(
            &path,
            &json!({"format":1,"worker":case.worker,"case":case.label,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":masked}),
        )?;
        println!("GOLDEN-RECORDED: {} :: {}", case.worker, case.label);
        return Ok(());
    }
    observation = json!({"before": mask_metrics(&observation["before"]), "after": mask_metrics(&observation["after"]), "notifies": observation["notifies"]});
    if learn {
        println!("LEARN {}::{} {}", case.worker, case.label, observation);
        return Ok(());
    }
    setjoin_conformance::golden::compare(&golden.unwrap()["observation"], &observation)?;
    println!("GOLDEN-REPLAY: {} :: {} :: seed-plus-one-tick", case.worker, case.label);
    Ok(())
}

/// The diagnostic evidence's `boundedMetrics` counts are database-wide, so the
/// stored golden hides them (the record step compares them unmasked).
fn mask_metrics(value: &Value) -> Value {
    let mut value = value.clone();
    if let Some(artifacts) = value.get_mut("artifacts").and_then(Value::as_array_mut) {
        for artifact in artifacts {
            if let Some(entries) = artifact.get_mut("entries").and_then(Value::as_array_mut) {
                for entry in entries {
                    if let Some(lines) = entry.get_mut("lines").and_then(Value::as_array_mut) {
                        for line in lines {
                            if line["type"] == "boundedMetrics" {
                                for key in ["jobs", "transitions", "candidates"] {
                                    line[key] = json!("<database-wide>");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    value
}

async fn audit_base(owner: &Client) -> Result<i64, BoxError> {
    Ok(owner
        .query_one("SELECT coalesce(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0))
}

async fn drain_listeners(owner: &Client, listeners: &mut [Listener]) -> Result<Vec<String>, BoxError> {
    let mut out = Vec::new();
    for listener in listeners {
        out.extend(listener.drain(owner).await?);
    }
    out.sort();
    Ok(out)
}

async fn observe_all(
    db: &Db,
    owner: &Client,
    worker: &str,
    ids: &Ids,
    audit_base: i64,
    sfu: Arc<Mutex<Vec<String>>>,
    _mask_metrics: bool,
) -> Result<Value, BoxError> {
    let _ = db;
    let mut rows = Map::new();
    for (label, sql) in observe_sql(worker) {
        let text = text_rows(owner, &sub(sql, ids)).await?;
        rows.insert(
            label.into(),
            json!(text.iter().map(|t| mask(t, ids)).collect::<Vec<_>>()),
        );
    }
    let audit = text_rows(
        owner,
        &format!("SELECT action||':'||coalesce(target_type,'')||':'||coalesce(notes,'') FROM admin_audit_log WHERE id>{audit_base} AND action<>'chat.chain_notary' ORDER BY id"),
    )
    .await?;
    let mut observation = json!({"rows": rows, "audit": audit.iter().map(|t| mask(t, ids)).collect::<Vec<_>>()});
    if worker == "identity-transitions" {
        observation["sfu"] = json!(sfu.lock().unwrap().iter().map(|c| mask(c, ids)).collect::<Vec<_>>());
    }
    if worker == "identity-operations" {
        observation["artifacts"] = artifacts(owner).await?;
    }
    Ok(observation)
}

async fn text_rows(owner: &Client, sql: &str) -> Result<Vec<String>, BoxError> {
    let mut out = Vec::new();
    for message in owner
        .simple_query(sql)
        .await
        .map_err(|e| format!("`{sql}`: {}", db_text(&e)))?
    {
        if let SimpleQueryMessage::Row(row) = message {
            out.push(row.get(0).unwrap_or("<null>").to_string());
        }
    }
    Ok(out)
}

fn db_text(error: &tokio_postgres::Error) -> String {
    error.as_db_error().map_or_else(
        || error.to_string(),
        |d| format!("{} ({})", d.message(), d.code().code()),
    )
}

// ---------------------------------------------------------------- artifacts

/// Every diagnostic artifact in the fixture jobs, as its zip structure and the
/// inflated entries (lines parsed as JSON), with the manifest's `createdAt` masked.
async fn artifacts(owner: &Client) -> Result<Value, BoxError> {
    let rows = owner
        .query("SELECT id::text,artifact,artifact_sha256 FROM identity_jobs WHERE id::text LIKE 'aaaaaaaa-0000-4000-8000-%' AND artifact IS NOT NULL ORDER BY id", &[])
        .await?;
    let mut out = Vec::new();
    for row in rows {
        let id: String = row.get(0);
        let bytes: Vec<u8> = row.get(1);
        let sha: Vec<u8> = row.get(2);
        let digest = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&bytes).to_vec()
        };
        out.push(json!({"job": id, "entries": unzip(&bytes)?, "sha256_matches_artifact": digest == sha}));
    }
    Ok(json!(out))
}

fn le16(b: &[u8], at: usize) -> usize {
    u16::from_le_bytes([b[at], b[at + 1]]) as usize
}
fn le32(b: &[u8], at: usize) -> usize {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as usize
}

fn unzip(bytes: &[u8]) -> Result<Value, BoxError> {
    use std::io::Read;
    let end = bytes.len().checked_sub(22).ok_or("zip too short")?;
    if le32(bytes, end) != 0x0605_4b50 {
        return Err("no end of central directory".into());
    }
    let (entries, mut at) = (le16(bytes, end + 10), le32(bytes, end + 16));
    let mut out = Vec::new();
    for _ in 0..entries {
        if le32(bytes, at) != 0x0201_4b50 {
            return Err("bad central directory entry".into());
        }
        let (creator, reader, flags, method) = (le16(bytes, at + 4), le16(bytes, at + 6), le16(bytes, at + 8), le16(bytes, at + 10));
        let (time, date, crc) = (le16(bytes, at + 12), le16(bytes, at + 14), le32(bytes, at + 16));
        let (csize, usize_) = (le32(bytes, at + 20), le32(bytes, at + 24));
        let (name_len, extra_len, comment_len) = (le16(bytes, at + 28), le16(bytes, at + 30), le16(bytes, at + 32));
        let external = le32(bytes, at + 38);
        let offset = le32(bytes, at + 42);
        let name = String::from_utf8(bytes[at + 46..at + 46 + name_len].to_vec())?;
        let extra = bytes[at + 46 + name_len..at + 46 + name_len + extra_len].to_vec();
        let local_name = le16(bytes, offset + 26);
        let local_extra = le16(bytes, offset + 28);
        let data = &bytes[offset + 30 + local_name + local_extra..][..csize];
        let mut inflated = Vec::new();
        flate2::read::DeflateDecoder::new(data).read_to_end(&mut inflated)?;
        let mut sum = flate2::Crc::new();
        sum.update(&inflated);
        let text = String::from_utf8(inflated)?;
        let mut lines = Vec::new();
        for line in text.lines() {
            let mut value: Value = serde_json::from_str(line)?;
            if value.get("createdAt").is_some() && value.get("manifestVersion").is_some() {
                value["createdAt"] = json!("<time>");
            }
            lines.push(value);
        }
        out.push(json!({
            "name": name, "creator": creator, "reader": reader, "flags": flags, "method": method,
            "time": time, "date": date, "external": external, "extra": extra,
            "crc_ok": sum.sum() as usize == crc, "size_ok": text.len() == usize_,
            "trailing_newline": text.ends_with('\n'), "lines": lines, "text_has_spaces_after_colon": text.contains("\": "),
        }));
        at += 46 + name_len + extra_len + comment_len;
    }
    Ok(json!(out))
}

// ------------------------------------------------------------------ ticks

async fn native_tick(
    db: &Db,
    case: &Case,
    sfu: Option<std::net::SocketAddr>,
) -> Result<(), BoxError> {
    let worker = WorkerDatabase::new(&db.dsn)?.with_audit_keys(String::new(), HMAC.into());
    match case.worker {
        "bulk-role-jobs" => {
            let w = BulkRoleJobs { db: worker };
            w.reclaim().await?;
            let _ = w.tick().await;
        }
        "email-address-policy-jobs" => {
            let w = EapJobs::new(worker);
            w.reclaim().await?;
            let _ = w.tick().await;
        }
        "identity-operations" => {
            let _ = IdentityOperations::new(worker).tick().await;
        }
        _ => {
            let rooms = sfu.map(|addr| Rooms {
                endpoint: format!("http://{addr}"),
                key: LK_KEY.into(),
                secret: LK_SECRET.into(),
            });
            IdentityTransitions::new(worker, rooms).tick().await;
        }
    }
    Ok(())
}

fn record_go_tick(db: &Db, case: &Case, lk_url: Option<&str>) -> Result<(), BoxError> {
    use std::io::Write;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?;
    let folder = root.join("test-results/gofree-adminjobs");
    std::fs::create_dir_all(&folder)?;
    let (package, overlay) = package(case.worker);
    std::fs::write(
        folder.join("overlay.json"),
        serde_json::to_vec(&json!({"Replace":{
            format!("/src/mailserver/internal/{package}/gofree_admin_jobs_tick_test.go"):
                format!("/src/server-rust/tests/conformance/admin-workers/{overlay}")
        }}))?,
    )?;
    let name = format!("gofree-admin11-oracle-{}", std::process::id());
    if let Ok(ledger) = std::env::var("GOFREE_RESOURCE_LEDGER") {
        writeln!(
            std::fs::OpenOptions::new().append(true).open(ledger)?,
            "Planned {name}, local Docker, go cache {}/go-cache; assigned DB only; --rm",
            folder.display()
        )?;
    }
    let mut command = std::process::Command::new("docker");
    command
        .args(["run", "--rm", "--name", &name, "--network", "host", "-v"])
        .arg(format!("{}:/src", root.display()))
        .args([
            "-v",
            &gofree_go_mod_mount(),
            "-w",
            "/src/mailserver",
            "-e",
        ])
        .arg(format!("GOFREE_JOBS_DSN={}", db.dsn))
        .args(["-e", &format!("GOFREE_JOBS_HMAC={HMAC}")]);
    if let Some(url) = lk_url {
        command.args(["-e", &format!("GOFREE_JOBS_LK_URL={url}")]);
    }
    let output = command
        .args(["-e", "GOMAXPROCS=1", "-e", "GOGC=50", "-e", "GOMEMLIMIT=768MiB"])
        .args(["-e", "GOCACHE=/src/test-results/gofree-adminjobs/go-cache"])
        .args([
            "setjoin-ci-linux-tc:local-amd64",
            "go",
            "test",
            "-p=1",
            "-vet=off",
            "-overlay=/src/test-results/gofree-adminjobs/overlay.json",
        ])
        .arg(format!("./internal/{package}"))
        .args(["-run", "^TestGoFreeAdminJobsTick$", "-count=1", "-v"])
        .output()?;
    if !output.status.success() {
        std::fs::write(
            folder.join("go-record.log"),
            [output.stdout.as_slice(), output.stderr.as_slice()].concat(),
        )?;
        return Err(format!(
            "frozen Go worker tick failed: {}",
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .rev()
                .take(8)
                .collect::<Vec<_>>()
                .join(" | ")
        )
        .into());
    }
    Ok(())
}

/// Go's eviction loop keeps kicking until the reducer-supplied horizon has passed
/// (`mediaevict.EvictParticipantThrough`). Frozen Go cannot be recorded for this
/// (its process start-up outlasts any short horizon), so the loop is asserted
/// directly: a horizon 4 s ahead (Go re-kicks every few seconds, so 10 s gives three calls; 4 s is still far enough that a starved host starts the tick
/// before it passes) gives two calls, then the target is acknowledged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn livekit_eviction_waits_for_the_horizon() -> Result<(), BoxError> {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(db) = Db::for_case("admin-job-workers-horizon") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let toggles: Vec<(String, bool)> = owner
        .query("SELECT key,enabled FROM feature_toggles WHERE key IN ('feature.identity_model_v2','feature.identity_transitions')", &[])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let mut ids = fixture(&owner).await?;
    owner.execute("UPDATE feature_toggles SET enabled=true WHERE key IN ('feature.identity_model_v2','feature.identity_transitions')", &[]).await?;
    ids.person = person(&owner).await?;
    let case = Case {
        worker: "identity-transitions",
        label: "horizon",
        seed: transition(1, "effects_pending", &[("livekit_sessions", &[("room-a|u:1", "now()+interval '4 seconds'")])]),
        lk: Lk::Ok,
    };
    let result = async {
        seed(&owner, &case, &ids).await?;
        let server = sfu(Lk::Ok).await;
        let started = std::time::Instant::now();
        native_tick(&db, &case, Some(server.addr)).await?;
        let calls = server.calls.lock().unwrap().len();
        assert_eq!(calls, 2, "one kick, a wait for the horizon, one more kick");
        assert!(started.elapsed() >= std::time::Duration::from_millis(1000));
        let states = text_rows(&owner, "SELECT e.state||':'||(t.completed_at IS NOT NULL) FROM identity_transition_effects e JOIN identity_transition_effect_targets t USING (transition_id,effect_kind) WHERE e.transition_id::text LIKE 'bbbbbbbb-0000-4000-8000-%'").await?;
        assert_eq!(states, vec!["completed:true".to_owned()]);
        Ok::<_, BoxError>(())
    }
    .await;
    let _ = reset(&owner, &case, &ids).await;
    let _ = owner.batch_execute("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM identity_link_events WHERE transition_id::text LIKE 'bbbbbbbb-0000-4000-8000-%'; DELETE FROM identity_source_inbox i WHERE i.applied_event_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM identity_link_events e WHERE e.id=i.applied_event_id); DELETE FROM identity_sync_log WHERE source_id IN (SELECT id FROM identity_sources WHERE source_key LIKE 'legacy:%'); UPDATE identity_sources SET last_success_at=NULL WHERE source_key LIKE 'legacy:%' AND last_success_at IS NOT NULL; COMMIT").await;
    let _ = drop_person(&owner, ids.person).await;
    for (key, enabled) in toggles {
        owner.execute("UPDATE feature_toggles SET enabled=$2 WHERE key=$1", &[&key, &enabled]).await?;
    }
    owner.batch_execute(&format!(
        "DELETE FROM mailboxes WHERE user_id IN ({0},{1},{2},{3}); DELETE FROM users WHERE id IN ({0},{1},{2},{3}); DELETE FROM domains WHERE id IN ({4},{5})",
        ids.act, ids.t[0], ids.t[1], ids.t[2], ids.dom, ids.dom2
    )).await?;
    result
}

/// Host Go module cache for the Go recorder container (GOFREE_GO_MOD_CACHE, default $HOME/go/pkg/mod).
#[allow(dead_code)]
fn gofree_go_mod_mount() -> String {
    let host = std::env::var("GOFREE_GO_MOD_CACHE").unwrap_or_else(|_| {
        format!(
            "{}/go/pkg/mod",
            std::env::var("HOME").unwrap_or_else(|_| "/root".into())
        )
    });
    format!("{host}:/root/go/pkg/mod")
}
