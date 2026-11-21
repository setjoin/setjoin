//! #374: frozen-Go MailWork/* JMAP family HTTP/effect oracle, replayed with no upstream.

mod common;
#[allow(dead_code, unused_imports)]
mod jmap_family_oracle;

use jmap_family_oracle::{run, Case, Mutation};
use setjoin_conformance::harness::{BoxError, Db};

const WORK_TOGGLES: &[(&str, bool)] = &[("feature.shared_mail_work", true)];
const INTEGRATIONS_TOGGLES: &[(&str, bool)] = &[
    ("feature.shared_mail_work", true),
    ("feature.shared_mail_integrations", true),
];
const NOTIFICATIONS_TOGGLES: &[(&str, bool)] = &[
    ("feature.shared_mail_work", true),
    ("feature.shared_mail_notifications", true),
];
const ANALYTICS_TOGGLES: &[(&str, bool)] = &[
    ("feature.shared_mail_work", true),
    ("feature.shared_mail_analytics", true),
];

const SEED_SHARED_OWN: &str =
    "INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary) \
    SELECT NULL, domain_id, 'mw-' || gen_random_uuid() || '@mw.test', 'Shared', 'personal', false \
    FROM mailboxes WHERE id = {a.mailbox} RETURNING id";
const SEED_SHARED_FOREIGN: &str = "INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary) \
    SELECT NULL, domain_id, 'mw-' || gen_random_uuid() || '@mw.test', 'Foreign Shared', 'personal', false \
    FROM mailboxes WHERE id = {f.mailbox} RETURNING id";
const SEED_DELEGATE_FULL: &str =
    "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
    VALUES ({seed.0}, {a.user}, 'full_access', {a.user})";
const SEED_DELEGATE_SEND_AS: &str =
    "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
    VALUES ({seed.0}, {a.user}, 'send_as', {a.user})";
const SEED_DELEGATE_READ: &str =
    "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
    VALUES ({seed.0}, {a.user}, 'read', {a.user})";
const SEED_DELEGATE_CALENDAR: &str =
    "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
    VALUES ({seed.0}, {a.user}, 'manage_calendar', {a.user})";
const REVOKE_DELEGATE: &str =
    "DELETE FROM mailbox_delegates WHERE mailbox_id = {seed.0} AND user_id = {a.user}";
const SUSPEND_MAILBOX: &str = "UPDATE mailboxes SET enabled = false WHERE id = {seed.0}";
const SUSPEND_LIFECYCLE: &str = "UPDATE mailbox_lifecycle SET access_state = 'suspended', generation = generation + 1, \
    updated_at = statement_timestamp() WHERE mailbox_id = {seed.0} AND binding_state IN ('bound','shared')";
const SEED_THREAD_MESSAGE: &str =
    "INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, size_bytes, \
    thread_id, raw_ref, received_at, is_read) \
    SELECT {seed.0}, (SELECT id FROM tags WHERE mailbox_id = {seed.0} AND name = 'Inbox'), \
    '<mw-' || gen_random_uuid() || '@mw.test>', 'Work', 'sender@example.test', 100, \
    'mw-thread-1', 'raw-mw-1', now(), false";
const BUMP_OUTBOX_SEQ: &str = "DO $$ BEGIN PERFORM setval('mail_work_outbox_id_seq', \
    GREATEST((SELECT last_value FROM mail_work_outbox_id_seq), 28000000)); END $$";

const WORK_EFFECTS: &[(&str, &str)] = &[
    (
        "state",
        "SELECT coalesce((SELECT jmap_mailwork_state::text FROM mailboxes WHERE id = {seed.0}), 'missing')",
    ),
    (
        "work",
        "SELECT coalesce(jsonb_agg(to_jsonb(w) - 'mailbox_id' ORDER BY w.thread_id), '[]'::jsonb)::text \
         FROM mail_thread_work w WHERE w.mailbox_id = {seed.0}",
    ),
    (
        "events",
        "SELECT coalesce(jsonb_agg(jsonb_build_object('threadId', e.thread_id, 'generation', e.generation, \
         'eventType', e.event_type, 'actorUserId', e.actor_user_id, 'reason', e.reason) \
         ORDER BY e.occurred_at, e.id), '[]'::jsonb)::text \
         FROM mail_thread_work_events e WHERE e.mailbox_id = {seed.0}",
    ),
    (
        "changes",
        "SELECT coalesce(jsonb_agg(to_jsonb(c) - 'mailbox_id' - 'occurred_at' ORDER BY c.state_seq), '[]'::jsonb)::text \
         FROM mail_work_changes c WHERE c.mailbox_id = {seed.0}",
    ),
    (
        "ops",
        "SELECT coalesce(jsonb_agg(jsonb_build_object('op', o.operation_id, 'kind', o.operation_kind, \
         'actor', o.actor_user_id, 'has_digest', (o.request_digest IS NOT NULL)) ORDER BY o.created_at, o.operation_id), '[]'::jsonb)::text \
         FROM mail_work_operations o WHERE o.mailbox_id = {seed.0}",
    ),
];

const WORK_SET_EFFECTS: &[(&str, &str)] = &[
    (
        "state",
        "SELECT coalesce((SELECT jmap_mailwork_state::text FROM mailboxes WHERE id = {seed.0}), 'missing')",
    ),
    (
        "work",
        "SELECT coalesce(jsonb_agg(to_jsonb(w) - 'mailbox_id' ORDER BY w.thread_id), '[]'::jsonb)::text \
         FROM mail_thread_work w WHERE w.mailbox_id = {seed.0}",
    ),
    (
        "events",
        "SELECT coalesce(jsonb_agg(jsonb_build_object('threadId', e.thread_id, 'generation', e.generation, \
         'eventType', e.event_type, 'actorUserId', e.actor_user_id, 'reason', e.reason) \
         ORDER BY e.occurred_at, e.id), '[]'::jsonb)::text \
         FROM mail_thread_work_events e WHERE e.mailbox_id = {seed.0}",
    ),
    (
        "changes",
        "SELECT coalesce(jsonb_agg(to_jsonb(c) - 'mailbox_id' - 'occurred_at' ORDER BY c.state_seq), '[]'::jsonb)::text \
         FROM mail_work_changes c WHERE c.mailbox_id = {seed.0}",
    ),
    (
        "ops",
        "SELECT coalesce(jsonb_agg(jsonb_build_object('op', o.operation_id, 'kind', o.operation_kind, \
         'actor', o.actor_user_id, 'has_digest', (o.request_digest IS NOT NULL)) ORDER BY o.created_at, o.operation_id), '[]'::jsonb)::text \
         FROM mail_work_operations o WHERE o.mailbox_id = {seed.0}",
    ),
    (
        "audit",
        "SELECT coalesce(jsonb_agg(jsonb_build_object('action', a.action, 'actor', a.actor_user_id) \
         ORDER BY a.id), '[]'::jsonb)::text FROM mailbox_audit_log a WHERE a.mailbox_id = {seed.0}",
    ),
];

const WORK_ACTION_EFFECTS: &[(&str, &str)] = &[
    (
        "state",
        "SELECT coalesce((SELECT jmap_mailwork_state::text FROM mailboxes WHERE id = {seed.0}), 'missing')",
    ),
    (
        "work",
        "SELECT coalesce(jsonb_agg(to_jsonb(w) - 'mailbox_id' ORDER BY w.thread_id), '[]'::jsonb)::text \
         FROM mail_thread_work w WHERE w.mailbox_id = {seed.0}",
    ),
    (
        "events",
        "SELECT coalesce(jsonb_agg(jsonb_build_object('threadId', e.thread_id, 'generation', e.generation, \
         'eventType', e.event_type, 'actorUserId', e.actor_user_id, 'reason', e.reason) \
         ORDER BY e.occurred_at, e.id), '[]'::jsonb)::text \
         FROM mail_thread_work_events e WHERE e.mailbox_id = {seed.0}",
    ),
    (
        "changes",
        "SELECT coalesce(jsonb_agg(to_jsonb(c) - 'mailbox_id' - 'occurred_at' ORDER BY c.state_seq), '[]'::jsonb)::text \
         FROM mail_work_changes c WHERE c.mailbox_id = {seed.0}",
    ),
    (
        "ops",
        "SELECT coalesce(jsonb_agg(jsonb_build_object('op', o.operation_id, 'kind', o.operation_kind, \
         'actor', o.actor_user_id, 'has_digest', (o.request_digest IS NOT NULL)) ORDER BY o.created_at, o.operation_id), '[]'::jsonb)::text \
         FROM mail_work_operations o WHERE o.mailbox_id = {seed.0}",
    ),
    (
        "outbox",
        "SELECT coalesce(jsonb_agg(jsonb_build_object('id', o.id::text, 'kind', o.consumer_kind, \
         'state', o.state, 'payload', o.payload) ORDER BY o.id), '[]'::jsonb)::text \
         FROM mail_work_outbox o JOIN mail_thread_work_events e ON e.id = o.event_id \
         WHERE e.mailbox_id = {seed.0}",
    ),
];

const POLICY_EFFECTS: &[(&str, &str)] = &[
    (
        "state",
        "SELECT coalesce((SELECT jmap_mailwork_state::text FROM mailboxes WHERE id = {seed.0}), 'missing')",
    ),
    (
        "policy",
        "SELECT coalesce((SELECT (to_jsonb(p) - 'mailbox_id' - 'updated_at')::text \
         FROM mail_work_sla_policies p WHERE p.mailbox_id = {seed.0}), 'none')",
    ),
    (
        "changes",
        "SELECT coalesce(jsonb_agg(to_jsonb(c) - 'mailbox_id' - 'occurred_at' ORDER BY c.state_seq), '[]'::jsonb)::text \
         FROM mail_work_changes c WHERE c.mailbox_id = {seed.0}",
    ),
    (
        "ops",
        "SELECT coalesce(jsonb_agg(jsonb_build_object('op', o.operation_id, 'kind', o.operation_kind, \
         'actor', o.actor_user_id, 'has_digest', (o.request_digest IS NOT NULL)) ORDER BY o.created_at, o.operation_id), '[]'::jsonb)::text \
         FROM mail_work_operations o WHERE o.mailbox_id = {seed.0}",
    ),
    (
        "audit",
        "SELECT coalesce(jsonb_agg(jsonb_build_object('action', a.action, 'actor', a.actor_user_id) \
         ORDER BY a.id), '[]'::jsonb)::text FROM mailbox_audit_log a WHERE a.mailbox_id = {seed.0}",
    ),
];

const PREFS_EFFECTS: &[(&str, &str)] = &[
    (
        "prefs",
        "SELECT coalesce(jsonb_agg(to_jsonb(p) - 'mailbox_id' ORDER BY p.user_id, p.category), '[]'::jsonb)::text \
         FROM mail_work_notification_preferences p WHERE p.mailbox_id = {seed.0}",
    ),
    (
        "ops",
        "SELECT coalesce(jsonb_agg(jsonb_build_object('op', o.operation_id, 'kind', o.operation_kind, \
         'actor', o.actor_user_id, 'has_digest', (o.request_digest IS NOT NULL)) ORDER BY o.created_at, o.operation_id), '[]'::jsonb)::text \
         FROM mail_work_operations o WHERE o.mailbox_id = {seed.0}",
    ),
];

const METRICS_EFFECTS: &[(&str, &str)] = &[(
    "metrics",
    "SELECT coalesce(jsonb_agg((to_jsonb(m) - 'mailbox_id' - 'rebuilt_at') \
     ORDER BY m.metric_day, m.policy_version), '[]'::jsonb)::text \
     FROM mail_work_metric_daily m WHERE m.mailbox_id = {seed.0}",
)];

async fn replay(case: &Case) -> Result<(), BoxError> {
    run(case, Mutation::None).await
}

async fn status_mutant(case: &Case) -> Result<(), BoxError> {
    if Db::for_case(case.name).is_none() {
        return Ok(());
    }
    let diff = run(case, Mutation::Status)
        .await
        .expect_err("status mutant must fail")
        .to_string();
    assert!(diff.contains("/response/status"), "{diff}");
    println!("MUTANT-REJECTED: POST /jmap {} :: status", case.method);
    Ok(())
}

// --- MailWork/get ---

const WORK_GET_SUCCESS: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_SHARED_FOREIGN,
        SEED_DELEGATE_FULL,
        "INSERT INTO mail_thread_work (mailbox_id, thread_id, status, assignee_user_id, sla_minutes, \
         first_activity_at, last_activity_at) \
         VALUES ({seed.0}, 'mw-own', 'owned', {a.user}, 480, '2026-10-01T10:00:00Z', '2026-10-01T10:00:00Z')",
        "INSERT INTO mail_thread_work (mailbox_id, thread_id, status, assignee_user_id, sla_minutes, \
         first_activity_at, last_activity_at) \
         VALUES ({seed.1}, 'mw-foreign', 'owned', {f.user}, 480, '2026-10-01T10:00:00Z', '2026-10-01T10:00:00Z')",
    ],
    absent: &["mw-foreign"],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-get-success",
        "success",
        "MailWork/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/get",{"accountId":"{seed.0}","ids":null},"c0"]]}"#,
    )
};

const WORK_GET_NO_TENANT_MUTANT: Case = Case {
    absent: &[],
    ..WORK_GET_SUCCESS
};

const WORK_GET_CROSS_TENANT: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_FOREIGN],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-get-cross-tenant",
        "cross-tenant",
        "MailWork/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

const WORK_GET_INVALID: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-get-invalid-input",
        "invalid-input",
        "MailWork/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/get",{"accountId":"{seed.0}","ids":123},"c0"]]}"#,
    )
};

const WORK_GET_DELEGATE_ALLOWED: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_READ,
        "INSERT INTO mail_thread_work (mailbox_id, thread_id, status, assignee_user_id, sla_minutes, \
         first_activity_at, last_activity_at) \
         VALUES ({seed.0}, 'mw-read', 'owned', {a.user}, 480, '2026-10-01T10:00:00Z', '2026-10-01T10:00:00Z')",
    ],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-get-delegate-allowed",
        "delegate-allowed",
        "MailWork/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/get",{"accountId":"{seed.0}","ids":["mw-read","mw-missing"]},"c0"]]}"#,
    )
};

const WORK_GET_DELEGATE_INSUFFICIENT: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_CALENDAR],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-get-delegate-insufficient",
        "delegate-insufficient",
        "MailWork/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

const WORK_GET_DELEGATE_REVOKED: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_READ],
    setup: &[
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/get",{"accountId":"{seed.0}"},"s0"]]}"#,
    ],
    between: &[REVOKE_DELEGATE],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-get-delegate-revoked",
        "delegate-revoked",
        "MailWork/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

const WORK_GET_SUSPENDED: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_READ,
        SUSPEND_MAILBOX,
        SUSPEND_LIFECYCLE,
    ],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-get-suspended",
        "suspended",
        "MailWork/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_get_success() -> Result<(), BoxError> {
    replay(&WORK_GET_SUCCESS).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_get_cross_tenant() -> Result<(), BoxError> {
    replay(&WORK_GET_CROSS_TENANT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_get_invalid_input() -> Result<(), BoxError> {
    replay(&WORK_GET_INVALID).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_get_delegate_allowed() -> Result<(), BoxError> {
    replay(&WORK_GET_DELEGATE_ALLOWED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_get_delegate_insufficient() -> Result<(), BoxError> {
    replay(&WORK_GET_DELEGATE_INSUFFICIENT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_get_delegate_revoked() -> Result<(), BoxError> {
    replay(&WORK_GET_DELEGATE_REVOKED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_get_suspended() -> Result<(), BoxError> {
    replay(&WORK_GET_SUSPENDED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_get_status_mutant() -> Result<(), BoxError> {
    status_mutant(&WORK_GET_SUCCESS).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_get_no_tenant_filter_mutant() -> Result<(), BoxError> {
    run(
        &WORK_GET_NO_TENANT_MUTANT,
        Mutation::NoTenantFilter {
            function: "mail_work_get(bigint,bigint,text[])",
            from: "w.mailbox_id=p_mailbox_id",
        },
    )
    .await
}

// --- MailWork/changes ---

const WORK_CHANGES_SUCCESS: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_FULL,
        "UPDATE mailboxes SET jmap_mailwork_state = 2 WHERE id = {seed.0}",
        "INSERT INTO mail_work_changes (mailbox_id, state_seq, object_kind, object_id, op) VALUES \
         ({seed.0}, 1, 'work', 'mw-1', 'created'), ({seed.0}, 2, 'work', 'mw-2', 'updated')",
    ],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-changes-success",
        "success",
        "MailWork/changes",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/changes",{"accountId":"{seed.0}","sinceState":"0","maxChanges":10},"c0"]]}"#,
    )
};

const WORK_CHANGES_CROSS_TENANT: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_FOREIGN],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-changes-cross-tenant",
        "cross-tenant",
        "MailWork/changes",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/changes",{"accountId":"{seed.0}","sinceState":"0"},"c0"]]}"#,
    )
};

const WORK_CHANGES_INVALID: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-changes-invalid-input",
        "invalid-input",
        "MailWork/changes",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/changes",{"accountId":"{seed.0}","sinceState":"0","maxChanges":"bad"},"c0"]]}"#,
    )
};

const WORK_CHANGES_DELEGATE_ALLOWED: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_READ,
        "UPDATE mailboxes SET jmap_mailwork_state = 1 WHERE id = {seed.0}",
        "INSERT INTO mail_work_changes (mailbox_id, state_seq, object_kind, object_id, op) \
         VALUES ({seed.0}, 1, 'work', 'mw-read', 'created')",
    ],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-changes-delegate-allowed",
        "delegate-allowed",
        "MailWork/changes",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/changes",{"accountId":"{seed.0}","sinceState":"0"},"c0"]]}"#,
    )
};

const WORK_CHANGES_DELEGATE_INSUFFICIENT: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_CALENDAR],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-changes-delegate-insufficient",
        "delegate-insufficient",
        "MailWork/changes",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/changes",{"accountId":"{seed.0}","sinceState":"0"},"c0"]]}"#,
    )
};

const WORK_CHANGES_DELEGATE_REVOKED: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_READ],
    setup: &[
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/changes",{"accountId":"{seed.0}","sinceState":"0"},"s0"]]}"#,
    ],
    between: &[REVOKE_DELEGATE],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-changes-delegate-revoked",
        "delegate-revoked",
        "MailWork/changes",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/changes",{"accountId":"{seed.0}","sinceState":"0"},"c0"]]}"#,
    )
};

const WORK_CHANGES_SUSPENDED: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_READ,
        SUSPEND_MAILBOX,
        SUSPEND_LIFECYCLE,
    ],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-changes-suspended",
        "suspended",
        "MailWork/changes",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/changes",{"accountId":"{seed.0}","sinceState":"0"},"c0"]]}"#,
    )
};

const WORK_CHANGES_STATE_MISMATCH: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_READ,
        "UPDATE mailboxes SET jmap_mailwork_state = 5 WHERE id = {seed.0}",
        "INSERT INTO mail_work_changes (mailbox_id, state_seq, object_kind, object_id, op) \
         VALUES ({seed.0}, 5, 'work', 'mw-5', 'created')",
    ],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-changes-state-mismatch",
        "state-mismatch",
        "MailWork/changes",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/changes",{"accountId":"{seed.0}","sinceState":"1"},"c0"]]}"#,
    )
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_changes_success() -> Result<(), BoxError> {
    replay(&WORK_CHANGES_SUCCESS).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_changes_cross_tenant() -> Result<(), BoxError> {
    replay(&WORK_CHANGES_CROSS_TENANT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_changes_invalid_input() -> Result<(), BoxError> {
    replay(&WORK_CHANGES_INVALID).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_changes_delegate_allowed() -> Result<(), BoxError> {
    replay(&WORK_CHANGES_DELEGATE_ALLOWED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_changes_delegate_insufficient() -> Result<(), BoxError> {
    replay(&WORK_CHANGES_DELEGATE_INSUFFICIENT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_changes_delegate_revoked() -> Result<(), BoxError> {
    replay(&WORK_CHANGES_DELEGATE_REVOKED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_changes_suspended() -> Result<(), BoxError> {
    replay(&WORK_CHANGES_SUSPENDED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_changes_state_mismatch() -> Result<(), BoxError> {
    replay(&WORK_CHANGES_STATE_MISMATCH).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_changes_status_mutant() -> Result<(), BoxError> {
    status_mutant(&WORK_CHANGES_SUCCESS).await
}

// --- MailWork/set ---

const WORK_SET_SUCCESS: Case = Case {
    mutator: true,
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL, SEED_THREAD_MESSAGE],
    effects: WORK_SET_EFFECTS,
    notify: &["tag:{seed.0}"],
    ..Case::new(
        "mail_work",
        "mail-work-set-success",
        "success",
        "MailWork/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/set",{"accountId":"{seed.0}","threadId":"mw-thread-1","operationId":"11111111-1111-4111-8111-000000000001","action":"claim","expectedGeneration":"0","reason":"triage"},"c0"]]}"#,
    )
};

const WORK_SET_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL, SEED_THREAD_MESSAGE],
    effects: WORK_SET_EFFECTS,
    notify: &["tag:{seed.0}"],
    ..Case::new(
        "mail_work",
        "mail-work-set-repeat",
        "repeat",
        "MailWork/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/set",{"accountId":"{seed.0}","threadId":"mw-thread-1","operationId":"11111111-1111-4111-8111-000000000002","action":"claim","expectedGeneration":"0","reason":"triage"},"c0"]]}"#,
    )
};

const WORK_SET_CROSS_TENANT: Case = Case {
    mutator: true,
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_FOREIGN],
    effects: WORK_SET_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-set-cross-tenant",
        "cross-tenant",
        "MailWork/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/set",{"accountId":"{seed.0}","threadId":"mw-thread-1","operationId":"11111111-1111-4111-8111-000000000003","action":"claim","expectedGeneration":"0","reason":"triage"},"c0"]]}"#,
    )
};

const WORK_SET_INVALID: Case = Case {
    mutator: true,
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    effects: WORK_SET_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-set-invalid-input",
        "invalid-input",
        "MailWork/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/set",{"accountId":"{seed.0}","threadId":"mw-thread-1","operationId":"bad-uuid","action":"claim","expectedGeneration":"0","reason":"triage"},"c0"]]}"#,
    )
};

const WORK_SET_DELEGATE_ALLOWED: Case = Case {
    mutator: true,
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_SEND_AS, SEED_THREAD_MESSAGE],
    effects: WORK_SET_EFFECTS,
    notify: &["tag:{seed.0}"],
    ..Case::new(
        "mail_work",
        "mail-work-set-delegate-allowed",
        "delegate-allowed",
        "MailWork/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/set",{"accountId":"{seed.0}","threadId":"mw-thread-1","operationId":"11111111-1111-4111-8111-000000000004","action":"claim","expectedGeneration":"0","reason":"triage"},"c0"]]}"#,
    )
};

const WORK_SET_DELEGATE_INSUFFICIENT: Case = Case {
    mutator: true,
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_READ, SEED_THREAD_MESSAGE],
    effects: WORK_SET_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-set-delegate-insufficient",
        "delegate-insufficient",
        "MailWork/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/set",{"accountId":"{seed.0}","threadId":"mw-thread-1","operationId":"11111111-1111-4111-8111-000000000005","action":"claim","expectedGeneration":"0","reason":"triage"},"c0"]]}"#,
    )
};

const WORK_SET_DELEGATE_REVOKED: Case = Case {
    mutator: true,
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL, SEED_THREAD_MESSAGE],
    setup: &[
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/get",{"accountId":"{seed.0}"},"s0"]]}"#,
    ],
    between: &[REVOKE_DELEGATE],
    effects: WORK_SET_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-set-delegate-revoked",
        "delegate-revoked",
        "MailWork/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/set",{"accountId":"{seed.0}","threadId":"mw-thread-1","operationId":"11111111-1111-4111-8111-000000000006","action":"claim","expectedGeneration":"0","reason":"triage"},"c0"]]}"#,
    )
};

const WORK_SET_SUSPENDED: Case = Case {
    mutator: true,
    toggles: WORK_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_FULL,
        SEED_THREAD_MESSAGE,
        SUSPEND_MAILBOX,
        SUSPEND_LIFECYCLE,
    ],
    effects: WORK_SET_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-set-suspended",
        "suspended",
        "MailWork/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/set",{"accountId":"{seed.0}","threadId":"mw-thread-1","operationId":"11111111-1111-4111-8111-000000000007","action":"claim","expectedGeneration":"0","reason":"triage"},"c0"]]}"#,
    )
};

const WORK_SET_STATE_MISMATCH: Case = Case {
    mutator: true,
    toggles: WORK_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_FULL,
        SEED_THREAD_MESSAGE,
        "INSERT INTO mail_thread_work (mailbox_id, thread_id, status, assignee_user_id, generation, \
         first_activity_at, last_activity_at) \
         VALUES ({seed.0}, 'mw-thread-1', 'owned', {a.user}, 1, '2026-10-01T10:00:00Z', '2026-10-01T10:00:00Z')",
    ],
    effects: WORK_SET_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-set-state-mismatch",
        "state-mismatch",
        "MailWork/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/set",{"accountId":"{seed.0}","threadId":"mw-thread-1","operationId":"11111111-1111-4111-8111-000000000008","action":"claim","expectedGeneration":"0","reason":"triage"},"c0"]]}"#,
    )
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_set_success() -> Result<(), BoxError> {
    replay(&WORK_SET_SUCCESS).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_set_repeat() -> Result<(), BoxError> {
    replay(&WORK_SET_REPEAT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_set_cross_tenant() -> Result<(), BoxError> {
    replay(&WORK_SET_CROSS_TENANT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_set_invalid_input() -> Result<(), BoxError> {
    replay(&WORK_SET_INVALID).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_set_delegate_allowed() -> Result<(), BoxError> {
    replay(&WORK_SET_DELEGATE_ALLOWED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_set_delegate_insufficient() -> Result<(), BoxError> {
    replay(&WORK_SET_DELEGATE_INSUFFICIENT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_set_delegate_revoked() -> Result<(), BoxError> {
    replay(&WORK_SET_DELEGATE_REVOKED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_set_suspended() -> Result<(), BoxError> {
    replay(&WORK_SET_SUSPENDED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_set_state_mismatch() -> Result<(), BoxError> {
    replay(&WORK_SET_STATE_MISMATCH).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_set_status_mutant() -> Result<(), BoxError> {
    status_mutant(&WORK_SET_SUCCESS).await
}

// --- MailWork/action ---

const SEED_ACTION_WORK: &str = "INSERT INTO mail_thread_work (mailbox_id, thread_id, status, assignee_user_id, generation, \
    first_activity_at, last_activity_at) \
    VALUES ({seed.0}, 'mw-action-1', 'owned', {a.user}, 1, '2026-10-01T10:00:00Z', '2026-10-01T10:00:00Z')";

const WORK_ACTION_SUCCESS: Case = Case {
    mutator: true,
    toggles: INTEGRATIONS_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_FULL,
        SEED_ACTION_WORK,
        BUMP_OUTBOX_SEQ,
    ],
    effects: WORK_ACTION_EFFECTS,
    notify: &["tag:{seed.0}"],
    scrub: &[("/methodResponses/0/1/outboxId", "outboxId")],
    ..Case::new(
        "mail_work",
        "mail-work-action-success",
        "success",
        "MailWork/action",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/action",{"accountId":"{seed.0}","threadId":"mw-action-1","operationId":"22222222-2222-4222-8222-000000000001","expectedGeneration":"1","actionKind":"task"},"c0"]]}"#,
    )
};

const WORK_ACTION_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    toggles: INTEGRATIONS_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_FULL,
        SEED_ACTION_WORK,
        BUMP_OUTBOX_SEQ,
    ],
    effects: WORK_ACTION_EFFECTS,
    notify: &["tag:{seed.0}"],
    scrub: &[("/methodResponses/0/1/outboxId", "outboxId")],
    ..Case::new(
        "mail_work",
        "mail-work-action-repeat",
        "repeat",
        "MailWork/action",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/action",{"accountId":"{seed.0}","threadId":"mw-action-1","operationId":"22222222-2222-4222-8222-000000000002","expectedGeneration":"1","actionKind":"task"},"c0"]]}"#,
    )
};

const WORK_ACTION_CROSS_TENANT: Case = Case {
    mutator: true,
    toggles: INTEGRATIONS_TOGGLES,
    seed: &[SEED_SHARED_FOREIGN],
    effects: WORK_ACTION_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-action-cross-tenant",
        "cross-tenant",
        "MailWork/action",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/action",{"accountId":"{seed.0}","threadId":"mw-action-1","operationId":"22222222-2222-4222-8222-000000000003","expectedGeneration":"1","actionKind":"task"},"c0"]]}"#,
    )
};

const WORK_ACTION_INVALID: Case = Case {
    mutator: true,
    toggles: INTEGRATIONS_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL, SEED_ACTION_WORK],
    effects: WORK_ACTION_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-action-invalid-input",
        "invalid-input",
        "MailWork/action",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/action",{"accountId":"{seed.0}","threadId":"mw-action-1","operationId":"22222222-2222-4222-8222-000000000004","expectedGeneration":"1","actionKind":"task","targetId":"5"},"c0"]]}"#,
    )
};

const WORK_ACTION_DELEGATE_ALLOWED: Case = Case {
    mutator: true,
    toggles: INTEGRATIONS_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_SEND_AS,
        SEED_ACTION_WORK,
        BUMP_OUTBOX_SEQ,
    ],
    effects: WORK_ACTION_EFFECTS,
    notify: &["tag:{seed.0}"],
    scrub: &[("/methodResponses/0/1/outboxId", "outboxId")],
    ..Case::new(
        "mail_work",
        "mail-work-action-delegate-allowed",
        "delegate-allowed",
        "MailWork/action",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/action",{"accountId":"{seed.0}","threadId":"mw-action-1","operationId":"22222222-2222-4222-8222-000000000005","expectedGeneration":"1","actionKind":"task"},"c0"]]}"#,
    )
};

const WORK_ACTION_DELEGATE_INSUFFICIENT: Case = Case {
    mutator: true,
    toggles: INTEGRATIONS_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_READ, SEED_ACTION_WORK],
    effects: WORK_ACTION_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-action-delegate-insufficient",
        "delegate-insufficient",
        "MailWork/action",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/action",{"accountId":"{seed.0}","threadId":"mw-action-1","operationId":"22222222-2222-4222-8222-000000000006","expectedGeneration":"1","actionKind":"task"},"c0"]]}"#,
    )
};

const WORK_ACTION_DELEGATE_REVOKED: Case = Case {
    mutator: true,
    toggles: INTEGRATIONS_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL, SEED_ACTION_WORK],
    setup: &[
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/get",{"accountId":"{seed.0}"},"s0"]]}"#,
    ],
    between: &[REVOKE_DELEGATE],
    effects: WORK_ACTION_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-action-delegate-revoked",
        "delegate-revoked",
        "MailWork/action",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/action",{"accountId":"{seed.0}","threadId":"mw-action-1","operationId":"22222222-2222-4222-8222-000000000007","expectedGeneration":"1","actionKind":"task"},"c0"]]}"#,
    )
};

const WORK_ACTION_SUSPENDED: Case = Case {
    mutator: true,
    toggles: INTEGRATIONS_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_FULL,
        SEED_ACTION_WORK,
        SUSPEND_MAILBOX,
        SUSPEND_LIFECYCLE,
    ],
    effects: WORK_ACTION_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-action-suspended",
        "suspended",
        "MailWork/action",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/action",{"accountId":"{seed.0}","threadId":"mw-action-1","operationId":"22222222-2222-4222-8222-000000000008","expectedGeneration":"1","actionKind":"task"},"c0"]]}"#,
    )
};

const WORK_ACTION_STATE_MISMATCH: Case = Case {
    mutator: true,
    toggles: INTEGRATIONS_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_FULL,
        "INSERT INTO mail_thread_work (mailbox_id, thread_id, status, assignee_user_id, generation, \
         first_activity_at, last_activity_at) \
         VALUES ({seed.0}, 'mw-action-1', 'owned', {a.user}, 2, '2026-10-01T10:00:00Z', '2026-10-01T10:00:00Z')",
    ],
    effects: WORK_ACTION_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-action-state-mismatch",
        "state-mismatch",
        "MailWork/action",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/action",{"accountId":"{seed.0}","threadId":"mw-action-1","operationId":"22222222-2222-4222-8222-000000000009","expectedGeneration":"1","actionKind":"task"},"c0"]]}"#,
    )
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_action_success() -> Result<(), BoxError> {
    replay(&WORK_ACTION_SUCCESS).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_action_repeat() -> Result<(), BoxError> {
    replay(&WORK_ACTION_REPEAT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_action_cross_tenant() -> Result<(), BoxError> {
    replay(&WORK_ACTION_CROSS_TENANT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_action_invalid_input() -> Result<(), BoxError> {
    replay(&WORK_ACTION_INVALID).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_action_delegate_allowed() -> Result<(), BoxError> {
    replay(&WORK_ACTION_DELEGATE_ALLOWED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_action_delegate_insufficient() -> Result<(), BoxError> {
    replay(&WORK_ACTION_DELEGATE_INSUFFICIENT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_action_delegate_revoked() -> Result<(), BoxError> {
    replay(&WORK_ACTION_DELEGATE_REVOKED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_action_suspended() -> Result<(), BoxError> {
    replay(&WORK_ACTION_SUSPENDED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_action_state_mismatch() -> Result<(), BoxError> {
    replay(&WORK_ACTION_STATE_MISMATCH).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_action_status_mutant() -> Result<(), BoxError> {
    status_mutant(&WORK_ACTION_SUCCESS).await
}

// --- MailWorkCollaborators/get ---

const COLLABORATORS_GET_SUCCESS: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    effects: WORK_EFFECTS,
    scrub: &[("/methodResponses/0/1/list/0/email", "a.email")],
    ..Case::new(
        "mail_work",
        "mail-work-collaborators-get-success",
        "success",
        "MailWorkCollaborators/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkCollaborators/get",{"accountId":"{seed.0}","query":"","limit":20},"c0"]]}"#,
    )
};

const COLLABORATORS_GET_CROSS_TENANT: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_FOREIGN],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-collaborators-get-cross-tenant",
        "cross-tenant",
        "MailWorkCollaborators/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkCollaborators/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

const COLLABORATORS_GET_INVALID: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-collaborators-get-invalid-input",
        "invalid-input",
        "MailWorkCollaborators/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkCollaborators/get",{"accountId":"{seed.0}","limit":51},"c0"]]}"#,
    )
};

const COLLABORATORS_GET_DELEGATE_ALLOWED: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_READ],
    effects: WORK_EFFECTS,
    scrub: &[("/methodResponses/0/1/list/0/email", "a.email")],
    ..Case::new(
        "mail_work",
        "mail-work-collaborators-get-delegate-allowed",
        "delegate-allowed",
        "MailWorkCollaborators/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkCollaborators/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

const COLLABORATORS_GET_DELEGATE_INSUFFICIENT: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_CALENDAR],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-collaborators-get-delegate-insufficient",
        "delegate-insufficient",
        "MailWorkCollaborators/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkCollaborators/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

const COLLABORATORS_GET_DELEGATE_REVOKED: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_READ],
    setup: &[
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWork/get",{"accountId":"{seed.0}"},"s0"]]}"#,
    ],
    between: &[REVOKE_DELEGATE],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-collaborators-get-delegate-revoked",
        "delegate-revoked",
        "MailWorkCollaborators/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkCollaborators/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

const COLLABORATORS_GET_SUSPENDED: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_READ,
        SUSPEND_MAILBOX,
        SUSPEND_LIFECYCLE,
    ],
    effects: WORK_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-collaborators-get-suspended",
        "suspended",
        "MailWorkCollaborators/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkCollaborators/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_collaborators_get_success() -> Result<(), BoxError> {
    replay(&COLLABORATORS_GET_SUCCESS).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_collaborators_get_cross_tenant() -> Result<(), BoxError> {
    replay(&COLLABORATORS_GET_CROSS_TENANT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_collaborators_get_invalid_input() -> Result<(), BoxError> {
    replay(&COLLABORATORS_GET_INVALID).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_collaborators_get_delegate_allowed() -> Result<(), BoxError> {
    replay(&COLLABORATORS_GET_DELEGATE_ALLOWED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_collaborators_get_delegate_insufficient() -> Result<(), BoxError> {
    replay(&COLLABORATORS_GET_DELEGATE_INSUFFICIENT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_collaborators_get_delegate_revoked() -> Result<(), BoxError> {
    replay(&COLLABORATORS_GET_DELEGATE_REVOKED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_collaborators_get_suspended() -> Result<(), BoxError> {
    replay(&COLLABORATORS_GET_SUSPENDED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_collaborators_get_status_mutant() -> Result<(), BoxError> {
    status_mutant(&COLLABORATORS_GET_SUCCESS).await
}

// --- MailWorkPolicy/get ---

const POLICY_GET_SUCCESS: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    effects: POLICY_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-policy-get-success",
        "success",
        "MailWorkPolicy/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkPolicy/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

const POLICY_GET_CROSS_TENANT: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_FOREIGN],
    effects: POLICY_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-policy-get-cross-tenant",
        "cross-tenant",
        "MailWorkPolicy/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkPolicy/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

const POLICY_GET_INVALID: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    effects: POLICY_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-policy-get-invalid-input",
        "invalid-input",
        "MailWorkPolicy/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkPolicy/get",{"accountId":123},"c0"]]}"#,
    )
};

const POLICY_GET_DELEGATE_ALLOWED: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_READ],
    effects: POLICY_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-policy-get-delegate-allowed",
        "delegate-allowed",
        "MailWorkPolicy/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkPolicy/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

const POLICY_GET_DELEGATE_INSUFFICIENT: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_CALENDAR],
    effects: POLICY_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-policy-get-delegate-insufficient",
        "delegate-insufficient",
        "MailWorkPolicy/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkPolicy/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

const POLICY_GET_DELEGATE_REVOKED: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_READ],
    setup: &[
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkPolicy/get",{"accountId":"{seed.0}"},"s0"]]}"#,
    ],
    between: &[REVOKE_DELEGATE],
    effects: POLICY_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-policy-get-delegate-revoked",
        "delegate-revoked",
        "MailWorkPolicy/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkPolicy/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

const POLICY_GET_SUSPENDED: Case = Case {
    toggles: WORK_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_READ,
        SUSPEND_MAILBOX,
        SUSPEND_LIFECYCLE,
    ],
    effects: POLICY_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-policy-get-suspended",
        "suspended",
        "MailWorkPolicy/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkPolicy/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_policy_get_success() -> Result<(), BoxError> {
    replay(&POLICY_GET_SUCCESS).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_policy_get_cross_tenant() -> Result<(), BoxError> {
    replay(&POLICY_GET_CROSS_TENANT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_policy_get_invalid_input() -> Result<(), BoxError> {
    replay(&POLICY_GET_INVALID).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_policy_get_delegate_allowed() -> Result<(), BoxError> {
    replay(&POLICY_GET_DELEGATE_ALLOWED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_policy_get_delegate_insufficient() -> Result<(), BoxError> {
    replay(&POLICY_GET_DELEGATE_INSUFFICIENT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_policy_get_delegate_revoked() -> Result<(), BoxError> {
    replay(&POLICY_GET_DELEGATE_REVOKED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_policy_get_suspended() -> Result<(), BoxError> {
    replay(&POLICY_GET_SUSPENDED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_policy_get_status_mutant() -> Result<(), BoxError> {
    status_mutant(&POLICY_GET_SUCCESS).await
}

// --- MailWorkPolicy/set ---

const POLICY_SET_SUCCESS: Case = Case {
    mutator: true,
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    effects: POLICY_EFFECTS,
    notify: &["tag:{seed.0}"],
    ..Case::new(
        "mail_work",
        "mail-work-policy-set-success",
        "success",
        "MailWorkPolicy/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkPolicy/set",{"accountId":"{seed.0}","operationId":"33333333-3333-4333-8333-000000000001","expectedGeneration":"0","timezone":"Asia/Shanghai","weekdayMask":62,"workdayStart":"09:00","workdayEnd":"18:00","holidays":["2026-10-01"],"slaMinutes":240},"c0"]]}"#,
    )
};

const POLICY_SET_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    effects: POLICY_EFFECTS,
    notify: &["tag:{seed.0}"],
    ..Case::new(
        "mail_work",
        "mail-work-policy-set-repeat",
        "repeat",
        "MailWorkPolicy/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkPolicy/set",{"accountId":"{seed.0}","operationId":"33333333-3333-4333-8333-000000000002","expectedGeneration":"0","timezone":"Asia/Shanghai","weekdayMask":62,"workdayStart":"09:00","workdayEnd":"18:00","holidays":["2026-10-01"],"slaMinutes":240},"c0"]]}"#,
    )
};

const POLICY_SET_CROSS_TENANT: Case = Case {
    mutator: true,
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_FOREIGN],
    effects: POLICY_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-policy-set-cross-tenant",
        "cross-tenant",
        "MailWorkPolicy/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkPolicy/set",{"accountId":"{seed.0}","operationId":"33333333-3333-4333-8333-000000000003","expectedGeneration":"0","timezone":"UTC","weekdayMask":62,"workdayStart":"09:00","workdayEnd":"17:00","holidays":[],"slaMinutes":480},"c0"]]}"#,
    )
};

const POLICY_SET_INVALID: Case = Case {
    mutator: true,
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    effects: POLICY_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-policy-set-invalid-input",
        "invalid-input",
        "MailWorkPolicy/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkPolicy/set",{"accountId":"{seed.0}","operationId":"33333333-3333-4333-8333-000000000004","expectedGeneration":"0","timezone":"Not/AZone","weekdayMask":62,"workdayStart":"09:00","workdayEnd":"17:00","holidays":[],"slaMinutes":480},"c0"]]}"#,
    )
};

const POLICY_SET_DELEGATE_ALLOWED: Case = Case {
    mutator: true,
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    effects: POLICY_EFFECTS,
    notify: &["tag:{seed.0}"],
    ..Case::new(
        "mail_work",
        "mail-work-policy-set-delegate-allowed",
        "delegate-allowed",
        "MailWorkPolicy/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkPolicy/set",{"accountId":"{seed.0}","operationId":"33333333-3333-4333-8333-000000000005","expectedGeneration":"0","timezone":"UTC","weekdayMask":62,"workdayStart":"09:00","workdayEnd":"17:00","holidays":[],"slaMinutes":480},"c0"]]}"#,
    )
};

const POLICY_SET_DELEGATE_INSUFFICIENT: Case = Case {
    mutator: true,
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_READ],
    effects: POLICY_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-policy-set-delegate-insufficient",
        "delegate-insufficient",
        "MailWorkPolicy/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkPolicy/set",{"accountId":"{seed.0}","operationId":"33333333-3333-4333-8333-000000000006","expectedGeneration":"0","timezone":"UTC","weekdayMask":62,"workdayStart":"09:00","workdayEnd":"17:00","holidays":[],"slaMinutes":480},"c0"]]}"#,
    )
};

const POLICY_SET_DELEGATE_REVOKED: Case = Case {
    mutator: true,
    toggles: WORK_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    setup: &[
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkPolicy/get",{"accountId":"{seed.0}"},"s0"]]}"#,
    ],
    between: &[REVOKE_DELEGATE],
    effects: POLICY_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-policy-set-delegate-revoked",
        "delegate-revoked",
        "MailWorkPolicy/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkPolicy/set",{"accountId":"{seed.0}","operationId":"33333333-3333-4333-8333-000000000007","expectedGeneration":"0","timezone":"UTC","weekdayMask":62,"workdayStart":"09:00","workdayEnd":"17:00","holidays":[],"slaMinutes":480},"c0"]]}"#,
    )
};

const POLICY_SET_SUSPENDED: Case = Case {
    mutator: true,
    toggles: WORK_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_FULL,
        SUSPEND_MAILBOX,
        SUSPEND_LIFECYCLE,
    ],
    effects: POLICY_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-policy-set-suspended",
        "suspended",
        "MailWorkPolicy/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkPolicy/set",{"accountId":"{seed.0}","operationId":"33333333-3333-4333-8333-000000000008","expectedGeneration":"0","timezone":"UTC","weekdayMask":62,"workdayStart":"09:00","workdayEnd":"17:00","holidays":[],"slaMinutes":480},"c0"]]}"#,
    )
};

const POLICY_SET_STATE_MISMATCH: Case = Case {
    mutator: true,
    toggles: WORK_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_FULL,
        "INSERT INTO mail_work_sla_policies (mailbox_id, timezone, weekday_mask, workday_start, workday_end, \
         holidays, sla_minutes, generation, updated_by) \
         VALUES ({seed.0}, 'UTC', 62, '09:00', '17:00', '{}', 480, 1, {a.user})",
    ],
    effects: POLICY_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-policy-set-state-mismatch",
        "state-mismatch",
        "MailWorkPolicy/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkPolicy/set",{"accountId":"{seed.0}","operationId":"33333333-3333-4333-8333-000000000009","expectedGeneration":"0","timezone":"UTC","weekdayMask":62,"workdayStart":"09:00","workdayEnd":"17:00","holidays":[],"slaMinutes":480},"c0"]]}"#,
    )
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_policy_set_success() -> Result<(), BoxError> {
    replay(&POLICY_SET_SUCCESS).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_policy_set_repeat() -> Result<(), BoxError> {
    replay(&POLICY_SET_REPEAT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_policy_set_cross_tenant() -> Result<(), BoxError> {
    replay(&POLICY_SET_CROSS_TENANT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_policy_set_invalid_input() -> Result<(), BoxError> {
    replay(&POLICY_SET_INVALID).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_policy_set_delegate_allowed() -> Result<(), BoxError> {
    replay(&POLICY_SET_DELEGATE_ALLOWED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_policy_set_delegate_insufficient() -> Result<(), BoxError> {
    replay(&POLICY_SET_DELEGATE_INSUFFICIENT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_policy_set_delegate_revoked() -> Result<(), BoxError> {
    replay(&POLICY_SET_DELEGATE_REVOKED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_policy_set_suspended() -> Result<(), BoxError> {
    replay(&POLICY_SET_SUSPENDED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_policy_set_state_mismatch() -> Result<(), BoxError> {
    replay(&POLICY_SET_STATE_MISMATCH).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_policy_set_status_mutant() -> Result<(), BoxError> {
    status_mutant(&POLICY_SET_SUCCESS).await
}

// --- MailWorkNotificationPreferences/get ---

const PREFS_GET_SUCCESS: Case = Case {
    toggles: NOTIFICATIONS_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    effects: PREFS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-notification-preferences-get-success",
        "success",
        "MailWorkNotificationPreferences/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkNotificationPreferences/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

const PREFS_GET_CROSS_TENANT: Case = Case {
    toggles: NOTIFICATIONS_TOGGLES,
    seed: &[SEED_SHARED_FOREIGN],
    effects: PREFS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-notification-preferences-get-cross-tenant",
        "cross-tenant",
        "MailWorkNotificationPreferences/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkNotificationPreferences/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

const PREFS_GET_INVALID: Case = Case {
    toggles: NOTIFICATIONS_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    effects: PREFS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-notification-preferences-get-invalid-input",
        "invalid-input",
        "MailWorkNotificationPreferences/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkNotificationPreferences/get",{"accountId":123},"c0"]]}"#,
    )
};

const PREFS_GET_DELEGATE_ALLOWED: Case = Case {
    toggles: NOTIFICATIONS_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_READ],
    effects: PREFS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-notification-preferences-get-delegate-allowed",
        "delegate-allowed",
        "MailWorkNotificationPreferences/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkNotificationPreferences/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

const PREFS_GET_DELEGATE_INSUFFICIENT: Case = Case {
    toggles: NOTIFICATIONS_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_CALENDAR],
    effects: PREFS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-notification-preferences-get-delegate-insufficient",
        "delegate-insufficient",
        "MailWorkNotificationPreferences/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkNotificationPreferences/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

const PREFS_GET_DELEGATE_REVOKED: Case = Case {
    toggles: NOTIFICATIONS_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_READ],
    setup: &[
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkNotificationPreferences/get",{"accountId":"{seed.0}"},"s0"]]}"#,
    ],
    between: &[REVOKE_DELEGATE],
    effects: PREFS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-notification-preferences-get-delegate-revoked",
        "delegate-revoked",
        "MailWorkNotificationPreferences/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkNotificationPreferences/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

const PREFS_GET_SUSPENDED: Case = Case {
    toggles: NOTIFICATIONS_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_READ,
        SUSPEND_MAILBOX,
        SUSPEND_LIFECYCLE,
    ],
    effects: PREFS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-notification-preferences-get-suspended",
        "suspended",
        "MailWorkNotificationPreferences/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkNotificationPreferences/get",{"accountId":"{seed.0}"},"c0"]]}"#,
    )
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_notification_preferences_get_success() -> Result<(), BoxError> {
    replay(&PREFS_GET_SUCCESS).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_notification_preferences_get_cross_tenant() -> Result<(), BoxError> {
    replay(&PREFS_GET_CROSS_TENANT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_notification_preferences_get_invalid_input() -> Result<(), BoxError> {
    replay(&PREFS_GET_INVALID).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_notification_preferences_get_delegate_allowed() -> Result<(), BoxError> {
    replay(&PREFS_GET_DELEGATE_ALLOWED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_notification_preferences_get_delegate_insufficient() -> Result<(), BoxError> {
    replay(&PREFS_GET_DELEGATE_INSUFFICIENT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_notification_preferences_get_delegate_revoked() -> Result<(), BoxError> {
    replay(&PREFS_GET_DELEGATE_REVOKED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_notification_preferences_get_suspended() -> Result<(), BoxError> {
    replay(&PREFS_GET_SUSPENDED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_notification_preferences_get_status_mutant() -> Result<(), BoxError> {
    status_mutant(&PREFS_GET_SUCCESS).await
}

// --- MailWorkNotificationPreferences/set ---

const PREFS_SET_SUCCESS: Case = Case {
    mutator: true,
    toggles: NOTIFICATIONS_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    effects: PREFS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-notification-preferences-set-success",
        "success",
        "MailWorkNotificationPreferences/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkNotificationPreferences/set",{"accountId":"{seed.0}","operationId":"44444444-4444-4444-8444-000000000001","category":"due","delivery":"digest","timezone":"Asia/Shanghai","digestHour":9,"expectedGeneration":"0"},"c0"]]}"#,
    )
};

const PREFS_SET_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    toggles: NOTIFICATIONS_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    effects: PREFS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-notification-preferences-set-repeat",
        "repeat",
        "MailWorkNotificationPreferences/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkNotificationPreferences/set",{"accountId":"{seed.0}","operationId":"44444444-4444-4444-8444-000000000002","category":"due","delivery":"digest","timezone":"Asia/Shanghai","digestHour":9,"expectedGeneration":"0"},"c0"]]}"#,
    )
};

const PREFS_SET_CROSS_TENANT: Case = Case {
    mutator: true,
    toggles: NOTIFICATIONS_TOGGLES,
    seed: &[SEED_SHARED_FOREIGN],
    effects: PREFS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-notification-preferences-set-cross-tenant",
        "cross-tenant",
        "MailWorkNotificationPreferences/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkNotificationPreferences/set",{"accountId":"{seed.0}","operationId":"44444444-4444-4444-8444-000000000003","category":"due","delivery":"digest","timezone":"UTC","digestHour":9,"expectedGeneration":"0"},"c0"]]}"#,
    )
};

const PREFS_SET_INVALID: Case = Case {
    mutator: true,
    toggles: NOTIFICATIONS_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    effects: PREFS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-notification-preferences-set-invalid-input",
        "invalid-input",
        "MailWorkNotificationPreferences/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkNotificationPreferences/set",{"accountId":"{seed.0}","operationId":"bad-uuid","category":"due","delivery":"digest","timezone":"UTC","digestHour":9,"expectedGeneration":"0"},"c0"]]}"#,
    )
};

const PREFS_SET_DELEGATE_ALLOWED: Case = Case {
    mutator: true,
    toggles: NOTIFICATIONS_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_SEND_AS],
    effects: PREFS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-notification-preferences-set-delegate-allowed",
        "delegate-allowed",
        "MailWorkNotificationPreferences/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkNotificationPreferences/set",{"accountId":"{seed.0}","operationId":"44444444-4444-4444-8444-000000000004","category":"assignment","delivery":"immediate","timezone":"UTC","digestHour":9,"expectedGeneration":"0"},"c0"]]}"#,
    )
};

const PREFS_SET_DELEGATE_INSUFFICIENT: Case = Case {
    mutator: true,
    toggles: NOTIFICATIONS_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_READ],
    effects: PREFS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-notification-preferences-set-delegate-insufficient",
        "delegate-insufficient",
        "MailWorkNotificationPreferences/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkNotificationPreferences/set",{"accountId":"{seed.0}","operationId":"44444444-4444-4444-8444-000000000005","category":"due","delivery":"digest","timezone":"UTC","digestHour":9,"expectedGeneration":"0"},"c0"]]}"#,
    )
};

const PREFS_SET_DELEGATE_REVOKED: Case = Case {
    mutator: true,
    toggles: NOTIFICATIONS_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    setup: &[
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkNotificationPreferences/get",{"accountId":"{seed.0}"},"s0"]]}"#,
    ],
    between: &[REVOKE_DELEGATE],
    effects: PREFS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-notification-preferences-set-delegate-revoked",
        "delegate-revoked",
        "MailWorkNotificationPreferences/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkNotificationPreferences/set",{"accountId":"{seed.0}","operationId":"44444444-4444-4444-8444-000000000006","category":"due","delivery":"digest","timezone":"UTC","digestHour":9,"expectedGeneration":"0"},"c0"]]}"#,
    )
};

const PREFS_SET_SUSPENDED: Case = Case {
    mutator: true,
    toggles: NOTIFICATIONS_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_FULL,
        SUSPEND_MAILBOX,
        SUSPEND_LIFECYCLE,
    ],
    effects: PREFS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-notification-preferences-set-suspended",
        "suspended",
        "MailWorkNotificationPreferences/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkNotificationPreferences/set",{"accountId":"{seed.0}","operationId":"44444444-4444-4444-8444-000000000007","category":"due","delivery":"digest","timezone":"UTC","digestHour":9,"expectedGeneration":"0"},"c0"]]}"#,
    )
};

const PREFS_SET_STATE_MISMATCH: Case = Case {
    mutator: true,
    toggles: NOTIFICATIONS_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_FULL,
        "INSERT INTO mail_work_notification_preferences (mailbox_id, user_id, category, delivery, timezone, digest_hour, generation) \
         VALUES ({seed.0}, {a.user}, 'due', 'digest', 'UTC', 9, 1)",
    ],
    effects: PREFS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-notification-preferences-set-state-mismatch",
        "state-mismatch",
        "MailWorkNotificationPreferences/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkNotificationPreferences/set",{"accountId":"{seed.0}","operationId":"44444444-4444-4444-8444-000000000008","category":"due","delivery":"off","timezone":"UTC","digestHour":9,"expectedGeneration":"0"},"c0"]]}"#,
    )
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_notification_preferences_set_success() -> Result<(), BoxError> {
    replay(&PREFS_SET_SUCCESS).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_notification_preferences_set_repeat() -> Result<(), BoxError> {
    replay(&PREFS_SET_REPEAT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_notification_preferences_set_cross_tenant() -> Result<(), BoxError> {
    replay(&PREFS_SET_CROSS_TENANT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_notification_preferences_set_invalid_input() -> Result<(), BoxError> {
    replay(&PREFS_SET_INVALID).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_notification_preferences_set_delegate_allowed() -> Result<(), BoxError> {
    replay(&PREFS_SET_DELEGATE_ALLOWED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_notification_preferences_set_delegate_insufficient() -> Result<(), BoxError> {
    replay(&PREFS_SET_DELEGATE_INSUFFICIENT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_notification_preferences_set_delegate_revoked() -> Result<(), BoxError> {
    replay(&PREFS_SET_DELEGATE_REVOKED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_notification_preferences_set_suspended() -> Result<(), BoxError> {
    replay(&PREFS_SET_SUSPENDED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_notification_preferences_set_state_mismatch() -> Result<(), BoxError> {
    replay(&PREFS_SET_STATE_MISMATCH).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_notification_preferences_set_status_mutant() -> Result<(), BoxError> {
    status_mutant(&PREFS_SET_SUCCESS).await
}

// --- MailWorkMetrics/get ---

const SEED_METRIC_DAILY: &str = "INSERT INTO mail_work_metric_daily (mailbox_id, metric_day, policy_version, \
    conversation_count, first_response_count, first_response_seconds, completed_count, breached_count, actor_cohort_count, rebuilt_at) \
    VALUES ({seed.0}, '2026-10-01', 1, 20, 10, 300, 15, 1, 5, '2026-10-01T12:00:00Z')";

const METRICS_GET_SUCCESS: Case = Case {
    toggles: ANALYTICS_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL, SEED_METRIC_DAILY],
    effects: METRICS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-metrics-get-success",
        "success",
        "MailWorkMetrics/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkMetrics/get",{"accountId":"{seed.0}","from":"2026-10-01","to":"2026-10-01","policyVersion":1},"c0"]]}"#,
    )
};

const METRICS_GET_CROSS_TENANT: Case = Case {
    toggles: ANALYTICS_TOGGLES,
    seed: &[SEED_SHARED_FOREIGN],
    effects: METRICS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-metrics-get-cross-tenant",
        "cross-tenant",
        "MailWorkMetrics/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkMetrics/get",{"accountId":"{seed.0}","from":"2026-10-01","to":"2026-10-01"},"c0"]]}"#,
    )
};

const METRICS_GET_INVALID: Case = Case {
    toggles: ANALYTICS_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    effects: METRICS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-metrics-get-invalid-input",
        "invalid-input",
        "MailWorkMetrics/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkMetrics/get",{"accountId":"{seed.0}","from":"2026-10-02","to":"2026-10-01"},"c0"]]}"#,
    )
};

const METRICS_GET_DELEGATE_ALLOWED: Case = Case {
    toggles: ANALYTICS_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL, SEED_METRIC_DAILY],
    effects: METRICS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-metrics-get-delegate-allowed",
        "delegate-allowed",
        "MailWorkMetrics/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkMetrics/get",{"accountId":"{seed.0}","from":"2026-10-01","to":"2026-10-01"},"c0"]]}"#,
    )
};

const METRICS_GET_DELEGATE_INSUFFICIENT: Case = Case {
    toggles: ANALYTICS_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_CALENDAR],
    effects: METRICS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-metrics-get-delegate-insufficient",
        "delegate-insufficient",
        "MailWorkMetrics/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkMetrics/get",{"accountId":"{seed.0}","from":"2026-10-01","to":"2026-10-01"},"c0"]]}"#,
    )
};

const METRICS_GET_DELEGATE_REVOKED: Case = Case {
    toggles: ANALYTICS_TOGGLES,
    seed: &[SEED_SHARED_OWN, SEED_DELEGATE_FULL],
    setup: &[
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkMetrics/get",{"accountId":"{seed.0}","from":"2026-10-01","to":"2026-10-01"},"s0"]]}"#,
    ],
    between: &[REVOKE_DELEGATE],
    effects: METRICS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-metrics-get-delegate-revoked",
        "delegate-revoked",
        "MailWorkMetrics/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkMetrics/get",{"accountId":"{seed.0}","from":"2026-10-01","to":"2026-10-01"},"c0"]]}"#,
    )
};

const METRICS_GET_SUSPENDED: Case = Case {
    toggles: ANALYTICS_TOGGLES,
    seed: &[
        SEED_SHARED_OWN,
        SEED_DELEGATE_FULL,
        SUSPEND_MAILBOX,
        SUSPEND_LIFECYCLE,
    ],
    effects: METRICS_EFFECTS,
    ..Case::new(
        "mail_work",
        "mail-work-metrics-get-suspended",
        "suspended",
        "MailWorkMetrics/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["MailWorkMetrics/get",{"accountId":"{seed.0}","from":"2026-10-01","to":"2026-10-01"},"c0"]]}"#,
    )
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_metrics_get_success() -> Result<(), BoxError> {
    replay(&METRICS_GET_SUCCESS).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_metrics_get_cross_tenant() -> Result<(), BoxError> {
    replay(&METRICS_GET_CROSS_TENANT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_metrics_get_invalid_input() -> Result<(), BoxError> {
    replay(&METRICS_GET_INVALID).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_metrics_get_delegate_allowed() -> Result<(), BoxError> {
    replay(&METRICS_GET_DELEGATE_ALLOWED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_metrics_get_delegate_insufficient() -> Result<(), BoxError> {
    replay(&METRICS_GET_DELEGATE_INSUFFICIENT).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_metrics_get_delegate_revoked() -> Result<(), BoxError> {
    replay(&METRICS_GET_DELEGATE_REVOKED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_metrics_get_suspended() -> Result<(), BoxError> {
    replay(&METRICS_GET_SUSPENDED).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_metrics_get_status_mutant() -> Result<(), BoxError> {
    status_mutant(&METRICS_GET_SUCCESS).await
}
