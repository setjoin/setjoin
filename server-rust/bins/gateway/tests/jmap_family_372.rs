//! Frozen-Go oracle suite for #372 (`MailDraft/*` and `MailComment/*`).

mod common;
mod jmap_family_oracle;

use jmap_family_oracle::{run, Case, Mutation};

const FAMILY: &str = "mail-draft";
const DRAFT_TOGGLES: &[(&str, bool)] = &[("feature.shared_mail_drafts", true)];
const COMMENT_TOGGLES: &[(&str, bool)] = &[("feature.shared_mail_comments", true)];
const COMMENT_SET_TOGGLES: &[(&str, bool)] = &[
    ("feature.shared_mail_work", true),
    ("feature.shared_mail_comments", true),
];

const SEED_SHARED_MAILBOX_A: &str =
    "INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary) \
    SELECT NULL, domain_id, 'shared-' || {a.mailbox} || '@oracle.test', 'Shared', 'personal', FALSE \
    FROM mailboxes WHERE id = {a.mailbox} RETURNING id";
const SEED_SHARED_MAILBOX_F: &str = "INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary) \
    SELECT NULL, domain_id, 'shared-' || {f.mailbox} || '@oracle.test', 'Shared Foreign', 'personal', FALSE \
    FROM mailboxes WHERE id = {f.mailbox} RETURNING id";
const GRANT_A_FULL: &str =
    "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
    VALUES ({seed.0}, {a.user}, 'full_access', {a.user})";
const GRANT_A_SEND: &str =
    "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
    VALUES ({seed.0}, {a.user}, 'send_as', {a.user})";
const GRANT_A_READ: &str =
    "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
    VALUES ({seed.0}, {a.user}, 'read', {a.user})";
const GRANT_A_CALENDAR: &str =
    "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
    VALUES ({seed.0}, {a.user}, 'manage_calendar', {a.user})";
const GRANT_F_READ: &str =
    "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
    VALUES ({seed.0}, {f.user}, 'read', {a.user})";
const GRANT_F_SEND: &str =
    "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
    VALUES ({seed.0}, {f.user}, 'send_as', {a.user})";
const REVOKE_SEED0: &str = "DELETE FROM mailbox_delegates WHERE mailbox_id = {seed.0};";

const SEED_DRAFT_MSG_SEED0: &str = "INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, body_text, size_bytes, thread_id, raw_ref, received_at, is_read, is_draft) \
    SELECT {seed.0}, (SELECT id FROM tags WHERE mailbox_id = {seed.0} AND name = 'Drafts'), '<draft@oracle.test>', 'Shared draft', email, 'draft body', 100, 'draft-thread-1', 's3://draft-1', '2026-11-01T00:00:00Z'::timestamptz, false, true \
    FROM mailboxes WHERE id = {seed.0} RETURNING id";
const SEED_DRAFT_SESSION_SEED0_MSG1: &str = "INSERT INTO mail_draft_collaboration (draft_session_id, mailbox_id, message_id, received_at, content_revision, lease_epoch, lease_holder_user_id, lease_expires_at, final_sender_address) \
    VALUES ('11111111-1111-4111-8111-111111111111', {seed.0}, {seed.1}, '2026-11-01T00:00:00Z'::timestamptz, 1, 1, {a.user}, now() + interval '2 minutes', 'shared-' || {a.mailbox} || '@oracle.test')";
const SEED_DRAFTS_TAG_SEED0: &str =
    "SELECT id FROM tags WHERE mailbox_id = {seed.0} AND name = 'Drafts'";

const SEED_COMMENT_MSG_SEED0: &str = "INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, body_text, size_bytes, thread_id, raw_ref, received_at, is_read) \
    SELECT {seed.0}, (SELECT id FROM tags WHERE mailbox_id = {seed.0} AND name = 'Inbox'), '<comment@oracle.test>', 'Comment item', 'sender@oracle.test', 'public MIME body', 100, 'comment-thread-1', 's3://comment-1', '2026-11-01T00:00:00Z'::timestamptz, false \
    FROM mailboxes WHERE id = {seed.0} RETURNING id";
const SEED_COMMENT_ROW_SEED0: &str = "INSERT INTO mail_thread_comments (id, mailbox_id, thread_id, author_user_id, author_display_snapshot, body, operation_id) \
    VALUES ('11111111-1111-4111-8111-111111111111', {seed.0}, 'comment-thread-1', {a.user}, 'Author', 'Private note', '22222222-2222-4222-8222-222222222222')";

const SHARED_DRAFT_EFFECTS: &[(&str, &str)] = &[
    (
        "mail_drafts",
        "SELECT coalesce(string_agg(draft_session_id::text || ':' || content_revision::text || ':' || lease_epoch::text || ':' || coalesce(lease_holder_user_id::text,'null') || ':' || state || ':' || generation::text, ',' ORDER BY draft_session_id), '') \
         FROM mail_draft_collaboration WHERE mailbox_id IN ({seed.0},{a.mailbox},{f.mailbox})",
    ),
    (
        "mail_draft_revisions",
        "SELECT count(*)::text FROM mail_draft_revisions r JOIN mail_draft_collaboration d ON d.draft_session_id = r.draft_session_id \
         WHERE d.mailbox_id IN ({seed.0},{a.mailbox},{f.mailbox})",
    ),
    (
        "mailwork_state",
        "SELECT coalesce((SELECT jmap_mailwork_state::text FROM mailboxes WHERE id = {seed.0}), 'null')",
    ),
    (
        "mail_work_operations",
        "SELECT count(*)::text FROM mail_work_operations WHERE mailbox_id = {seed.0}",
    ),
];

const REPLACE_DRAFT_EFFECTS: &[(&str, &str)] = &[
    (
        "mail_drafts",
        "SELECT coalesce(string_agg(draft_session_id::text || ':' || message_id::text || ':' || content_revision::text || ':' || lease_epoch::text || ':' || state || ':' || generation::text, ',' ORDER BY draft_session_id), '') \
         FROM mail_draft_collaboration WHERE mailbox_id = {seed.0}",
    ),
    (
        "mail_draft_revisions",
        "SELECT count(*)::text FROM mail_draft_revisions r JOIN mail_draft_collaboration d ON d.draft_session_id = r.draft_session_id \
         WHERE d.mailbox_id = {seed.0}",
    ),
    (
        "draft_messages",
        "SELECT count(*)::text || ':' || coalesce(string_agg(subject, ',' ORDER BY id), '') FROM messages WHERE mailbox_id = {seed.0} AND is_draft",
    ),
    (
        "mailwork_state",
        "SELECT jmap_mailwork_state::text || ':' || jmap_email_state::text FROM mailboxes WHERE id = {seed.0}",
    ),
    (
        "mail_work_operations",
        "SELECT count(*)::text FROM mail_work_operations WHERE mailbox_id = {seed.0}",
    ),
];

const FIXTURE_DRAFT_EFFECTS: &[(&str, &str)] = &[
    (
        "mail_drafts",
        "SELECT count(*)::text FROM mail_draft_collaboration WHERE mailbox_id IN ({a.mailbox},{f.mailbox})",
    ),
    (
        "mailwork_state",
        "SELECT string_agg(id::text || ':' || jmap_mailwork_state::text, ',' ORDER BY id) FROM mailboxes WHERE id IN ({a.mailbox},{f.mailbox})",
    ),
    (
        "mail_work_operations",
        "SELECT count(*)::text FROM mail_work_operations WHERE mailbox_id IN ({a.mailbox},{f.mailbox})",
    ),
];

const SHARED_COMMENT_EFFECTS: &[(&str, &str)] = &[
    (
        "mail_thread_comments",
        "SELECT coalesce(string_agg(body || ':' || (tombstoned_at IS NOT NULL)::text, ',' ORDER BY created_at, id), '') \
         FROM mail_thread_comments WHERE mailbox_id = {seed.0}",
    ),
    (
        "mail_thread_work",
        "SELECT coalesce(string_agg(thread_id || ':' || status || ':' || coalesce(assignee_user_id::text,'null') || ':' || generation::text, ',' ORDER BY thread_id), '') \
         FROM mail_thread_work WHERE mailbox_id = {seed.0}",
    ),
    (
        "mailwork_state",
        "SELECT jmap_mailwork_state::text FROM mailboxes WHERE id = {seed.0}",
    ),
    (
        "mail_work_operations",
        "SELECT count(*)::text FROM mail_work_operations WHERE mailbox_id = {seed.0}",
    ),
];

const FIXTURE_COMMENT_EFFECTS: &[(&str, &str)] = &[
    (
        "mail_thread_comments",
        "SELECT count(*)::text FROM mail_thread_comments WHERE mailbox_id IN ({a.mailbox},{f.mailbox})",
    ),
    (
        "mailwork_state",
        "SELECT string_agg(id::text || ':' || jmap_mailwork_state::text, ',' ORDER BY id) FROM mailboxes WHERE id IN ({a.mailbox},{f.mailbox})",
    ),
    (
        "mail_work_operations",
        "SELECT count(*)::text FROM mail_work_operations WHERE mailbox_id IN ({a.mailbox},{f.mailbox})",
    ),
];

const SUSPEND_SEED0_BETWEEN: &[&str] = &[
    "UPDATE mailboxes SET enabled = false WHERE id = {seed.0};",
    "UPDATE mailbox_lifecycle SET access_state = 'suspended', generation = generation + 1, updated_at = statement_timestamp() WHERE mailbox_id = {seed.0} AND binding_state IN ('bound','shared');",
];

async fn status_mutant(case: &Case) {
    match run(case, Mutation::Status).await {
        Err(error) => {
            let text = error.to_string();
            assert!(
                text.starts_with("GOLDEN-DIFF ") && text.contains("/response/status"),
                "{text}"
            );
            println!(
                "MUTANT-REJECTED: POST /jmap {} :: changed-status",
                case.method
            );
        }
        Ok(()) => {
            if std::env::var_os("REQUIRE_DB").is_some_and(|value| value == "1") {
                panic!("status mutant survived for {}", case.method);
            }
        }
    }
}

// ============================================================================
// MailDraft/get
// ============================================================================

const MAIL_DRAFT_GET_SUCCESS: Case = Case {
    toggles: DRAFT_TOGGLES,
    // seed.0: a's shared mailbox; seed.1: a's draft message; seed.2: f's shared mailbox; seed.3: f's draft message.
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
        SEED_SHARED_MAILBOX_F,
        "INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, body_text, size_bytes, thread_id, raw_ref, received_at, is_read, is_draft) \
         SELECT {seed.2}, (SELECT id FROM tags WHERE mailbox_id = {seed.2} AND name = 'Drafts'), '<fdraft@oracle.test>', 'Foreign draft', email, 'foreign body', 100, 'fdraft-thread', 's3://fdraft', '2026-11-01T00:00:00Z'::timestamptz, false, true \
         FROM mailboxes WHERE id = {seed.2} RETURNING id",
        "INSERT INTO mail_draft_collaboration (draft_session_id, mailbox_id, message_id, received_at, content_revision, lease_epoch, lease_holder_user_id, lease_expires_at, final_sender_address) \
         VALUES ('22222222-2222-4222-8222-222222222222', {seed.2}, {seed.3}, '2026-11-01T00:00:00Z'::timestamptz, 1, 1, {f.user}, now() + interval '2 minutes', 'shared-' || {f.mailbox} || '@oracle.test')",
    ],
    absent: &["{seed.2}", "{seed.3}"],
    effects: &[
        (
            "mail_drafts",
            "SELECT count(*)::text FROM mail_draft_collaboration WHERE mailbox_id IN ({seed.0},{seed.2})",
        ),
        (
            "mailwork_state",
            "SELECT jmap_mailwork_state::text FROM mailboxes WHERE id = {seed.0}",
        ),
    ],
    ..Case::new(
        FAMILY,
        "mail-draft-get-success",
        "success",
        "MailDraft/get",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/get",{"accountId":"{seed.0}"},"c1"]]}"#,
    )
};

const MAIL_DRAFT_GET_NOT_FOUND: Case = Case {
    toggles: DRAFT_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_FULL],
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-get-not-found",
        "not-found",
        "MailDraft/get",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/get",{"accountId":"{seed.0}","ids":["99999999-9999-4999-8999-999999999999"]},"c1"]]}"#,
    )
};

const MAIL_DRAFT_GET_CROSS_TENANT: Case = Case {
    toggles: DRAFT_TOGGLES,
    effects: FIXTURE_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-get-cross-tenant",
        "cross-tenant",
        "MailDraft/get",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/get",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};

const MAIL_DRAFT_GET_INVALID_INPUT: Case = Case {
    toggles: DRAFT_TOGGLES,
    effects: FIXTURE_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-get-invalid-input",
        "invalid-input",
        "MailDraft/get",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/get",{"accountId":"{a.mailbox}","ids":["not-a-uuid"]},"c1"]]}"#,
    )
};

const MAIL_DRAFT_GET_DELEGATE_ALLOWED: Case = Case {
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_READ,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-get-delegate-allowed",
        "delegate-allowed",
        "MailDraft/get",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/get",{"accountId":"{seed.0}"},"c1"]]}"#,
    )
};

const MAIL_DRAFT_GET_DELEGATE_INSUFFICIENT: Case = Case {
    toggles: DRAFT_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_CALENDAR],
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-get-delegate-insufficient",
        "delegate-insufficient",
        "MailDraft/get",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/get",{"accountId":"{seed.0}"},"c1"]]}"#,
    )
};

const MAIL_DRAFT_GET_DELEGATE_REVOKED: Case = Case {
    toggles: DRAFT_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_READ],
    between: &[REVOKE_SEED0],
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-get-delegate-revoked",
        "delegate-revoked",
        "MailDraft/get",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/get",{"accountId":"{seed.0}"},"c1"]]}"#,
    )
};

const MAIL_DRAFT_GET_SUSPENDED: Case = Case {
    toggles: DRAFT_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_READ],
    between: SUSPEND_SEED0_BETWEEN,
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-get-suspended",
        "suspended",
        "MailDraft/get",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/get",{"accountId":"{seed.0}"},"c1"]]}"#,
    )
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_get_success() {
    run(&MAIL_DRAFT_GET_SUCCESS, Mutation::None).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_get_not_found() {
    run(&MAIL_DRAFT_GET_NOT_FOUND, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_get_cross_tenant() {
    run(&MAIL_DRAFT_GET_CROSS_TENANT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_get_invalid_input() {
    run(&MAIL_DRAFT_GET_INVALID_INPUT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_get_delegate_allowed() {
    run(&MAIL_DRAFT_GET_DELEGATE_ALLOWED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_get_delegate_insufficient() {
    run(&MAIL_DRAFT_GET_DELEGATE_INSUFFICIENT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_get_delegate_revoked() {
    run(&MAIL_DRAFT_GET_DELEGATE_REVOKED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_get_suspended() {
    run(&MAIL_DRAFT_GET_SUSPENDED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_get_status_mutant() {
    status_mutant(&MAIL_DRAFT_GET_SUCCESS).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_get_no_tenant_filter_mutant() {
    // Pitfall #4: absent must be empty so NoTenantFilter observes GOLDEN-DIFF instead of early absent panic.
    let mutant = Case {
        absent: &[],
        ..MAIL_DRAFT_GET_SUCCESS
    };
    run(
        &mutant,
        Mutation::NoTenantFilter {
            function: "mail_draft_get(bigint,bigint,uuid[])",
            from: "d.mailbox_id=p_mailbox_id",
        },
    )
    .await
    .unwrap();
}

// ============================================================================
// MailDraft/open
// ============================================================================

const MAIL_DRAFT_OPEN_SUCCESS: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_FULL, SEED_DRAFT_MSG_SEED0],
    effects: SHARED_DRAFT_EFFECTS,
    notify: &["tag:{seed.0}"],
    ..Case::new(
        FAMILY,
        "mail-draft-open-success",
        "success",
        "MailDraft/open",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/open",{"accountId":"{seed.0}","operationId":"11111111-1111-4111-8111-111111111111","messageId":"{seed.1}","receivedAt":"2026-11-01T00:00:00Z","finalSenderAddress":"shared-{a.mailbox}@oracle.test"},"c1"]]}"#,
    )
};

const MAIL_DRAFT_OPEN_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    toggles: DRAFT_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_FULL, SEED_DRAFT_MSG_SEED0],
    effects: SHARED_DRAFT_EFFECTS,
    notify: &["tag:{seed.0}"],
    ..Case::new(
        FAMILY,
        "mail-draft-open-repeat",
        "repeat",
        "MailDraft/open",
        MAIL_DRAFT_OPEN_SUCCESS.request,
    )
};

const MAIL_DRAFT_OPEN_NOT_FOUND: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_FULL],
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-open-not-found",
        "not-found",
        "MailDraft/open",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/open",{"accountId":"{seed.0}","operationId":"11111111-1111-4111-8111-111111111111","messageId":"999999","receivedAt":"2026-11-01T00:00:00Z","finalSenderAddress":"shared-{a.mailbox}@oracle.test"},"c1"]]}"#,
    )
};

const MAIL_DRAFT_OPEN_CROSS_TENANT: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    effects: FIXTURE_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-open-cross-tenant",
        "cross-tenant",
        "MailDraft/open",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/open",{"accountId":"{f.mailbox}","operationId":"11111111-1111-4111-8111-111111111111","messageId":"1","receivedAt":"2026-11-01T00:00:00Z","finalSenderAddress":"x@oracle.test"},"c1"]]}"#,
    )
};

const MAIL_DRAFT_OPEN_INVALID_INPUT: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    effects: FIXTURE_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-open-invalid-input",
        "invalid-input",
        "MailDraft/open",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/open",{"accountId":"{a.mailbox}","operationId":"bad","messageId":"0","receivedAt":"bad","finalSenderAddress":"x@oracle.test"},"c1"]]}"#,
    )
};

const MAIL_DRAFT_OPEN_DELEGATE_ALLOWED: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_SEND, SEED_DRAFT_MSG_SEED0],
    effects: SHARED_DRAFT_EFFECTS,
    notify: &["tag:{seed.0}"],
    ..Case::new(
        FAMILY,
        "mail-draft-open-delegate-allowed",
        "delegate-allowed",
        "MailDraft/open",
        MAIL_DRAFT_OPEN_SUCCESS.request,
    )
};

const MAIL_DRAFT_OPEN_DELEGATE_INSUFFICIENT: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_READ, SEED_DRAFT_MSG_SEED0],
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-open-delegate-insufficient",
        "delegate-insufficient",
        "MailDraft/open",
        MAIL_DRAFT_OPEN_SUCCESS.request,
    )
};

const MAIL_DRAFT_OPEN_DELEGATE_REVOKED: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_FULL, SEED_DRAFT_MSG_SEED0],
    between: &[REVOKE_SEED0],
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-open-delegate-revoked",
        "delegate-revoked",
        "MailDraft/open",
        MAIL_DRAFT_OPEN_SUCCESS.request,
    )
};

const MAIL_DRAFT_OPEN_SUSPENDED: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_FULL, SEED_DRAFT_MSG_SEED0],
    between: SUSPEND_SEED0_BETWEEN,
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-open-suspended",
        "suspended",
        "MailDraft/open",
        MAIL_DRAFT_OPEN_SUCCESS.request,
    )
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_open_success() {
    run(&MAIL_DRAFT_OPEN_SUCCESS, Mutation::None).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_open_repeat() {
    run(&MAIL_DRAFT_OPEN_REPEAT, Mutation::None).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_open_not_found() {
    run(&MAIL_DRAFT_OPEN_NOT_FOUND, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_open_cross_tenant() {
    run(&MAIL_DRAFT_OPEN_CROSS_TENANT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_open_invalid_input() {
    run(&MAIL_DRAFT_OPEN_INVALID_INPUT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_open_delegate_allowed() {
    run(&MAIL_DRAFT_OPEN_DELEGATE_ALLOWED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_open_delegate_insufficient() {
    run(&MAIL_DRAFT_OPEN_DELEGATE_INSUFFICIENT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_open_delegate_revoked() {
    run(&MAIL_DRAFT_OPEN_DELEGATE_REVOKED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_open_suspended() {
    run(&MAIL_DRAFT_OPEN_SUSPENDED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_open_status_mutant() {
    status_mutant(&MAIL_DRAFT_OPEN_SUCCESS).await;
}

// ============================================================================
// MailDraft/lease
// ============================================================================

const MAIL_DRAFT_LEASE_SUCCESS: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        GRANT_F_SEND,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    effects: SHARED_DRAFT_EFFECTS,
    notify: &["tag:{seed.0}"],
    ..Case::new(
        FAMILY,
        "mail-draft-lease-success",
        "success",
        "MailDraft/lease",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/lease",{"accountId":"{seed.0}","operationId":"22222222-2222-4222-8222-222222222222","id":"11111111-1111-4111-8111-111111111111","action":"handoff","expectedEpoch":"1","targetUserId":"{f.user}","reason":"handoff for review"},"c1"]]}"#,
    )
};

const MAIL_DRAFT_LEASE_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        GRANT_F_SEND,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    effects: SHARED_DRAFT_EFFECTS,
    notify: &["tag:{seed.0}"],
    ..Case::new(
        FAMILY,
        "mail-draft-lease-repeat",
        "repeat",
        "MailDraft/lease",
        MAIL_DRAFT_LEASE_SUCCESS.request,
    )
};

const MAIL_DRAFT_LEASE_STATE_MISMATCH: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-lease-state-mismatch",
        "state-mismatch",
        "MailDraft/lease",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/lease",{"accountId":"{seed.0}","operationId":"22222222-2222-4222-8222-222222222222","id":"11111111-1111-4111-8111-111111111111","action":"renew","expectedEpoch":"99","reason":"stale epoch"},"c1"]]}"#,
    )
};

const MAIL_DRAFT_LEASE_NOT_FOUND: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_FULL],
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-lease-not-found",
        "not-found",
        "MailDraft/lease",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/lease",{"accountId":"{seed.0}","operationId":"22222222-2222-4222-8222-222222222222","id":"99999999-9999-4999-8999-999999999999","action":"renew","expectedEpoch":"1","reason":"missing"},"c1"]]}"#,
    )
};

const MAIL_DRAFT_LEASE_CROSS_TENANT: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    effects: FIXTURE_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-lease-cross-tenant",
        "cross-tenant",
        "MailDraft/lease",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/lease",{"accountId":"{f.mailbox}","operationId":"22222222-2222-4222-8222-222222222222","id":"11111111-1111-4111-8111-111111111111","action":"renew","expectedEpoch":"1","reason":"foreign"},"c1"]]}"#,
    )
};

const MAIL_DRAFT_LEASE_INVALID_INPUT: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    effects: FIXTURE_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-lease-invalid-input",
        "invalid-input",
        "MailDraft/lease",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/lease",{"accountId":"{a.mailbox}","operationId":"22222222-2222-4222-8222-222222222222","id":"11111111-1111-4111-8111-111111111111","action":"renew","expectedEpoch":"0","reason":"bad epoch"},"c1"]]}"#,
    )
};

const MAIL_DRAFT_LEASE_DELEGATE_ALLOWED: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_SEND,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    effects: SHARED_DRAFT_EFFECTS,
    notify: &["tag:{seed.0}"],
    ..Case::new(
        FAMILY,
        "mail-draft-lease-delegate-allowed",
        "delegate-allowed",
        "MailDraft/lease",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/lease",{"accountId":"{seed.0}","operationId":"22222222-2222-4222-8222-222222222222","id":"11111111-1111-4111-8111-111111111111","action":"renew","expectedEpoch":"1","reason":"still editing"},"c1"]]}"#,
    )
};

const MAIL_DRAFT_LEASE_DELEGATE_INSUFFICIENT: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_READ,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-lease-delegate-insufficient",
        "delegate-insufficient",
        "MailDraft/lease",
        MAIL_DRAFT_LEASE_DELEGATE_ALLOWED.request,
    )
};

const MAIL_DRAFT_LEASE_DELEGATE_REVOKED: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    between: &[REVOKE_SEED0],
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-lease-delegate-revoked",
        "delegate-revoked",
        "MailDraft/lease",
        MAIL_DRAFT_LEASE_DELEGATE_ALLOWED.request,
    )
};

const MAIL_DRAFT_LEASE_SUSPENDED: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    between: SUSPEND_SEED0_BETWEEN,
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-lease-suspended",
        "suspended",
        "MailDraft/lease",
        MAIL_DRAFT_LEASE_DELEGATE_ALLOWED.request,
    )
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_lease_success() {
    run(&MAIL_DRAFT_LEASE_SUCCESS, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_lease_repeat() {
    run(&MAIL_DRAFT_LEASE_REPEAT, Mutation::None).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_lease_state_mismatch() {
    run(&MAIL_DRAFT_LEASE_STATE_MISMATCH, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_lease_not_found() {
    run(&MAIL_DRAFT_LEASE_NOT_FOUND, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_lease_cross_tenant() {
    run(&MAIL_DRAFT_LEASE_CROSS_TENANT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_lease_invalid_input() {
    run(&MAIL_DRAFT_LEASE_INVALID_INPUT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_lease_delegate_allowed() {
    run(&MAIL_DRAFT_LEASE_DELEGATE_ALLOWED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_lease_delegate_insufficient() {
    run(&MAIL_DRAFT_LEASE_DELEGATE_INSUFFICIENT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_lease_delegate_revoked() {
    run(&MAIL_DRAFT_LEASE_DELEGATE_REVOKED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_lease_suspended() {
    run(&MAIL_DRAFT_LEASE_SUSPENDED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_lease_status_mutant() {
    status_mutant(&MAIL_DRAFT_LEASE_SUCCESS).await;
}

// ============================================================================
// MailDraft/save
// ============================================================================

const MAIL_DRAFT_SAVE_SUCCESS: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    effects: SHARED_DRAFT_EFFECTS,
    notify: &["tag:{seed.0}"],
    ..Case::new(
        FAMILY,
        "mail-draft-save-success",
        "success",
        "MailDraft/save",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/save",{"accountId":"{seed.0}","operationId":"33333333-3333-4333-8333-333333333333","id":"11111111-1111-4111-8111-111111111111","expectedEpoch":"1","baseRevision":"1","messageId":"{seed.1}","receivedAt":"2026-11-01T00:00:00Z","contentDigest":"1111111111111111111111111111111111111111111111111111111111111111","attachmentDigest":"2222222222222222222222222222222222222222222222222222222222222222"},"c1"]]}"#,
    )
};

const MAIL_DRAFT_SAVE_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    effects: SHARED_DRAFT_EFFECTS,
    notify: &["tag:{seed.0}"],
    ..Case::new(
        FAMILY,
        "mail-draft-save-repeat",
        "repeat",
        "MailDraft/save",
        MAIL_DRAFT_SAVE_SUCCESS.request,
    )
};

const MAIL_DRAFT_SAVE_STATE_MISMATCH: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-save-state-mismatch",
        "state-mismatch",
        "MailDraft/save",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/save",{"accountId":"{seed.0}","operationId":"33333333-3333-4333-8333-333333333333","id":"11111111-1111-4111-8111-111111111111","expectedEpoch":"1","baseRevision":"99","messageId":"{seed.1}","receivedAt":"2026-11-01T00:00:00Z","contentDigest":"1111111111111111111111111111111111111111111111111111111111111111","attachmentDigest":"2222222222222222222222222222222222222222222222222222222222222222"},"c1"]]}"#,
    )
};

const MAIL_DRAFT_SAVE_NOT_FOUND: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    between: &["DELETE FROM messages WHERE mailbox_id = {seed.0} AND id = {seed.1};"],
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-save-not-found",
        "not-found",
        "MailDraft/save",
        MAIL_DRAFT_SAVE_SUCCESS.request,
    )
};

const MAIL_DRAFT_SAVE_CROSS_TENANT: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    effects: FIXTURE_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-save-cross-tenant",
        "cross-tenant",
        "MailDraft/save",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/save",{"accountId":"{f.mailbox}","operationId":"33333333-3333-4333-8333-333333333333","id":"11111111-1111-4111-8111-111111111111","expectedEpoch":"1","baseRevision":"1","messageId":"1","receivedAt":"2026-11-01T00:00:00Z","contentDigest":"1111111111111111111111111111111111111111111111111111111111111111","attachmentDigest":"2222222222222222222222222222222222222222222222222222222222222222"},"c1"]]}"#,
    )
};

const MAIL_DRAFT_SAVE_INVALID_INPUT: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    effects: FIXTURE_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-save-invalid-input",
        "invalid-input",
        "MailDraft/save",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/save",{"accountId":"{a.mailbox}","operationId":"33333333-3333-4333-8333-333333333333","id":"11111111-1111-4111-8111-111111111111","expectedEpoch":"1","baseRevision":"1","messageId":"1","receivedAt":"2026-11-01T00:00:00Z","contentDigest":"short","attachmentDigest":"2222222222222222222222222222222222222222222222222222222222222222"},"c1"]]}"#,
    )
};

const MAIL_DRAFT_SAVE_DELEGATE_ALLOWED: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_SEND,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    effects: SHARED_DRAFT_EFFECTS,
    notify: &["tag:{seed.0}"],
    ..Case::new(
        FAMILY,
        "mail-draft-save-delegate-allowed",
        "delegate-allowed",
        "MailDraft/save",
        MAIL_DRAFT_SAVE_SUCCESS.request,
    )
};

const MAIL_DRAFT_SAVE_DELEGATE_INSUFFICIENT: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_READ,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-save-delegate-insufficient",
        "delegate-insufficient",
        "MailDraft/save",
        MAIL_DRAFT_SAVE_SUCCESS.request,
    )
};

const MAIL_DRAFT_SAVE_DELEGATE_REVOKED: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    between: &[REVOKE_SEED0],
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-save-delegate-revoked",
        "delegate-revoked",
        "MailDraft/save",
        MAIL_DRAFT_SAVE_SUCCESS.request,
    )
};

const MAIL_DRAFT_SAVE_SUSPENDED: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    between: SUSPEND_SEED0_BETWEEN,
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-save-suspended",
        "suspended",
        "MailDraft/save",
        MAIL_DRAFT_SAVE_SUCCESS.request,
    )
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_save_success() {
    run(&MAIL_DRAFT_SAVE_SUCCESS, Mutation::None).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_save_repeat() {
    run(&MAIL_DRAFT_SAVE_REPEAT, Mutation::None).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_save_state_mismatch() {
    run(&MAIL_DRAFT_SAVE_STATE_MISMATCH, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_save_not_found() {
    run(&MAIL_DRAFT_SAVE_NOT_FOUND, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_save_cross_tenant() {
    run(&MAIL_DRAFT_SAVE_CROSS_TENANT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_save_invalid_input() {
    run(&MAIL_DRAFT_SAVE_INVALID_INPUT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_save_delegate_allowed() {
    run(&MAIL_DRAFT_SAVE_DELEGATE_ALLOWED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_save_delegate_insufficient() {
    run(&MAIL_DRAFT_SAVE_DELEGATE_INSUFFICIENT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_save_delegate_revoked() {
    run(&MAIL_DRAFT_SAVE_DELEGATE_REVOKED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_save_suspended() {
    run(&MAIL_DRAFT_SAVE_SUSPENDED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_save_status_mutant() {
    status_mutant(&MAIL_DRAFT_SAVE_SUCCESS).await;
}

// ============================================================================
// MailDraft/replace
// ============================================================================

const MAIL_DRAFT_REPLACE_SUCCESS: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    // seed.0: shared mailbox; seed.1: old draft message; seed.2: Drafts tag.
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFTS_TAG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    effects: REPLACE_DRAFT_EFFECTS,
    notify: &["tag:{seed.0}"],
    scrub: &[("/methodResponses/0/1/messageId", "new_message")],
    ..Case::new(
        FAMILY,
        "mail-draft-replace-success",
        "success",
        "MailDraft/replace",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/replace",{"accountId":"{seed.0}","operationId":"44444444-4444-4444-8444-444444444444","id":"11111111-1111-4111-8111-111111111111","expectedEpoch":"1","baseRevision":"1","draft":{"from":[{"email":"shared-{a.mailbox}@oracle.test"}],"to":[],"subject":"After replace","bodyValues":{"text":{"value":"after body","partId":"text"}},"textBody":[{"partId":"text","type":"text/plain"}],"mailboxIds":{"{seed.2}":true}}},"c1"]]}"#,
    )
};

const MAIL_DRAFT_REPLACE_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFTS_TAG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    effects: REPLACE_DRAFT_EFFECTS,
    notify: &["tag:{seed.0}"],
    scrub: &[("/methodResponses/0/1/messageId", "new_message")],
    ..Case::new(
        FAMILY,
        "mail-draft-replace-repeat",
        "repeat",
        "MailDraft/replace",
        MAIL_DRAFT_REPLACE_SUCCESS.request,
    )
};

const MAIL_DRAFT_REPLACE_STATE_MISMATCH: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFTS_TAG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-replace-state-mismatch",
        "state-mismatch",
        "MailDraft/replace",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/replace",{"accountId":"{seed.0}","operationId":"44444444-4444-4444-8444-444444444444","id":"11111111-1111-4111-8111-111111111111","expectedEpoch":"1","baseRevision":"99","draft":{"from":[{"email":"shared-{a.mailbox}@oracle.test"}],"to":[],"subject":"Stale","bodyValues":{"text":{"value":"after body","partId":"text"}},"textBody":[{"partId":"text","type":"text/plain"}],"mailboxIds":{"{seed.2}":true}}},"c1"]]}"#,
    )
};

const MAIL_DRAFT_REPLACE_NOT_FOUND: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFTS_TAG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    between: &["DELETE FROM messages WHERE mailbox_id = {seed.0} AND id = {seed.1};"],
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-replace-not-found",
        "not-found",
        "MailDraft/replace",
        MAIL_DRAFT_REPLACE_SUCCESS.request,
    )
};

const MAIL_DRAFT_REPLACE_CROSS_TENANT: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    effects: FIXTURE_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-replace-cross-tenant",
        "cross-tenant",
        "MailDraft/replace",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/replace",{"accountId":"{f.mailbox}","operationId":"44444444-4444-4444-8444-444444444444","id":"11111111-1111-4111-8111-111111111111","expectedEpoch":"1","baseRevision":"1","draft":{"from":[{"email":"x@oracle.test"}]}},"c1"]]}"#,
    )
};

const MAIL_DRAFT_REPLACE_INVALID_INPUT: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    effects: FIXTURE_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-replace-invalid-input",
        "invalid-input",
        "MailDraft/replace",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailDraft/replace",{"accountId":"{a.mailbox}","operationId":"44444444-4444-4444-8444-444444444444","id":"11111111-1111-4111-8111-111111111111","expectedEpoch":"1","baseRevision":"1","draft":null},"c1"]]}"#,
    )
};

const MAIL_DRAFT_REPLACE_DELEGATE_ALLOWED: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_SEND,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFTS_TAG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    effects: REPLACE_DRAFT_EFFECTS,
    notify: &["tag:{seed.0}"],
    scrub: &[("/methodResponses/0/1/messageId", "new_message")],
    ..Case::new(
        FAMILY,
        "mail-draft-replace-delegate-allowed",
        "delegate-allowed",
        "MailDraft/replace",
        MAIL_DRAFT_REPLACE_SUCCESS.request,
    )
};

const MAIL_DRAFT_REPLACE_DELEGATE_INSUFFICIENT: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_READ,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFTS_TAG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-replace-delegate-insufficient",
        "delegate-insufficient",
        "MailDraft/replace",
        MAIL_DRAFT_REPLACE_SUCCESS.request,
    )
};

const MAIL_DRAFT_REPLACE_DELEGATE_REVOKED: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFTS_TAG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    between: &[REVOKE_SEED0],
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-replace-delegate-revoked",
        "delegate-revoked",
        "MailDraft/replace",
        MAIL_DRAFT_REPLACE_SUCCESS.request,
    )
};

const MAIL_DRAFT_REPLACE_SUSPENDED: Case = Case {
    mutator: true,
    toggles: DRAFT_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        SEED_DRAFT_MSG_SEED0,
        SEED_DRAFTS_TAG_SEED0,
        SEED_DRAFT_SESSION_SEED0_MSG1,
    ],
    between: SUSPEND_SEED0_BETWEEN,
    effects: SHARED_DRAFT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-draft-replace-suspended",
        "suspended",
        "MailDraft/replace",
        MAIL_DRAFT_REPLACE_SUCCESS.request,
    )
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_replace_success() {
    run(&MAIL_DRAFT_REPLACE_SUCCESS, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_replace_repeat() {
    run(&MAIL_DRAFT_REPLACE_REPEAT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_replace_state_mismatch() {
    run(&MAIL_DRAFT_REPLACE_STATE_MISMATCH, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_replace_not_found() {
    run(&MAIL_DRAFT_REPLACE_NOT_FOUND, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_replace_cross_tenant() {
    run(&MAIL_DRAFT_REPLACE_CROSS_TENANT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_replace_invalid_input() {
    run(&MAIL_DRAFT_REPLACE_INVALID_INPUT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_replace_delegate_allowed() {
    run(&MAIL_DRAFT_REPLACE_DELEGATE_ALLOWED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_replace_delegate_insufficient() {
    run(&MAIL_DRAFT_REPLACE_DELEGATE_INSUFFICIENT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_replace_delegate_revoked() {
    run(&MAIL_DRAFT_REPLACE_DELEGATE_REVOKED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_replace_suspended() {
    run(&MAIL_DRAFT_REPLACE_SUSPENDED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_draft_replace_status_mutant() {
    status_mutant(&MAIL_DRAFT_REPLACE_SUCCESS).await;
}

// ============================================================================
// MailComment/get
// ============================================================================

const MAIL_COMMENT_GET_SUCCESS: Case = Case {
    toggles: COMMENT_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_FULL, SEED_COMMENT_ROW_SEED0],
    effects: SHARED_COMMENT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-comment-get-success",
        "success",
        "MailComment/get",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailComment/get",{"accountId":"{seed.0}","threadId":"comment-thread-1","limit":10},"c1"]]}"#,
    )
};

const MAIL_COMMENT_GET_NOT_FOUND: Case = Case {
    toggles: COMMENT_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_FULL],
    effects: SHARED_COMMENT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-comment-get-not-found",
        "not-found",
        "MailComment/get",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailComment/get",{"accountId":"{seed.0}","threadId":"no-such-thread"},"c1"]]}"#,
    )
};

const MAIL_COMMENT_GET_CROSS_TENANT: Case = Case {
    toggles: COMMENT_TOGGLES,
    effects: FIXTURE_COMMENT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-comment-get-cross-tenant",
        "cross-tenant",
        "MailComment/get",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailComment/get",{"accountId":"{f.mailbox}","threadId":"comment-thread-1"},"c1"]]}"#,
    )
};

const MAIL_COMMENT_GET_INVALID_INPUT: Case = Case {
    toggles: COMMENT_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_FULL],
    effects: SHARED_COMMENT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-comment-get-invalid-input",
        "invalid-input",
        "MailComment/get",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailComment/get",{"accountId":"{seed.0}","threadId":"comment-thread-1","limit":101},"c1"]]}"#,
    )
};

const MAIL_COMMENT_GET_DELEGATE_ALLOWED: Case = Case {
    toggles: COMMENT_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_READ, SEED_COMMENT_ROW_SEED0],
    effects: SHARED_COMMENT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-comment-get-delegate-allowed",
        "delegate-allowed",
        "MailComment/get",
        MAIL_COMMENT_GET_SUCCESS.request,
    )
};

const MAIL_COMMENT_GET_DELEGATE_INSUFFICIENT: Case = Case {
    toggles: COMMENT_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_CALENDAR],
    effects: SHARED_COMMENT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-comment-get-delegate-insufficient",
        "delegate-insufficient",
        "MailComment/get",
        MAIL_COMMENT_GET_SUCCESS.request,
    )
};

const MAIL_COMMENT_GET_DELEGATE_REVOKED: Case = Case {
    toggles: COMMENT_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_READ],
    between: &[REVOKE_SEED0],
    effects: SHARED_COMMENT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-comment-get-delegate-revoked",
        "delegate-revoked",
        "MailComment/get",
        MAIL_COMMENT_GET_SUCCESS.request,
    )
};

const MAIL_COMMENT_GET_SUSPENDED: Case = Case {
    toggles: COMMENT_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_READ],
    between: SUSPEND_SEED0_BETWEEN,
    effects: SHARED_COMMENT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-comment-get-suspended",
        "suspended",
        "MailComment/get",
        MAIL_COMMENT_GET_SUCCESS.request,
    )
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_get_success() {
    run(&MAIL_COMMENT_GET_SUCCESS, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_get_not_found() {
    run(&MAIL_COMMENT_GET_NOT_FOUND, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_get_cross_tenant() {
    run(&MAIL_COMMENT_GET_CROSS_TENANT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_get_invalid_input() {
    run(&MAIL_COMMENT_GET_INVALID_INPUT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_get_delegate_allowed() {
    run(&MAIL_COMMENT_GET_DELEGATE_ALLOWED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_get_delegate_insufficient() {
    run(&MAIL_COMMENT_GET_DELEGATE_INSUFFICIENT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_get_delegate_revoked() {
    run(&MAIL_COMMENT_GET_DELEGATE_REVOKED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_get_suspended() {
    run(&MAIL_COMMENT_GET_SUSPENDED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_get_status_mutant() {
    status_mutant(&MAIL_COMMENT_GET_SUCCESS).await;
}

// ============================================================================
// MailComment/set
// ============================================================================

const MAIL_COMMENT_SET_SUCCESS: Case = Case {
    mutator: true,
    toggles: COMMENT_SET_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        GRANT_F_READ,
        SEED_COMMENT_MSG_SEED0,
    ],
    effects: SHARED_COMMENT_EFFECTS,
    notify: &["tag:{seed.0}"],
    ..Case::new(
        FAMILY,
        "mail-comment-set-success",
        "success",
        "MailComment/set",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailComment/set",{"accountId":"{seed.0}","threadId":"comment-thread-1","operationId":"55555555-5555-4555-8555-555555555555","expectedGeneration":"0","body":"Private note","mentionUserIds":["{f.user}"]},"c1"]]}"#,
    )
};

const MAIL_COMMENT_SET_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    toggles: COMMENT_SET_TOGGLES,
    seed: &[
        SEED_SHARED_MAILBOX_A,
        GRANT_A_FULL,
        GRANT_F_READ,
        SEED_COMMENT_MSG_SEED0,
    ],
    effects: SHARED_COMMENT_EFFECTS,
    notify: &["tag:{seed.0}"],
    ..Case::new(
        FAMILY,
        "mail-comment-set-repeat",
        "repeat",
        "MailComment/set",
        MAIL_COMMENT_SET_SUCCESS.request,
    )
};

const MAIL_COMMENT_SET_STATE_MISMATCH: Case = Case {
    mutator: true,
    toggles: COMMENT_SET_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_FULL, SEED_COMMENT_MSG_SEED0],
    effects: SHARED_COMMENT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-comment-set-state-mismatch",
        "state-mismatch",
        "MailComment/set",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailComment/set",{"accountId":"{seed.0}","threadId":"comment-thread-1","operationId":"55555555-5555-4555-8555-555555555555","expectedGeneration":"99","body":"Stale generation"},"c1"]]}"#,
    )
};

const MAIL_COMMENT_SET_NOT_FOUND: Case = Case {
    mutator: true,
    toggles: COMMENT_SET_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_FULL],
    effects: SHARED_COMMENT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-comment-set-not-found",
        "not-found",
        "MailComment/set",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailComment/set",{"accountId":"{seed.0}","threadId":"no-such-thread","operationId":"55555555-5555-4555-8555-555555555555","expectedGeneration":"0","body":"Missing thread"},"c1"]]}"#,
    )
};

const MAIL_COMMENT_SET_CROSS_TENANT: Case = Case {
    mutator: true,
    toggles: COMMENT_SET_TOGGLES,
    effects: FIXTURE_COMMENT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-comment-set-cross-tenant",
        "cross-tenant",
        "MailComment/set",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailComment/set",{"accountId":"{f.mailbox}","threadId":"comment-thread-1","operationId":"55555555-5555-4555-8555-555555555555","expectedGeneration":"0","body":"Foreign"},"c1"]]}"#,
    )
};

const MAIL_COMMENT_SET_INVALID_INPUT: Case = Case {
    mutator: true,
    toggles: COMMENT_SET_TOGGLES,
    effects: FIXTURE_COMMENT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-comment-set-invalid-input",
        "invalid-input",
        "MailComment/set",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailComment/set",{"accountId":"{a.mailbox}","threadId":"comment-thread-1","operationId":"bad","expectedGeneration":"0","body":"Invalid"},"c1"]]}"#,
    )
};

const MAIL_COMMENT_SET_DELEGATE_ALLOWED: Case = Case {
    mutator: true,
    toggles: COMMENT_SET_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_SEND, SEED_COMMENT_MSG_SEED0],
    effects: SHARED_COMMENT_EFFECTS,
    notify: &["tag:{seed.0}"],
    ..Case::new(
        FAMILY,
        "mail-comment-set-delegate-allowed",
        "delegate-allowed",
        "MailComment/set",
        r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["MailComment/set",{"accountId":"{seed.0}","threadId":"comment-thread-1","operationId":"55555555-5555-4555-8555-555555555555","expectedGeneration":"0","body":"Delegate note"},"c1"]]}"#,
    )
};

const MAIL_COMMENT_SET_DELEGATE_INSUFFICIENT: Case = Case {
    mutator: true,
    toggles: COMMENT_SET_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_READ, SEED_COMMENT_MSG_SEED0],
    effects: SHARED_COMMENT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-comment-set-delegate-insufficient",
        "delegate-insufficient",
        "MailComment/set",
        MAIL_COMMENT_SET_DELEGATE_ALLOWED.request,
    )
};

const MAIL_COMMENT_SET_DELEGATE_REVOKED: Case = Case {
    mutator: true,
    toggles: COMMENT_SET_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_FULL, SEED_COMMENT_MSG_SEED0],
    between: &[REVOKE_SEED0],
    effects: SHARED_COMMENT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-comment-set-delegate-revoked",
        "delegate-revoked",
        "MailComment/set",
        MAIL_COMMENT_SET_DELEGATE_ALLOWED.request,
    )
};

const MAIL_COMMENT_SET_SUSPENDED: Case = Case {
    mutator: true,
    toggles: COMMENT_SET_TOGGLES,
    seed: &[SEED_SHARED_MAILBOX_A, GRANT_A_FULL, SEED_COMMENT_MSG_SEED0],
    between: SUSPEND_SEED0_BETWEEN,
    effects: SHARED_COMMENT_EFFECTS,
    ..Case::new(
        FAMILY,
        "mail-comment-set-suspended",
        "suspended",
        "MailComment/set",
        MAIL_COMMENT_SET_DELEGATE_ALLOWED.request,
    )
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_set_success() {
    run(&MAIL_COMMENT_SET_SUCCESS, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_set_repeat() {
    run(&MAIL_COMMENT_SET_REPEAT, Mutation::None).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_set_state_mismatch() {
    run(&MAIL_COMMENT_SET_STATE_MISMATCH, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_set_not_found() {
    run(&MAIL_COMMENT_SET_NOT_FOUND, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_set_cross_tenant() {
    run(&MAIL_COMMENT_SET_CROSS_TENANT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_set_invalid_input() {
    run(&MAIL_COMMENT_SET_INVALID_INPUT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_set_delegate_allowed() {
    run(&MAIL_COMMENT_SET_DELEGATE_ALLOWED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_set_delegate_insufficient() {
    run(&MAIL_COMMENT_SET_DELEGATE_INSUFFICIENT, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_set_delegate_revoked() {
    run(&MAIL_COMMENT_SET_DELEGATE_REVOKED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_set_suspended() {
    run(&MAIL_COMMENT_SET_SUSPENDED, Mutation::None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_comment_set_status_mutant() {
    status_mutant(&MAIL_COMMENT_SET_SUCCESS).await;
}
