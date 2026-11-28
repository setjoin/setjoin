//! Frozen-Go oracle replays and mutants for #373 (`Task/*`, `TaskComment/*`,
//! `TaskList/*`, `TaskListMember/set`, `TaskAssigned/*`).
mod common;
mod jmap_family_oracle;

use jmap_family_oracle::{run, Case, Mutation};
use serde_json::Value;
use setjoin_conformance::harness::BoxError;

const CAP_TASKS: &str = "urn:ietf:params:jmap:tasks";

const EFFECT_TASKS: (&str, &str) = (
    "tasks",
    "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.id), '[]'::jsonb)::text \
     FROM tasks t WHERE t.mailbox_id IN ({a.mailbox},{f.mailbox})",
);
const EFFECT_ACTIVITY: (&str, &str) = (
    "task_activity",
    "SELECT COALESCE(jsonb_agg(to_jsonb(a) - 'id' ORDER BY a.task_id, a.kind, a.created_at, a.id), '[]'::jsonb)::text \
     FROM task_activity a WHERE a.mailbox_id IN ({a.mailbox},{f.mailbox})",
);
const EFFECT_ENTITY_STATE: (&str, &str) = (
    "entity_state",
    "SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY s.mailbox_id, s.datatype), '[]'::jsonb)::text \
     FROM jmap_entity_state s WHERE s.mailbox_id IN ({a.mailbox},{f.mailbox})",
);
const EFFECT_JOURNAL: (&str, &str) = (
    "journal",
    "SELECT COALESCE(jsonb_agg(to_jsonb(j) - 'imap_uid' ORDER BY j.datatype, j.state_seq, j.entity_id), '[]'::jsonb)::text \
     FROM jmap_changes_journal j WHERE j.mailbox_id IN ({a.mailbox},{f.mailbox})",
);
const EFFECT_LISTS: (&str, &str) = (
    "task_lists",
    "SELECT COALESCE(jsonb_agg(to_jsonb(l) ORDER BY l.id), '[]'::jsonb)::text \
     FROM task_lists l WHERE l.owner_user_id IN ({a.user},{f.user})",
);
const EFFECT_MEMBERS: (&str, &str) = (
    "task_list_members",
    "SELECT COALESCE(jsonb_agg(to_jsonb(m) ORDER BY m.list_id, m.user_id), '[]'::jsonb)::text \
     FROM task_list_members m WHERE m.user_id IN ({a.user},{f.user}) \
     OR m.list_id IN (SELECT id FROM task_lists WHERE owner_user_id IN ({a.user},{f.user}))",
);

const SEED_OWN_TASK: &str =
    "INSERT INTO tasks (mailbox_id, title) VALUES ({a.mailbox}, 'Own task') RETURNING id";
const SEED_FOREIGN_TASK: &str =
    "INSERT INTO tasks (mailbox_id, title) VALUES ({f.mailbox}, 'Foreign task') RETURNING id";
const SEED_DELEGATE_FULL: &str =
    "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
     VALUES ({f.mailbox}, {a.user}, 'full_access', {f.user})";
const SEED_DENY_TASKS_APP: &str =
    "INSERT INTO user_app_entitlements (user_id, app, enabled) VALUES ({a.user}, 'tasks', false)";

const SHARED_ON: &[(&str, bool)] = &[("feature.shared_task_lists", true)];
const SHARED_OFF: &[(&str, bool)] = &[("feature.shared_task_lists", false)];

async fn run_status_mutant(case: &Case) -> Result<(), BoxError> {
    if setjoin_conformance::harness::Db::for_case(case.name).is_none() {
        return Ok(());
    }
    let diff = run(case, Mutation::Status)
        .await
        .expect_err("changed status mutant must fail the replay")
        .to_string();
    assert!(diff.contains("/response/status"), "{diff}");
    println!(
        "MUTANT-REJECTED: POST /jmap {} :: changed-status",
        case.method
    );
    Ok(())
}

fn created_id_var(prior: &[String]) -> Result<Vec<(String, String)>, BoxError> {
    let doc: Value = serde_json::from_str(prior.first().ok_or("missing setup response")?)?;
    let id = doc
        .pointer("/methodResponses/0/1/created/c1/id")
        .and_then(Value::as_str)
        .ok_or("missing created c1 id")?;
    Ok(vec![("created_id".to_owned(), id.to_owned())])
}

fn member_email_from_lists(prior: &[String]) -> Result<Vec<(String, String)>, BoxError> {
    let doc: Value = serde_json::from_str(prior.first().ok_or("missing TaskList/get setup")?)?;
    let lists = doc
        .pointer("/methodResponses/0/1/lists")
        .and_then(Value::as_array)
        .ok_or("missing lists array")?;
    for list in lists {
        if list.get("role").and_then(Value::as_str) == Some("member") {
            if let Some(members) = list.get("members").and_then(Value::as_array) {
                for m in members {
                    if m.get("role").and_then(Value::as_str) == Some("owner") {
                        let email = m
                            .get("email")
                            .and_then(Value::as_str)
                            .ok_or("owner email missing")?;
                        return Ok(vec![("member_email".to_owned(), email.to_owned())]);
                    }
                }
            }
        }
    }
    Err("helper member list not found in TaskList/get".into())
}

// ---------------------------------------------------------------------------
// Task/get
// ---------------------------------------------------------------------------

const TASK_GET_SUCCESS: Case = Case {
    seed: &[SEED_OWN_TASK, SEED_FOREIGN_TASK],
    absent: &["{seed.1}", "Foreign task"],
    effects: &[EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-get-success",
        "success",
        "Task/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/get",{"accountId":"{a.mailbox}","ids":null},"c1"]]}"#,
    )
};
const TASK_GET_NO_TENANT_MUTANT: Case = Case {
    absent: &[],
    ..TASK_GET_SUCCESS
};
const TASK_GET_MIXED_IDS: Case = Case {
    seed: &[SEED_OWN_TASK, SEED_FOREIGN_TASK],
    absent: &["Foreign task"],
    effects: &[EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-get-mixed-ids",
        "success",
        "Task/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/get",{"accountId":"{a.mailbox}","ids":["{seed.0}","{seed.1}","bad-id"]},"c1"]]}"#,
    )
};
const TASK_GET_CROSS_TENANT: Case = Case {
    seed: &[SEED_FOREIGN_TASK],
    absent: &["{seed.0}", "Foreign task"],
    effects: &[EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-get-cross-tenant",
        "cross-tenant",
        "Task/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/get",{"accountId":"{f.mailbox}","ids":null},"c1"]]}"#,
    )
};
const TASK_GET_INVALID_INPUT: Case = Case {
    effects: &[EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-get-invalid-input",
        "invalid-input",
        "Task/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/get",{"accountId":"{a.mailbox}","properties":123},"c1"]]}"#,
    )
};
const TASK_GET_DELEGATE_PERSONAL: Case = Case {
    seed: &[SEED_FOREIGN_TASK, SEED_DELEGATE_FULL],
    absent: &["{seed.0}", "Foreign task"],
    effects: &[EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-get-delegate-personal",
        "delegate-personal",
        "Task/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/get",{"accountId":"{f.mailbox}","ids":null},"c1"]]}"#,
    )
};
const TASK_GET_ENTITLEMENT_DENIED: Case = Case {
    seed: &[SEED_OWN_TASK, SEED_DENY_TASKS_APP],
    absent: &["{seed.0}", "Own task"],
    effects: &[EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-get-entitlement-denied",
        "entitlement-denied",
        "Task/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/get",{"accountId":"{a.mailbox}","ids":null},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// Task/query
// ---------------------------------------------------------------------------

const TASK_QUERY_SUCCESS: Case = Case {
    seed: &[
        "INSERT INTO tasks (mailbox_id, title, status) VALUES ({a.mailbox}, 'Open task', 'needs-action') RETURNING id",
        "INSERT INTO tasks (mailbox_id, title, status) VALUES ({a.mailbox}, 'Done task', 'completed') RETURNING id",
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({a.user}, 'Shared') RETURNING id",
        "INSERT INTO tasks (mailbox_id, list_id, title, status) VALUES ({a.mailbox}, {seed.2}, 'List task', 'needs-action') RETURNING id",
        SEED_FOREIGN_TASK,
    ],
    absent: &["{seed.1}", "{seed.2}", "{seed.3}", "{seed.4}"],
    effects: &[EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-query-success",
        "success",
        "Task/query",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/query",{"accountId":"{a.mailbox}","filter":{"status":"needs-action"},"position":0,"limit":999},"c1"]]}"#,
    )
};
const TASK_QUERY_CROSS_TENANT: Case = Case {
    seed: &[SEED_FOREIGN_TASK],
    absent: &["{seed.0}"],
    effects: &[EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-query-cross-tenant",
        "cross-tenant",
        "Task/query",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/query",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};
const TASK_QUERY_INVALID_INPUT: Case = Case {
    effects: &[EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-query-invalid-input",
        "invalid-input",
        "Task/query",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/query",{"accountId":"{a.mailbox}","limit":"bad"},"c1"]]}"#,
    )
};
const TASK_QUERY_DELEGATE_PERSONAL: Case = Case {
    seed: &[SEED_FOREIGN_TASK, SEED_DELEGATE_FULL],
    absent: &["{seed.0}"],
    effects: &[EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-query-delegate-personal",
        "delegate-personal",
        "Task/query",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/query",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};
const TASK_QUERY_ENTITLEMENT_DENIED: Case = Case {
    seed: &[SEED_OWN_TASK, SEED_DENY_TASKS_APP],
    absent: &["{seed.0}"],
    effects: &[EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-query-entitlement-denied",
        "entitlement-denied",
        "Task/query",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/query",{"accountId":"{a.mailbox}"},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// Task/changes
// ---------------------------------------------------------------------------

const TASK_CHANGES_SUCCESS: Case = Case {
    seed: &[SEED_FOREIGN_TASK],
    setup: &[
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/set",{"accountId":"{a.mailbox}","create":{"c1":{"title":"Delta task"}}},"s0"]]}"#,
    ],
    vars: created_id_var,
    absent: &["{seed.0}"],
    effects: &[EFFECT_TASKS, EFFECT_ENTITY_STATE, EFFECT_JOURNAL],
    ..Case::new(
        "tasks",
        "task-changes-success",
        "success",
        "Task/changes",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/changes",{"accountId":"{a.mailbox}","sinceState":"0"},"c1"]]}"#,
    )
};
const TASK_CHANGES_CROSS_TENANT: Case = Case {
    seed: &[SEED_FOREIGN_TASK],
    absent: &["{seed.0}"],
    effects: &[EFFECT_TASKS, EFFECT_ENTITY_STATE, EFFECT_JOURNAL],
    ..Case::new(
        "tasks",
        "task-changes-cross-tenant",
        "cross-tenant",
        "Task/changes",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/changes",{"accountId":"{f.mailbox}","sinceState":"0"},"c1"]]}"#,
    )
};
const TASK_CHANGES_INVALID_INPUT: Case = Case {
    effects: &[EFFECT_TASKS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "tasks",
        "task-changes-invalid-input",
        "invalid-input",
        "Task/changes",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/changes",{"accountId":"{a.mailbox}","sinceState":123},"c1"]]}"#,
    )
};
const TASK_CHANGES_STATE_MISMATCH: Case = Case {
    effects: &[EFFECT_TASKS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "tasks",
        "task-changes-state-mismatch",
        "state-mismatch",
        "Task/changes",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/changes",{"accountId":"{a.mailbox}","sinceState":"999999"},"c1"]]}"#,
    )
};
const TASK_CHANGES_DELEGATE_PERSONAL: Case = Case {
    seed: &[SEED_FOREIGN_TASK, SEED_DELEGATE_FULL],
    absent: &["{seed.0}"],
    effects: &[EFFECT_TASKS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "tasks",
        "task-changes-delegate-personal",
        "delegate-personal",
        "Task/changes",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/changes",{"accountId":"{f.mailbox}","sinceState":"0"},"c1"]]}"#,
    )
};
const TASK_CHANGES_ENTITLEMENT_DENIED: Case = Case {
    seed: &[SEED_OWN_TASK, SEED_DENY_TASKS_APP],
    absent: &["{seed.0}"],
    effects: &[EFFECT_TASKS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "tasks",
        "task-changes-entitlement-denied",
        "entitlement-denied",
        "Task/changes",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/changes",{"accountId":"{a.mailbox}","sinceState":"0"},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// Task/set
// ---------------------------------------------------------------------------

const TASK_SET_SUCCESS: Case = Case {
    mutator: true,
    notify: &["task:{a.mailbox}"],
    scrub: &[("/methodResponses/0/1/created/c1/id", "created")],
    effects: &[EFFECT_TASKS, EFFECT_ENTITY_STATE, EFFECT_JOURNAL],
    ..Case::new(
        "tasks",
        "task-set-success",
        "success",
        "Task/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/set",{"accountId":"{a.mailbox}","create":{"c1":{"title":"Buy milk"}}},"c1"]]}"#,
    )
};
const TASK_SET_REPEAT: Case = Case {
    name: "task-set-repeat",
    kind: "repeat",
    repeat: true,
    ..TASK_SET_SUCCESS
};
const TASK_SET_UPDATE_DESTROY: Case = Case {
    mutator: true,
    seed: &[
        SEED_OWN_TASK,
        "INSERT INTO tasks (mailbox_id, title) VALUES ({a.mailbox}, 'Delete me') RETURNING id",
        SEED_FOREIGN_TASK,
    ],
    absent: &["{seed.2}"],
    notify: &["task:{a.mailbox}"],
    effects: &[
        EFFECT_TASKS,
        EFFECT_ACTIVITY,
        EFFECT_ENTITY_STATE,
        EFFECT_JOURNAL,
    ],
    ..Case::new(
        "tasks",
        "task-set-update-destroy",
        "success",
        "Task/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/set",{"accountId":"{a.mailbox}","update":{"{seed.0}":{"status":"completed"}},"destroy":["{seed.1}","bad-id"]},"c1"]]}"#,
    )
};
const TASK_SET_CROSS_TENANT: Case = Case {
    mutator: true,
    seed: &[SEED_FOREIGN_TASK],
    absent: &["{seed.0}"],
    effects: &[EFFECT_TASKS, EFFECT_ENTITY_STATE, EFFECT_JOURNAL],
    ..Case::new(
        "tasks",
        "task-set-cross-tenant",
        "cross-tenant",
        "Task/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/set",{"accountId":"{f.mailbox}","create":{"c1":{"title":"Nope"}}},"c1"]]}"#,
    )
};
const TASK_SET_INVALID_INPUT: Case = Case {
    mutator: true,
    effects: &[EFFECT_TASKS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "tasks",
        "task-set-invalid-input",
        "invalid-input",
        "Task/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/set",{"accountId":"{a.mailbox}","destroy":[123]},"c1"]]}"#,
    )
};
const TASK_SET_DELEGATE_PERSONAL: Case = Case {
    mutator: true,
    seed: &[SEED_FOREIGN_TASK, SEED_DELEGATE_FULL],
    absent: &["{seed.0}"],
    effects: &[EFFECT_TASKS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "tasks",
        "task-set-delegate-personal",
        "delegate-personal",
        "Task/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/set",{"accountId":"{f.mailbox}","create":{"c1":{"title":"Nope"}}},"c1"]]}"#,
    )
};
const TASK_SET_ENTITLEMENT_DENIED: Case = Case {
    mutator: true,
    seed: &[SEED_OWN_TASK, SEED_DENY_TASKS_APP],
    absent: &["{seed.0}"],
    effects: &[EFFECT_TASKS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "tasks",
        "task-set-entitlement-denied",
        "entitlement-denied",
        "Task/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["Task/set",{"accountId":"{a.mailbox}","create":{"c1":{"title":"Nope"}}},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// TaskComment/get
// ---------------------------------------------------------------------------

const TASK_COMMENT_GET_SUCCESS: Case = Case {
    seed: &[
        SEED_OWN_TASK,
        "INSERT INTO task_activity (task_id, mailbox_id, author_user_id, kind, body) \
         VALUES ({seed.0}, {a.mailbox}, {a.user}, 'comment', 'Own comment') RETURNING id",
        SEED_FOREIGN_TASK,
        "INSERT INTO task_activity (task_id, mailbox_id, author_user_id, kind, body) \
         VALUES ({seed.2}, {f.mailbox}, {f.user}, 'comment', 'Foreign comment') RETURNING id",
    ],
    absent: &["{seed.2}", "{seed.3}", "Foreign comment"],
    scrub: &[("/methodResponses/0/1/list/0/authorEmail", "a.email")],
    effects: &[EFFECT_TASKS, EFFECT_ACTIVITY],
    ..Case::new(
        "tasks",
        "task-comment-get-success",
        "success",
        "TaskComment/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskComment/get",{"accountId":"{a.mailbox}","taskId":"{seed.0}"},"c1"]]}"#,
    )
};
const TASK_COMMENT_GET_CROSS_TENANT: Case = Case {
    seed: &[SEED_FOREIGN_TASK],
    absent: &["{seed.0}"],
    effects: &[EFFECT_TASKS, EFFECT_ACTIVITY],
    ..Case::new(
        "tasks",
        "task-comment-get-cross-tenant",
        "cross-tenant",
        "TaskComment/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskComment/get",{"accountId":"{f.mailbox}","taskId":"{seed.0}"},"c1"]]}"#,
    )
};
const TASK_COMMENT_GET_INVALID_INPUT: Case = Case {
    effects: &[EFFECT_TASKS, EFFECT_ACTIVITY],
    ..Case::new(
        "tasks",
        "task-comment-get-invalid-input",
        "invalid-input",
        "TaskComment/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskComment/get",{"accountId":"{a.mailbox}","taskId":"bad-id"},"c1"]]}"#,
    )
};
const TASK_COMMENT_GET_DELEGATE_PERSONAL: Case = Case {
    seed: &[SEED_FOREIGN_TASK, SEED_DELEGATE_FULL],
    absent: &["{seed.0}"],
    effects: &[EFFECT_TASKS, EFFECT_ACTIVITY],
    ..Case::new(
        "tasks",
        "task-comment-get-delegate-personal",
        "delegate-personal",
        "TaskComment/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskComment/get",{"accountId":"{f.mailbox}","taskId":"{seed.0}"},"c1"]]}"#,
    )
};
const TASK_COMMENT_GET_ENTITLEMENT_DENIED: Case = Case {
    seed: &[SEED_OWN_TASK, SEED_DENY_TASKS_APP],
    absent: &["{seed.0}"],
    effects: &[EFFECT_TASKS, EFFECT_ACTIVITY],
    ..Case::new(
        "tasks",
        "task-comment-get-entitlement-denied",
        "entitlement-denied",
        "TaskComment/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskComment/get",{"accountId":"{a.mailbox}","taskId":"{seed.0}"},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// TaskComment/set
// ---------------------------------------------------------------------------

const TASK_COMMENT_SET_SUCCESS: Case = Case {
    mutator: true,
    seed: &[SEED_OWN_TASK],
    notify: &["task:{a.mailbox}"],
    scrub: &[("/methodResponses/0/1/id", "comment")],
    effects: &[EFFECT_TASKS, EFFECT_ACTIVITY],
    ..Case::new(
        "tasks",
        "task-comment-set-success",
        "success",
        "TaskComment/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskComment/set",{"accountId":"{a.mailbox}","taskId":"{seed.0}","body":"Hello team","mentionedEmails":[]},"c1"]]}"#,
    )
};
const TASK_COMMENT_SET_REPEAT: Case = Case {
    name: "task-comment-set-repeat",
    kind: "repeat",
    repeat: true,
    ..TASK_COMMENT_SET_SUCCESS
};
const TASK_COMMENT_SET_CROSS_TENANT: Case = Case {
    mutator: true,
    seed: &[SEED_FOREIGN_TASK],
    absent: &["{seed.0}"],
    effects: &[EFFECT_TASKS, EFFECT_ACTIVITY],
    ..Case::new(
        "tasks",
        "task-comment-set-cross-tenant",
        "cross-tenant",
        "TaskComment/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskComment/set",{"accountId":"{f.mailbox}","taskId":"{seed.0}","body":"Nope"},"c1"]]}"#,
    )
};
const TASK_COMMENT_SET_INVALID_INPUT: Case = Case {
    mutator: true,
    seed: &[SEED_OWN_TASK],
    effects: &[EFFECT_TASKS, EFFECT_ACTIVITY],
    ..Case::new(
        "tasks",
        "task-comment-set-invalid-input",
        "invalid-input",
        "TaskComment/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskComment/set",{"accountId":"{a.mailbox}","taskId":"{seed.0}","body":"   "},"c1"]]}"#,
    )
};
const TASK_COMMENT_SET_DELEGATE_PERSONAL: Case = Case {
    mutator: true,
    seed: &[SEED_FOREIGN_TASK, SEED_DELEGATE_FULL],
    absent: &["{seed.0}"],
    effects: &[EFFECT_TASKS, EFFECT_ACTIVITY],
    ..Case::new(
        "tasks",
        "task-comment-set-delegate-personal",
        "delegate-personal",
        "TaskComment/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskComment/set",{"accountId":"{f.mailbox}","taskId":"{seed.0}","body":"Nope"},"c1"]]}"#,
    )
};
const TASK_COMMENT_SET_ENTITLEMENT_DENIED: Case = Case {
    mutator: true,
    seed: &[SEED_OWN_TASK, SEED_DENY_TASKS_APP],
    absent: &["{seed.0}"],
    effects: &[EFFECT_TASKS, EFFECT_ACTIVITY],
    ..Case::new(
        "tasks",
        "task-comment-set-entitlement-denied",
        "entitlement-denied",
        "TaskComment/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskComment/set",{"accountId":"{a.mailbox}","taskId":"{seed.0}","body":"Nope"},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// TaskList/get
// ---------------------------------------------------------------------------

const TASK_LIST_GET_SUCCESS: Case = Case {
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO task_lists (owner_user_id, name, color) VALUES ({a.user}, 'Own List', '#2563eb') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.0}, {a.user}, 'owner', {a.user})",
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({f.user}, 'Foreign List') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.1}, {f.user}, 'owner', {f.user})",
    ],
    absent: &["{seed.1}", "Foreign List"],
    scrub: &[("/methodResponses/0/1/lists/0/members/0/email", "a.email")],
    effects: &[EFFECT_LISTS, EFFECT_MEMBERS],
    ..Case::new(
        "tasks",
        "task-list-get-success",
        "success",
        "TaskList/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/get",{},"c1"]]}"#,
    )
};
const TASK_LIST_GET_FOREIGN_OBJECT: Case = Case {
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({f.user}, 'Foreign Secret List') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.0}, {f.user}, 'owner', {f.user})",
    ],
    absent: &["{seed.0}", "Foreign Secret List"],
    effects: &[EFFECT_LISTS, EFFECT_MEMBERS],
    ..Case::new(
        "tasks",
        "task-list-get-foreign-object",
        "foreign-object",
        "TaskList/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/get",{},"c1"]]}"#,
    )
};
const TASK_LIST_GET_INVALID_INPUT: Case = Case {
    toggles: SHARED_ON,
    effects: &[EFFECT_LISTS, EFFECT_MEMBERS],
    ..Case::new(
        "tasks",
        "task-list-get-invalid-input",
        "invalid-input",
        "TaskList/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/get",[],"c1"]]}"#,
    )
};
const TASK_LIST_GET_DISABLED: Case = Case {
    toggles: SHARED_OFF,
    effects: &[EFFECT_LISTS, EFFECT_MEMBERS],
    ..Case::new(
        "tasks",
        "task-list-get-disabled",
        "invalid-input",
        "TaskList/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/get",{},"c1"]]}"#,
    )
};
const TASK_LIST_GET_ENTITLEMENT_DENIED: Case = Case {
    toggles: SHARED_ON,
    seed: &[SEED_DENY_TASKS_APP],
    effects: &[EFFECT_LISTS, EFFECT_MEMBERS],
    ..Case::new(
        "tasks",
        "task-list-get-entitlement-denied",
        "entitlement-denied",
        "TaskList/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/get",{},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// TaskList/set
// ---------------------------------------------------------------------------

const TASK_LIST_SET_SUCCESS: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    scrub: &[("/methodResponses/0/1/created/c1/id", "list")],
    effects: &[EFFECT_LISTS, EFFECT_MEMBERS],
    ..Case::new(
        "tasks",
        "task-list-set-success",
        "success",
        "TaskList/set",
        r##"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/set",{"create":{"c1":{"name":"Team Board","color":"#2563eb"}}},"c1"]]}"##,
    )
};
const TASK_LIST_SET_REPEAT: Case = Case {
    name: "task-list-set-repeat",
    kind: "repeat",
    repeat: true,
    ..TASK_LIST_SET_SUCCESS
};
const TASK_LIST_SET_UPDATE_DESTROY: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO task_lists (owner_user_id, name, color) VALUES ({a.user}, 'Rename Me', '#111111') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.0}, {a.user}, 'owner', {a.user})",
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({a.user}, 'Delete Me') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.1}, {a.user}, 'owner', {a.user})",
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({f.user}, 'Foreign Untouched') RETURNING id",
    ],
    absent: &["{seed.2}", "Foreign Untouched"],
    notify: &["task:{a.mailbox}"],
    effects: &[EFFECT_LISTS, EFFECT_MEMBERS],
    ..Case::new(
        "tasks",
        "task-list-set-update-destroy",
        "success",
        "TaskList/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/set",{"update":{"{seed.0}":{"name":"Renamed","color":null},"bad-u":{"name":"x"}},"destroy":["{seed.1}","bad-d"]},"c1"]]}"#,
    )
};
const TASK_LIST_SET_FOREIGN_OBJECT: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({f.user}, 'Foreign List') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.0}, {f.user}, 'owner', {f.user})",
    ],
    absent: &["Hijacked", "Foreign List"],
    effects: &[EFFECT_LISTS, EFFECT_MEMBERS],
    ..Case::new(
        "tasks",
        "task-list-set-foreign-object",
        "foreign-object",
        "TaskList/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/set",{"update":{"{seed.0}":{"name":"Hijacked"}},"destroy":["{seed.0}"]},"c1"]]}"#,
    )
};
const TASK_LIST_SET_INVALID_INPUT: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    effects: &[EFFECT_LISTS, EFFECT_MEMBERS],
    ..Case::new(
        "tasks",
        "task-list-set-invalid-input",
        "invalid-input",
        "TaskList/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/set",{"create":{"c1":{"name":"   "}}},"c1"]]}"#,
    )
};
const TASK_LIST_SET_ENTITLEMENT_DENIED: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    seed: &[SEED_DENY_TASKS_APP],
    effects: &[EFFECT_LISTS, EFFECT_MEMBERS],
    ..Case::new(
        "tasks",
        "task-list-set-entitlement-denied",
        "entitlement-denied",
        "TaskList/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/set",{"create":{"c1":{"name":"Nope"}}},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// TaskListMember/set (includes task_lists_roster_scope_test.go cases)
// ---------------------------------------------------------------------------

const TASK_LIST_MEMBER_SET_SUCCESS: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({a.user}, 'Roster List') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.0}, {a.user}, 'owner', {a.user})",
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({f.user}, 'Helper Lookup') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.1}, {f.user}, 'owner', {f.user})",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.1}, {a.user}, 'member', {f.user})",
    ],
    setup: &[
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/get",{},"s0"]]}"#,
    ],
    vars: member_email_from_lists,
    scrub: &[("/methodResponses/0/1/members/1/email", "a.email")],
    notify: &["task:{a.mailbox}", "task:{f.mailbox}"],
    effects: &[EFFECT_LISTS, EFFECT_MEMBERS],
    ..Case::new(
        "tasks",
        "task-list-member-set-success",
        "success",
        "TaskListMember/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskListMember/set",{"listId":"{seed.0}","add":["{var.member_email}"]},"c1"]]}"#,
    )
};
const TASK_LIST_MEMBER_SET_REPEAT: Case = Case {
    name: "task-list-member-set-repeat",
    kind: "repeat",
    repeat: true,
    ..TASK_LIST_MEMBER_SET_SUCCESS
};
const TASK_LIST_MEMBER_SET_SELF_LEAVE: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({f.user}, 'Leave List') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.0}, {f.user}, 'owner', {f.user})",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.0}, {a.user}, 'member', {f.user})",
    ],
    scrub: &[
        ("/methodResponses/0/1/members/0/email", "a.email"),
        ("/methodResponses/0/1/members/1/email", "f.email"),
    ],
    notify: &["task:{a.mailbox}", "task:{f.mailbox}"],
    effects: &[EFFECT_LISTS, EFFECT_MEMBERS],
    ..Case::new(
        "tasks",
        "task-list-member-set-self-leave",
        "success",
        "TaskListMember/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskListMember/set",{"listId":"{seed.0}","remove":["{a.user}"]},"c1"]]}"#,
    )
};
const TASK_LIST_MEMBER_SET_FOREIGN_OBJECT: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({f.user}, 'Roster Scope') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.0}, {f.user}, 'owner', {f.user})",
    ],
    absent: &["{seed.0}", "Roster Scope"],
    effects: &[EFFECT_LISTS, EFFECT_MEMBERS],
    ..Case::new(
        "tasks",
        "task-list-member-set-foreign-object",
        "foreign-object",
        "TaskListMember/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskListMember/set",{"listId":"{seed.0}","add":[],"remove":[]},"c1"]]}"#,
    )
};
const TASK_LIST_MEMBER_SET_NONEXISTENT_LIST: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({f.user}, 'Roster Scope') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.0}, {f.user}, 'owner', {f.user})",
    ],
    absent: &["{seed.0}", "Roster Scope"],
    effects: &[EFFECT_LISTS, EFFECT_MEMBERS],
    ..Case::new(
        "tasks",
        "task-list-member-set-nonexistent-list",
        "foreign-object",
        "TaskListMember/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskListMember/set",{"listId":"999999999","add":[],"remove":[]},"c1"]]}"#,
    )
};
const TASK_LIST_MEMBER_SET_INVALID_INPUT: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    effects: &[EFFECT_LISTS, EFFECT_MEMBERS],
    ..Case::new(
        "tasks",
        "task-list-member-set-invalid-input",
        "invalid-input",
        "TaskListMember/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskListMember/set",{"listId":"bad-id","add":[],"remove":[]},"c1"]]}"#,
    )
};
const TASK_LIST_MEMBER_SET_ENTITLEMENT_DENIED: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({a.user}, 'Roster List') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.0}, {a.user}, 'owner', {a.user})",
        SEED_DENY_TASKS_APP,
    ],
    effects: &[EFFECT_LISTS, EFFECT_MEMBERS],
    ..Case::new(
        "tasks",
        "task-list-member-set-entitlement-denied",
        "entitlement-denied",
        "TaskListMember/set",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskListMember/set",{"listId":"{seed.0}","add":[],"remove":[]},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// TaskList/tasks
// ---------------------------------------------------------------------------

const TASK_LIST_TASKS_SUCCESS: Case = Case {
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({a.user}, 'Own List') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.0}, {a.user}, 'owner', {a.user})",
        "INSERT INTO tasks (mailbox_id, list_id, title) VALUES ({a.mailbox}, {seed.0}, 'Own Shared Task') RETURNING id",
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({f.user}, 'Foreign List') RETURNING id",
        "INSERT INTO tasks (mailbox_id, list_id, title) VALUES ({f.mailbox}, {seed.2}, 'Foreign Shared Task') RETURNING id",
    ],
    absent: &["{seed.2}", "{seed.3}", "Foreign Shared Task"],
    scrub: &[("/methodResponses/0/1/list/0/creatorEmail", "a.email")],
    effects: &[EFFECT_LISTS, EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-list-tasks-success",
        "success",
        "TaskList/tasks",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/tasks",{"listId":"{seed.0}"},"c1"]]}"#,
    )
};
const TASK_LIST_TASKS_FOREIGN_OBJECT: Case = Case {
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({f.user}, 'Foreign List') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.0}, {f.user}, 'owner', {f.user})",
        "INSERT INTO tasks (mailbox_id, list_id, title) VALUES ({f.mailbox}, {seed.0}, 'Foreign Shared Task') RETURNING id",
    ],
    absent: &["{seed.1}", "Foreign Shared Task"],
    effects: &[EFFECT_LISTS, EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-list-tasks-foreign-object",
        "foreign-object",
        "TaskList/tasks",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/tasks",{"listId":"{seed.0}"},"c1"]]}"#,
    )
};
const TASK_LIST_TASKS_INVALID_INPUT: Case = Case {
    toggles: SHARED_ON,
    effects: &[EFFECT_LISTS, EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-list-tasks-invalid-input",
        "invalid-input",
        "TaskList/tasks",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/tasks",{"listId":"bad-id"},"c1"]]}"#,
    )
};
const TASK_LIST_TASKS_ENTITLEMENT_DENIED: Case = Case {
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({a.user}, 'Own List') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.0}, {a.user}, 'owner', {a.user})",
        SEED_DENY_TASKS_APP,
    ],
    effects: &[EFFECT_LISTS, EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-list-tasks-entitlement-denied",
        "entitlement-denied",
        "TaskList/tasks",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/tasks",{"listId":"{seed.0}"},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// TaskList/taskSet
// ---------------------------------------------------------------------------

const TASK_LIST_TASK_SET_SUCCESS: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({a.user}, 'Team Tasks') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.0}, {a.user}, 'owner', {a.user})",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.0}, {f.user}, 'member', {a.user})",
    ],
    scrub: &[("/methodResponses/0/1/created/c1/id", "created")],
    notify: &["task:{a.mailbox}", "task:{f.mailbox}"],
    effects: &[EFFECT_LISTS, EFFECT_TASKS, EFFECT_JOURNAL],
    ..Case::new(
        "tasks",
        "task-list-task-set-success",
        "success",
        "TaskList/taskSet",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/taskSet",{"listId":"{seed.0}","create":{"c1":{"title":"Shared task"}}},"c1"]]}"#,
    )
};
const TASK_LIST_TASK_SET_REPEAT: Case = Case {
    name: "task-list-task-set-repeat",
    kind: "repeat",
    repeat: true,
    ..TASK_LIST_TASK_SET_SUCCESS
};
const TASK_LIST_TASK_SET_UPDATE_DESTROY: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({f.user}, 'Team Tasks') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.0}, {f.user}, 'owner', {f.user})",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.0}, {a.user}, 'member', {f.user})",
        "INSERT INTO tasks (mailbox_id, list_id, title) VALUES ({f.mailbox}, {seed.0}, 'Member Edits') RETURNING id",
        "INSERT INTO tasks (mailbox_id, list_id, title) VALUES ({f.mailbox}, {seed.0}, 'Member Deletes') RETURNING id",
    ],
    notify: &["task:{a.mailbox}", "task:{f.mailbox}"],
    effects: &[EFFECT_LISTS, EFFECT_TASKS, EFFECT_ACTIVITY, EFFECT_JOURNAL],
    ..Case::new(
        "tasks",
        "task-list-task-set-update-destroy",
        "success",
        "TaskList/taskSet",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/taskSet",{"listId":"{seed.0}","update":{"{seed.1}":{"status":"completed"}},"destroy":["{seed.2}","bad-id"]},"c1"]]}"#,
    )
};
const TASK_LIST_TASK_SET_FOREIGN_OBJECT: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({f.user}, 'Foreign List') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.0}, {f.user}, 'owner', {f.user})",
    ],
    absent: &["Sneaky"],
    effects: &[EFFECT_LISTS, EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-list-task-set-foreign-object",
        "foreign-object",
        "TaskList/taskSet",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/taskSet",{"listId":"{seed.0}","create":{"c1":{"title":"Sneaky"}}},"c1"]]}"#,
    )
};
const TASK_LIST_TASK_SET_INVALID_INPUT: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    effects: &[EFFECT_LISTS, EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-list-task-set-invalid-input",
        "invalid-input",
        "TaskList/taskSet",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/taskSet",{"listId":"bad-id","create":{"c1":{"title":"x"}}},"c1"]]}"#,
    )
};
const TASK_LIST_TASK_SET_ENTITLEMENT_DENIED: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({a.user}, 'Team Tasks') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.0}, {a.user}, 'owner', {a.user})",
        SEED_DENY_TASKS_APP,
    ],
    effects: &[EFFECT_LISTS, EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-list-task-set-entitlement-denied",
        "entitlement-denied",
        "TaskList/taskSet",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskList/taskSet",{"listId":"{seed.0}","create":{"c1":{"title":"Nope"}}},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// TaskAssigned/get
// ---------------------------------------------------------------------------

const TASK_ASSIGNED_GET_SUCCESS: Case = Case {
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO tasks (mailbox_id, title, assignee_user_id) VALUES ({f.mailbox}, 'Assigned To Me', {a.user}) RETURNING id",
        "INSERT INTO tasks (mailbox_id, title, assignee_user_id) VALUES ({f.mailbox}, 'Foreign Assigned Task', {f.user}) RETURNING id",
    ],
    absent: &["{seed.1}", "Foreign Assigned Task"],
    scrub: &[("/methodResponses/0/1/list/0/ownerEmail", "f.email")],
    effects: &[EFFECT_TASKS, EFFECT_LISTS],
    ..Case::new(
        "tasks",
        "task-assigned-get-success",
        "success",
        "TaskAssigned/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskAssigned/get",{},"c1"]]}"#,
    )
};
const TASK_ASSIGNED_GET_FOREIGN_OBJECT: Case = Case {
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO tasks (mailbox_id, title, assignee_user_id) VALUES ({f.mailbox}, 'Foreign Only Assigned', {f.user}) RETURNING id",
        "INSERT INTO task_lists (owner_user_id, name) VALUES ({f.user}, 'Revoked List') RETURNING id",
        "INSERT INTO task_list_members (list_id, user_id, role, added_by_user_id) VALUES ({seed.1}, {f.user}, 'owner', {f.user})",
        "INSERT INTO tasks (mailbox_id, list_id, title, assignee_user_id) VALUES ({f.mailbox}, {seed.1}, 'Revoked List Assigned', {a.user}) RETURNING id",
    ],
    absent: &["{seed.0}", "Foreign Only Assigned", "{seed.2}", "Revoked List Assigned"],
    effects: &[EFFECT_TASKS, EFFECT_LISTS],
    ..Case::new(
        "tasks",
        "task-assigned-get-foreign-object",
        "foreign-object",
        "TaskAssigned/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskAssigned/get",{},"c1"]]}"#,
    )
};
const TASK_ASSIGNED_GET_INVALID_INPUT: Case = Case {
    toggles: SHARED_ON,
    effects: &[EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-assigned-get-invalid-input",
        "invalid-input",
        "TaskAssigned/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskAssigned/get",[],"c1"]]}"#,
    )
};
const TASK_ASSIGNED_GET_ENTITLEMENT_DENIED: Case = Case {
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO tasks (mailbox_id, title, assignee_user_id) VALUES ({f.mailbox}, 'Assigned To Me', {a.user}) RETURNING id",
        SEED_DENY_TASKS_APP,
    ],
    absent: &["{seed.0}", "Assigned To Me"],
    effects: &[EFFECT_TASKS],
    ..Case::new(
        "tasks",
        "task-assigned-get-entitlement-denied",
        "entitlement-denied",
        "TaskAssigned/get",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskAssigned/get",{},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// TaskAssigned/setStatus
// ---------------------------------------------------------------------------

const TASK_ASSIGNED_SET_STATUS_SUCCESS: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO tasks (mailbox_id, title, assignee_user_id) VALUES ({f.mailbox}, 'Assigned To Me', {a.user}) RETURNING id",
    ],
    notify: &["task:{f.mailbox}"],
    effects: &[EFFECT_TASKS, EFFECT_ACTIVITY, EFFECT_JOURNAL],
    ..Case::new(
        "tasks",
        "task-assigned-set-status-success",
        "success",
        "TaskAssigned/setStatus",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskAssigned/setStatus",{"taskId":"{seed.0}","status":"in-progress"},"c1"]]}"#,
    )
};
const TASK_ASSIGNED_SET_STATUS_REPEAT: Case = Case {
    name: "task-assigned-set-status-repeat",
    kind: "repeat",
    repeat: true,
    ..TASK_ASSIGNED_SET_STATUS_SUCCESS
};
const TASK_ASSIGNED_SET_STATUS_FOREIGN_OBJECT: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO tasks (mailbox_id, title, assignee_user_id) VALUES ({f.mailbox}, 'Not Mine', {f.user}) RETURNING id",
    ],
    absent: &["{seed.0}", "Not Mine"],
    effects: &[EFFECT_TASKS, EFFECT_ACTIVITY],
    ..Case::new(
        "tasks",
        "task-assigned-set-status-foreign-object",
        "foreign-object",
        "TaskAssigned/setStatus",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskAssigned/setStatus",{"taskId":"{seed.0}","status":"completed"},"c1"]]}"#,
    )
};
const TASK_ASSIGNED_SET_STATUS_INVALID_INPUT: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO tasks (mailbox_id, title, assignee_user_id) VALUES ({f.mailbox}, 'Assigned To Me', {a.user}) RETURNING id",
    ],
    effects: &[EFFECT_TASKS, EFFECT_ACTIVITY],
    ..Case::new(
        "tasks",
        "task-assigned-set-status-invalid-input",
        "invalid-input",
        "TaskAssigned/setStatus",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskAssigned/setStatus",{"taskId":"{seed.0}","status":"bogus"},"c1"]]}"#,
    )
};
const TASK_ASSIGNED_SET_STATUS_ENTITLEMENT_DENIED: Case = Case {
    mutator: true,
    toggles: SHARED_ON,
    seed: &[
        "INSERT INTO tasks (mailbox_id, title, assignee_user_id) VALUES ({f.mailbox}, 'Assigned To Me', {a.user}) RETURNING id",
        SEED_DENY_TASKS_APP,
    ],
    absent: &["{seed.0}"],
    effects: &[EFFECT_TASKS, EFFECT_ACTIVITY],
    ..Case::new(
        "tasks",
        "task-assigned-set-status-entitlement-denied",
        "entitlement-denied",
        "TaskAssigned/setStatus",
        r#"{"using":["urn:ietf:params:jmap:tasks"],"methodCalls":[["TaskAssigned/setStatus",{"taskId":"{seed.0}","status":"completed"},"c1"]]}"#,
    )
};

macro_rules! oracle_test {
    ($name:ident, $case:expr) => {
        #[tokio::test]
        async fn $name() -> Result<(), BoxError> {
            assert_eq!($case.family, "tasks");
            assert!($case.request.contains(CAP_TASKS));
            run(&$case, Mutation::None).await
        }
    };
}

macro_rules! status_mutant_test {
    ($name:ident, $case:expr) => {
        #[tokio::test]
        async fn $name() -> Result<(), BoxError> {
            run_status_mutant(&$case).await
        }
    };
}

// Task/get
oracle_test!(task_get_success, TASK_GET_SUCCESS);
oracle_test!(task_get_mixed_ids, TASK_GET_MIXED_IDS);
oracle_test!(task_get_cross_tenant, TASK_GET_CROSS_TENANT);
oracle_test!(task_get_invalid_input, TASK_GET_INVALID_INPUT);
oracle_test!(task_get_delegate_personal, TASK_GET_DELEGATE_PERSONAL);
oracle_test!(task_get_entitlement_denied, TASK_GET_ENTITLEMENT_DENIED);
status_mutant_test!(task_get_status_mutant, TASK_GET_SUCCESS);

#[tokio::test]
async fn task_get_no_tenant_filter_mutant() -> Result<(), BoxError> {
    run(
        &TASK_GET_NO_TENANT_MUTANT,
        Mutation::NoTenantFilter {
            function: "jmap_task_get(bigint,bigint[])",
            from: "t.mailbox_id = p_mailbox_id",
        },
    )
    .await
}

// Task/query
oracle_test!(task_query_success, TASK_QUERY_SUCCESS);
oracle_test!(task_query_cross_tenant, TASK_QUERY_CROSS_TENANT);
oracle_test!(task_query_invalid_input, TASK_QUERY_INVALID_INPUT);
oracle_test!(task_query_delegate_personal, TASK_QUERY_DELEGATE_PERSONAL);
oracle_test!(task_query_entitlement_denied, TASK_QUERY_ENTITLEMENT_DENIED);
status_mutant_test!(task_query_status_mutant, TASK_QUERY_SUCCESS);

// Task/changes
oracle_test!(task_changes_success, TASK_CHANGES_SUCCESS);
oracle_test!(task_changes_cross_tenant, TASK_CHANGES_CROSS_TENANT);
oracle_test!(task_changes_invalid_input, TASK_CHANGES_INVALID_INPUT);
oracle_test!(task_changes_state_mismatch, TASK_CHANGES_STATE_MISMATCH);
oracle_test!(
    task_changes_delegate_personal,
    TASK_CHANGES_DELEGATE_PERSONAL
);
oracle_test!(
    task_changes_entitlement_denied,
    TASK_CHANGES_ENTITLEMENT_DENIED
);
status_mutant_test!(task_changes_status_mutant, TASK_CHANGES_SUCCESS);

// Task/set
oracle_test!(task_set_success, TASK_SET_SUCCESS);
oracle_test!(task_set_repeat, TASK_SET_REPEAT);
oracle_test!(task_set_update_destroy, TASK_SET_UPDATE_DESTROY);
oracle_test!(task_set_cross_tenant, TASK_SET_CROSS_TENANT);
oracle_test!(task_set_invalid_input, TASK_SET_INVALID_INPUT);
oracle_test!(task_set_delegate_personal, TASK_SET_DELEGATE_PERSONAL);
oracle_test!(task_set_entitlement_denied, TASK_SET_ENTITLEMENT_DENIED);
status_mutant_test!(task_set_status_mutant, TASK_SET_SUCCESS);

// TaskComment/get
oracle_test!(task_comment_get_success, TASK_COMMENT_GET_SUCCESS);
oracle_test!(task_comment_get_cross_tenant, TASK_COMMENT_GET_CROSS_TENANT);
oracle_test!(
    task_comment_get_invalid_input,
    TASK_COMMENT_GET_INVALID_INPUT
);
oracle_test!(
    task_comment_get_delegate_personal,
    TASK_COMMENT_GET_DELEGATE_PERSONAL
);
oracle_test!(
    task_comment_get_entitlement_denied,
    TASK_COMMENT_GET_ENTITLEMENT_DENIED
);
status_mutant_test!(task_comment_get_status_mutant, TASK_COMMENT_GET_SUCCESS);

// TaskComment/set
oracle_test!(task_comment_set_success, TASK_COMMENT_SET_SUCCESS);
oracle_test!(task_comment_set_repeat, TASK_COMMENT_SET_REPEAT);
oracle_test!(task_comment_set_cross_tenant, TASK_COMMENT_SET_CROSS_TENANT);
oracle_test!(
    task_comment_set_invalid_input,
    TASK_COMMENT_SET_INVALID_INPUT
);
oracle_test!(
    task_comment_set_delegate_personal,
    TASK_COMMENT_SET_DELEGATE_PERSONAL
);
oracle_test!(
    task_comment_set_entitlement_denied,
    TASK_COMMENT_SET_ENTITLEMENT_DENIED
);
status_mutant_test!(task_comment_set_status_mutant, TASK_COMMENT_SET_SUCCESS);

// TaskList/get
oracle_test!(task_list_get_success, TASK_LIST_GET_SUCCESS);
oracle_test!(task_list_get_foreign_object, TASK_LIST_GET_FOREIGN_OBJECT);
oracle_test!(task_list_get_invalid_input, TASK_LIST_GET_INVALID_INPUT);
oracle_test!(task_list_get_disabled, TASK_LIST_GET_DISABLED);
oracle_test!(
    task_list_get_entitlement_denied,
    TASK_LIST_GET_ENTITLEMENT_DENIED
);
status_mutant_test!(task_list_get_status_mutant, TASK_LIST_GET_SUCCESS);

// TaskList/set
oracle_test!(task_list_set_success, TASK_LIST_SET_SUCCESS);
oracle_test!(task_list_set_repeat, TASK_LIST_SET_REPEAT);
oracle_test!(task_list_set_update_destroy, TASK_LIST_SET_UPDATE_DESTROY);
oracle_test!(task_list_set_foreign_object, TASK_LIST_SET_FOREIGN_OBJECT);
oracle_test!(task_list_set_invalid_input, TASK_LIST_SET_INVALID_INPUT);
oracle_test!(
    task_list_set_entitlement_denied,
    TASK_LIST_SET_ENTITLEMENT_DENIED
);
status_mutant_test!(task_list_set_status_mutant, TASK_LIST_SET_SUCCESS);

// TaskListMember/set
oracle_test!(task_list_member_set_success, TASK_LIST_MEMBER_SET_SUCCESS);
oracle_test!(task_list_member_set_repeat, TASK_LIST_MEMBER_SET_REPEAT);
oracle_test!(
    task_list_member_set_self_leave,
    TASK_LIST_MEMBER_SET_SELF_LEAVE
);
oracle_test!(
    task_list_member_set_foreign_object,
    TASK_LIST_MEMBER_SET_FOREIGN_OBJECT
);
oracle_test!(
    task_list_member_set_nonexistent_list,
    TASK_LIST_MEMBER_SET_NONEXISTENT_LIST
);
oracle_test!(
    task_list_member_set_invalid_input,
    TASK_LIST_MEMBER_SET_INVALID_INPUT
);
oracle_test!(
    task_list_member_set_entitlement_denied,
    TASK_LIST_MEMBER_SET_ENTITLEMENT_DENIED
);
status_mutant_test!(
    task_list_member_set_status_mutant,
    TASK_LIST_MEMBER_SET_SUCCESS
);

// TaskList/tasks
oracle_test!(task_list_tasks_success, TASK_LIST_TASKS_SUCCESS);
oracle_test!(
    task_list_tasks_foreign_object,
    TASK_LIST_TASKS_FOREIGN_OBJECT
);
oracle_test!(task_list_tasks_invalid_input, TASK_LIST_TASKS_INVALID_INPUT);
oracle_test!(
    task_list_tasks_entitlement_denied,
    TASK_LIST_TASKS_ENTITLEMENT_DENIED
);
status_mutant_test!(task_list_tasks_status_mutant, TASK_LIST_TASKS_SUCCESS);

// TaskList/taskSet
oracle_test!(task_list_task_set_success, TASK_LIST_TASK_SET_SUCCESS);
oracle_test!(task_list_task_set_repeat, TASK_LIST_TASK_SET_REPEAT);
oracle_test!(
    task_list_task_set_update_destroy,
    TASK_LIST_TASK_SET_UPDATE_DESTROY
);
oracle_test!(
    task_list_task_set_foreign_object,
    TASK_LIST_TASK_SET_FOREIGN_OBJECT
);
oracle_test!(
    task_list_task_set_invalid_input,
    TASK_LIST_TASK_SET_INVALID_INPUT
);
oracle_test!(
    task_list_task_set_entitlement_denied,
    TASK_LIST_TASK_SET_ENTITLEMENT_DENIED
);
status_mutant_test!(task_list_task_set_status_mutant, TASK_LIST_TASK_SET_SUCCESS);

// TaskAssigned/get
oracle_test!(task_assigned_get_success, TASK_ASSIGNED_GET_SUCCESS);
oracle_test!(
    task_assigned_get_foreign_object,
    TASK_ASSIGNED_GET_FOREIGN_OBJECT
);
oracle_test!(
    task_assigned_get_invalid_input,
    TASK_ASSIGNED_GET_INVALID_INPUT
);
oracle_test!(
    task_assigned_get_entitlement_denied,
    TASK_ASSIGNED_GET_ENTITLEMENT_DENIED
);
status_mutant_test!(task_assigned_get_status_mutant, TASK_ASSIGNED_GET_SUCCESS);

// TaskAssigned/setStatus
oracle_test!(
    task_assigned_set_status_success,
    TASK_ASSIGNED_SET_STATUS_SUCCESS
);
oracle_test!(
    task_assigned_set_status_repeat,
    TASK_ASSIGNED_SET_STATUS_REPEAT
);
oracle_test!(
    task_assigned_set_status_foreign_object,
    TASK_ASSIGNED_SET_STATUS_FOREIGN_OBJECT
);
oracle_test!(
    task_assigned_set_status_invalid_input,
    TASK_ASSIGNED_SET_STATUS_INVALID_INPUT
);
oracle_test!(
    task_assigned_set_status_entitlement_denied,
    TASK_ASSIGNED_SET_STATUS_ENTITLEMENT_DENIED
);
status_mutant_test!(
    task_assigned_set_status_status_mutant,
    TASK_ASSIGNED_SET_STATUS_SUCCESS
);
