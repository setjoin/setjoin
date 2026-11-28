//! Frozen-Go parity and mutant tests for #376 (SavedSearch/*, QuickStep/*, EmailTemplate/*).
mod common;
#[allow(dead_code, unused_imports)]
mod jmap_family_oracle;

use jmap_family_oracle::{run, Case, Mutation};
use setjoin_conformance::harness::{BoxError, Db};

const FAMILY: &str = "vendor-mail";

const SAVED_SEARCH_EFFECTS: &[(&str, &str)] = &[(
    "saved_searches",
    "SELECT COALESCE(jsonb_agg(jsonb_build_object(\
     'id', id, 'mailbox_id', mailbox_id, 'name', name, 'query', query, 'position', position) \
     ORDER BY id), '[]'::jsonb)::text \
     FROM saved_searches WHERE mailbox_id IN ({a.mailbox}, {f.mailbox})",
)];

const QUICK_STEP_EFFECTS: &[(&str, &str)] = &[(
    "quick_steps",
    "SELECT COALESCE(jsonb_agg(jsonb_build_object(\
     'id', id, 'mailbox_id', mailbox_id, 'name', name, 'icon', icon, \
     'position', position, 'actions', actions) ORDER BY id), '[]'::jsonb)::text \
     FROM quick_steps WHERE mailbox_id IN ({a.mailbox}, {f.mailbox})",
)];

const QUICK_STEP_APPLY_EFFECTS: &[(&str, &str)] = &[
    (
        "messages",
        "SELECT COALESCE(jsonb_agg(jsonb_build_object(\
         'idx', idx, 'mailbox_id', mailbox_id, 'is_read', is_read, 'is_flagged', is_flagged) \
         ORDER BY idx), '[]'::jsonb)::text \
         FROM (SELECT row_number() OVER (ORDER BY id) AS idx, mailbox_id, is_read, is_flagged \
         FROM messages WHERE mailbox_id IN ({a.mailbox}, {f.mailbox})) sub",
    ),
    (
        "message_tags",
        "SELECT COALESCE(jsonb_agg(jsonb_build_object(\
         'message_idx', msg_idx, 'tag_name', tag_name) \
         ORDER BY msg_idx, tag_name), '[]'::jsonb)::text \
         FROM (SELECT dense_rank() OVER (ORDER BY mt.message_id) AS msg_idx, t.name AS tag_name \
         FROM message_tags mt JOIN tags t ON t.id = mt.tag_id \
         WHERE t.mailbox_id IN ({a.mailbox}, {f.mailbox})) sub",
    ),
    (
        "mailboxes",
        "SELECT COALESCE(jsonb_agg(jsonb_build_object(\
         'id', id, 'jmap_email_state', jmap_email_state, 'jmap_tag_state', jmap_tag_state) \
         ORDER BY id), '[]'::jsonb)::text \
         FROM mailboxes WHERE id IN ({a.mailbox}, {f.mailbox})",
    ),
    (
        "tags",
        "SELECT COALESCE(jsonb_agg(jsonb_build_object(\
         'mailbox_id', mailbox_id, 'name', name, 'unread_count', unread_count, \
         'jmap_state', jmap_state) ORDER BY mailbox_id, name), '[]'::jsonb)::text \
         FROM tags WHERE mailbox_id IN ({a.mailbox}, {f.mailbox})",
    ),
];

const EMAIL_TEMPLATE_EFFECTS: &[(&str, &str)] = &[(
    "email_templates",
    "SELECT COALESCE(jsonb_agg(jsonb_build_object(\
     'id', id, 'mailbox_id', mailbox_id, 'name', name, \
     'subject', subject, 'body_html', body_html) ORDER BY id), '[]'::jsonb)::text \
     FROM email_templates WHERE mailbox_id IN ({a.mailbox}, {f.mailbox})",
)];

const DELEGATE_FULL_ACCESS: &str =
    "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
     VALUES ({f.mailbox}, {a.user}, 'full_access', {f.user})";

macro_rules! replay {
    ($name:ident, $case:ident) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() -> Result<(), BoxError> {
            run(&$case, Mutation::None).await
        }
    };
}

macro_rules! status_mutant {
    ($name:ident, $case:ident) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() -> Result<(), BoxError> {
            let Some(_) = Db::for_case(stringify!($name)) else {
                return Ok(());
            };
            let error = run(&$case, Mutation::Status)
                .await
                .expect_err("changed status must fail")
                .to_string();
            assert!(error.contains("/response/status"), "{error}");
            println!(
                "MUTANT-REJECTED: POST /jmap {} :: changed-status",
                $case.method
            );
            Ok(())
        }
    };
}

// --- SavedSearch/list ---

const SAVED_SEARCH_LIST_SUCCESS: Case = Case {
    seed: &[
        "INSERT INTO saved_searches (mailbox_id, name, query, position) \
         VALUES ({a.mailbox}, 'Own Search', 'is:unread', 0) RETURNING id",
        "INSERT INTO saved_searches (mailbox_id, name, query, position) \
         VALUES ({f.mailbox}, 'Foreign Search', 'from:boss', 0) RETURNING id",
    ],
    absent: &["{seed.1}", "Foreign Search"],
    effects: SAVED_SEARCH_EFFECTS,
    ..Case::new(
        FAMILY,
        "saved-search-list-success",
        "success",
        "SavedSearch/list",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["SavedSearch/list",{"accountId":"{a.mailbox}"},"c1"]]}"#,
    )
};

const SAVED_SEARCH_LIST_CROSS_TENANT: Case = Case {
    seed: &[
        "INSERT INTO saved_searches (mailbox_id, name, query, position) \
         VALUES ({f.mailbox}, 'Foreign Search', 'from:boss', 0) RETURNING id",
    ],
    absent: &["{seed.0}", "Foreign Search"],
    effects: SAVED_SEARCH_EFFECTS,
    ..Case::new(
        FAMILY,
        "saved-search-list-cross-tenant",
        "cross-tenant",
        "SavedSearch/list",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["SavedSearch/list",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};

const SAVED_SEARCH_LIST_INVALID: Case = Case {
    effects: SAVED_SEARCH_EFFECTS,
    ..Case::new(
        FAMILY,
        "saved-search-list-invalid",
        "invalid-input",
        "SavedSearch/list",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["SavedSearch/list",{"accountId":7},"c1"]]}"#,
    )
};

const SAVED_SEARCH_LIST_DELEGATE_PERSONAL: Case = Case {
    seed: &[DELEGATE_FULL_ACCESS],
    effects: SAVED_SEARCH_EFFECTS,
    ..Case::new(
        FAMILY,
        "saved-search-list-delegate-personal",
        "delegate-personal",
        "SavedSearch/list",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["SavedSearch/list",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};

replay!(saved_search_list_success, SAVED_SEARCH_LIST_SUCCESS);
replay!(
    saved_search_list_cross_tenant,
    SAVED_SEARCH_LIST_CROSS_TENANT
);
replay!(saved_search_list_invalid, SAVED_SEARCH_LIST_INVALID);
replay!(
    saved_search_list_delegate_personal,
    SAVED_SEARCH_LIST_DELEGATE_PERSONAL
);
status_mutant!(saved_search_list_status_mutant, SAVED_SEARCH_LIST_SUCCESS);

// --- SavedSearch/set ---

const SAVED_SEARCH_SET_SUCCESS: Case = Case {
    mutator: true,
    effects: SAVED_SEARCH_EFFECTS,
    scrub: &[("/methodResponses/0/1/created/id", "created.id")],
    ..Case::new(
        FAMILY,
        "saved-search-set-success",
        "success",
        "SavedSearch/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["SavedSearch/set",{"accountId":"{a.mailbox}","name":"Important","query":"is:flagged"},"c1"]]}"#,
    )
};

const SAVED_SEARCH_SET_CROSS_TENANT: Case = Case {
    mutator: true,
    effects: SAVED_SEARCH_EFFECTS,
    ..Case::new(
        FAMILY,
        "saved-search-set-cross-tenant",
        "cross-tenant",
        "SavedSearch/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["SavedSearch/set",{"accountId":"{f.mailbox}","name":"Steal","query":"is:unread"},"c1"]]}"#,
    )
};

const SAVED_SEARCH_SET_INVALID: Case = Case {
    mutator: true,
    effects: SAVED_SEARCH_EFFECTS,
    ..Case::new(
        FAMILY,
        "saved-search-set-invalid",
        "invalid-input",
        "SavedSearch/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["SavedSearch/set",{"accountId":"{a.mailbox}","name":"","query":"is:unread"},"c1"]]}"#,
    )
};

const SAVED_SEARCH_SET_DELEGATE_PERSONAL: Case = Case {
    mutator: true,
    seed: &[DELEGATE_FULL_ACCESS],
    effects: SAVED_SEARCH_EFFECTS,
    ..Case::new(
        FAMILY,
        "saved-search-set-delegate-personal",
        "delegate-personal",
        "SavedSearch/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["SavedSearch/set",{"accountId":"{f.mailbox}","name":"Delegate","query":"is:unread"},"c1"]]}"#,
    )
};

const SAVED_SEARCH_SET_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    effects: SAVED_SEARCH_EFFECTS,
    scrub: &[("/methodResponses/0/1/created/id", "created.id")],
    ..Case::new(
        FAMILY,
        "saved-search-set-repeat",
        "repeat",
        "SavedSearch/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["SavedSearch/set",{"accountId":"{a.mailbox}","name":"Repeat Search","query":"is:unread"},"c1"]]}"#,
    )
};

replay!(saved_search_set_success, SAVED_SEARCH_SET_SUCCESS);
replay!(saved_search_set_cross_tenant, SAVED_SEARCH_SET_CROSS_TENANT);
replay!(saved_search_set_invalid, SAVED_SEARCH_SET_INVALID);
replay!(
    saved_search_set_delegate_personal,
    SAVED_SEARCH_SET_DELEGATE_PERSONAL
);
replay!(saved_search_set_repeat, SAVED_SEARCH_SET_REPEAT);
status_mutant!(saved_search_set_status_mutant, SAVED_SEARCH_SET_SUCCESS);

// --- SavedSearch/delete ---

const SAVED_SEARCH_DELETE_SUCCESS: Case = Case {
    mutator: true,
    seed: &[
        "INSERT INTO saved_searches (mailbox_id, name, query, position) \
         VALUES ({a.mailbox}, 'Delete Me', 'is:unread', 0) RETURNING id",
    ],
    effects: SAVED_SEARCH_EFFECTS,
    ..Case::new(
        FAMILY,
        "saved-search-delete-success",
        "success",
        "SavedSearch/delete",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["SavedSearch/delete",{"accountId":"{a.mailbox}","id":"{seed.0}"},"c1"]]}"#,
    )
};

const SAVED_SEARCH_DELETE_CROSS_TENANT: Case = Case {
    mutator: true,
    seed: &[
        "INSERT INTO saved_searches (mailbox_id, name, query, position) \
         VALUES ({f.mailbox}, 'Foreign', 'is:unread', 0) RETURNING id",
    ],
    absent: &["{seed.0}"],
    effects: SAVED_SEARCH_EFFECTS,
    ..Case::new(
        FAMILY,
        "saved-search-delete-cross-tenant",
        "cross-tenant",
        "SavedSearch/delete",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["SavedSearch/delete",{"accountId":"{f.mailbox}","id":"{seed.0}"},"c1"]]}"#,
    )
};

const SAVED_SEARCH_DELETE_INVALID: Case = Case {
    mutator: true,
    effects: SAVED_SEARCH_EFFECTS,
    ..Case::new(
        FAMILY,
        "saved-search-delete-invalid",
        "invalid-input",
        "SavedSearch/delete",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["SavedSearch/delete",{"accountId":"{a.mailbox}","id":"not-an-id"},"c1"]]}"#,
    )
};

const SAVED_SEARCH_DELETE_DELEGATE_PERSONAL: Case = Case {
    mutator: true,
    seed: &[
        DELEGATE_FULL_ACCESS,
        "INSERT INTO saved_searches (mailbox_id, name, query, position) \
         VALUES ({f.mailbox}, 'Foreign', 'is:unread', 0) RETURNING id",
    ],
    effects: SAVED_SEARCH_EFFECTS,
    ..Case::new(
        FAMILY,
        "saved-search-delete-delegate-personal",
        "delegate-personal",
        "SavedSearch/delete",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["SavedSearch/delete",{"accountId":"{f.mailbox}","id":"{seed.0}"},"c1"]]}"#,
    )
};

const SAVED_SEARCH_DELETE_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    seed: &[
        "INSERT INTO saved_searches (mailbox_id, name, query, position) \
         VALUES ({a.mailbox}, 'Delete Twice', 'is:unread', 0) RETURNING id",
    ],
    effects: SAVED_SEARCH_EFFECTS,
    ..Case::new(
        FAMILY,
        "saved-search-delete-repeat",
        "repeat",
        "SavedSearch/delete",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["SavedSearch/delete",{"accountId":"{a.mailbox}","id":"{seed.0}"},"c1"]]}"#,
    )
};

replay!(saved_search_delete_success, SAVED_SEARCH_DELETE_SUCCESS);
replay!(
    saved_search_delete_cross_tenant,
    SAVED_SEARCH_DELETE_CROSS_TENANT
);
replay!(saved_search_delete_invalid, SAVED_SEARCH_DELETE_INVALID);
replay!(
    saved_search_delete_delegate_personal,
    SAVED_SEARCH_DELETE_DELEGATE_PERSONAL
);
replay!(saved_search_delete_repeat, SAVED_SEARCH_DELETE_REPEAT);
status_mutant!(
    saved_search_delete_status_mutant,
    SAVED_SEARCH_DELETE_SUCCESS
);

// --- QuickStep/get ---

const QUICK_STEP_GET_SUCCESS: Case = Case {
    seed: &[
        "INSERT INTO quick_steps (mailbox_id, name, icon, actions, position) \
         VALUES ({a.mailbox}, 'Own Step', 'Zap', '[{\"type\":\"mark_read\"}]'::jsonb, 0) RETURNING id",
        "INSERT INTO quick_steps (mailbox_id, name, icon, actions, position) \
         VALUES ({f.mailbox}, 'Foreign Step', 'Star', '[{\"type\":\"flag\"}]'::jsonb, 0) RETURNING id",
    ],
    absent: &["{seed.1}", "Foreign Step"],
    effects: QUICK_STEP_EFFECTS,
    ..Case::new(
        FAMILY,
        "quick-step-get-success",
        "success",
        "QuickStep/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["QuickStep/get",{"accountId":"{a.mailbox}"},"c1"]]}"#,
    )
};

const QUICK_STEP_GET_NO_TENANT_MUTANT: Case = Case {
    absent: &[],
    ..QUICK_STEP_GET_SUCCESS
};

const QUICK_STEP_GET_CROSS_TENANT: Case = Case {
    seed: &[
        "INSERT INTO quick_steps (mailbox_id, name, icon, actions, position) \
         VALUES ({f.mailbox}, 'Foreign Step', 'Star', '[{\"type\":\"flag\"}]'::jsonb, 0) RETURNING id",
    ],
    absent: &["{seed.0}", "Foreign Step"],
    effects: QUICK_STEP_EFFECTS,
    ..Case::new(
        FAMILY,
        "quick-step-get-cross-tenant",
        "cross-tenant",
        "QuickStep/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["QuickStep/get",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};

const QUICK_STEP_GET_INVALID: Case = Case {
    effects: QUICK_STEP_EFFECTS,
    ..Case::new(
        FAMILY,
        "quick-step-get-invalid",
        "invalid-input",
        "QuickStep/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["QuickStep/get",{"accountId":7},"c1"]]}"#,
    )
};

const QUICK_STEP_GET_DELEGATE_PERSONAL: Case = Case {
    seed: &[DELEGATE_FULL_ACCESS],
    effects: QUICK_STEP_EFFECTS,
    ..Case::new(
        FAMILY,
        "quick-step-get-delegate-personal",
        "delegate-personal",
        "QuickStep/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["QuickStep/get",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};

replay!(quick_step_get_success, QUICK_STEP_GET_SUCCESS);
replay!(quick_step_get_cross_tenant, QUICK_STEP_GET_CROSS_TENANT);
replay!(quick_step_get_invalid, QUICK_STEP_GET_INVALID);
replay!(
    quick_step_get_delegate_personal,
    QUICK_STEP_GET_DELEGATE_PERSONAL
);
status_mutant!(quick_step_get_status_mutant, QUICK_STEP_GET_SUCCESS);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quick_step_get_no_tenant_filter_mutant() -> Result<(), BoxError> {
    run(
        &QUICK_STEP_GET_NO_TENANT_MUTANT,
        Mutation::NoTenantFilter {
            function: "quick_step_list(bigint)",
            from: "mailbox_id = p_mailbox_id",
        },
    )
    .await
}

// --- QuickStep/set ---

const QUICK_STEP_SET_SUCCESS: Case = Case {
    mutator: true,
    effects: QUICK_STEP_EFFECTS,
    scrub: &[("/methodResponses/0/1/id", "created.id")],
    ..Case::new(
        FAMILY,
        "quick-step-set-success",
        "success",
        "QuickStep/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["QuickStep/set",{"accountId":"{a.mailbox}","name":"Archive & Read","icon":"Archive","actions":[{"type":"mark_read"},{"type":"move_to","params":{"folder":"Archive"}}]},"c1"]]}"#,
    )
};

const QUICK_STEP_SET_UPDATE: Case = Case {
    mutator: true,
    seed: &[
        "INSERT INTO quick_steps (mailbox_id, name, icon, actions, position) \
         VALUES ({a.mailbox}, 'Before', 'Zap', '[{\"type\":\"mark_read\"}]'::jsonb, 0) RETURNING id",
    ],
    effects: QUICK_STEP_EFFECTS,
    ..Case::new(
        FAMILY,
        "quick-step-set-update",
        "update",
        "QuickStep/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["QuickStep/set",{"accountId":"{a.mailbox}","id":"{seed.0}","name":"Flagged","icon":"Flag","actions":[{"type":"flag"}]},"c1"]]}"#,
    )
};

const QUICK_STEP_SET_DESTROY: Case = Case {
    mutator: true,
    seed: &[
        "INSERT INTO quick_steps (mailbox_id, name, icon, actions, position) \
         VALUES ({a.mailbox}, 'Remove Me', 'Zap', '[{\"type\":\"mark_read\"}]'::jsonb, 0) RETURNING id",
    ],
    effects: QUICK_STEP_EFFECTS,
    ..Case::new(
        FAMILY,
        "quick-step-set-destroy",
        "destroy",
        "QuickStep/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["QuickStep/set",{"accountId":"{a.mailbox}","id":"{seed.0}","destroy":true},"c1"]]}"#,
    )
};

const QUICK_STEP_SET_CROSS_TENANT: Case = Case {
    mutator: true,
    effects: QUICK_STEP_EFFECTS,
    ..Case::new(
        FAMILY,
        "quick-step-set-cross-tenant",
        "cross-tenant",
        "QuickStep/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["QuickStep/set",{"accountId":"{f.mailbox}","name":"Steal","actions":[{"type":"mark_read"}]},"c1"]]}"#,
    )
};

const QUICK_STEP_SET_INVALID: Case = Case {
    mutator: true,
    effects: QUICK_STEP_EFFECTS,
    ..Case::new(
        FAMILY,
        "quick-step-set-invalid",
        "invalid-input",
        "QuickStep/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["QuickStep/set",{"accountId":"{a.mailbox}","name":"Bad","actions":[{"type":"delete"}]},"c1"]]}"#,
    )
};

const QUICK_STEP_SET_DELEGATE_PERSONAL: Case = Case {
    mutator: true,
    seed: &[DELEGATE_FULL_ACCESS],
    effects: QUICK_STEP_EFFECTS,
    ..Case::new(
        FAMILY,
        "quick-step-set-delegate-personal",
        "delegate-personal",
        "QuickStep/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["QuickStep/set",{"accountId":"{f.mailbox}","name":"Delegate","actions":[{"type":"mark_read"}]},"c1"]]}"#,
    )
};

const QUICK_STEP_SET_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    effects: QUICK_STEP_EFFECTS,
    scrub: &[("/methodResponses/0/1/id", "created.id")],
    ..Case::new(
        FAMILY,
        "quick-step-set-repeat",
        "repeat",
        "QuickStep/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["QuickStep/set",{"accountId":"{a.mailbox}","name":"Repeat Step","actions":[{"type":"flag"}]},"c1"]]}"#,
    )
};

replay!(quick_step_set_success, QUICK_STEP_SET_SUCCESS);
replay!(quick_step_set_update, QUICK_STEP_SET_UPDATE);
replay!(quick_step_set_destroy, QUICK_STEP_SET_DESTROY);
replay!(quick_step_set_cross_tenant, QUICK_STEP_SET_CROSS_TENANT);
replay!(quick_step_set_invalid, QUICK_STEP_SET_INVALID);
replay!(
    quick_step_set_delegate_personal,
    QUICK_STEP_SET_DELEGATE_PERSONAL
);
replay!(quick_step_set_repeat, QUICK_STEP_SET_REPEAT);
status_mutant!(quick_step_set_status_mutant, QUICK_STEP_SET_SUCCESS);

// --- QuickStep/apply ---

const QUICK_STEP_APPLY_SUCCESS: Case = Case {
    mutator: true,
    seed: &[
        "INSERT INTO quick_steps (mailbox_id, name, actions) \
         VALUES ({a.mailbox}, 'Archive & Read', \
         '[{\"type\":\"mark_read\"},{\"type\":\"move_to\",\"params\":{\"folder\":\"Archive\"}}]'::jsonb) \
         RETURNING id",
        "SELECT id FROM messages WHERE mailbox_id = {a.mailbox} AND NOT is_read ORDER BY id LIMIT 1",
        "SELECT id FROM tags WHERE mailbox_id = {a.mailbox} AND name = 'Archive'",
    ],
    effects: QUICK_STEP_APPLY_EFFECTS,
    notify: &["tag:{a.mailbox}", "tag:{f.mailbox}"],
    ..Case::new(
        FAMILY,
        "quick-step-apply-success",
        "success",
        "QuickStep/apply",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["QuickStep/apply",{"accountId":"{a.mailbox}","id":"{seed.0}","messageId":"{seed.1}"},"c1"]]}"#,
    )
};

const QUICK_STEP_APPLY_NOT_FOUND: Case = Case {
    mutator: true,
    seed: &[
        "INSERT INTO quick_steps (mailbox_id, name, actions) \
         VALUES ({a.mailbox}, 'Mark Read', '[{\"type\":\"mark_read\"}]'::jsonb) RETURNING id",
        "SELECT id FROM messages WHERE mailbox_id = {f.mailbox} AND NOT is_read ORDER BY id LIMIT 1",
    ],
    effects: QUICK_STEP_APPLY_EFFECTS,
    notify: &["tag:{a.mailbox}", "tag:{f.mailbox}"],
    ..Case::new(
        FAMILY,
        "quick-step-apply-not-found",
        "not-found",
        "QuickStep/apply",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["QuickStep/apply",{"accountId":"{a.mailbox}","id":"{seed.0}","messageId":"{seed.1}"},"c1"]]}"#,
    )
};

const QUICK_STEP_APPLY_CROSS_TENANT: Case = Case {
    mutator: true,
    seed: &[
        "INSERT INTO quick_steps (mailbox_id, name, actions) \
         VALUES ({f.mailbox}, 'Foreign Step', '[{\"type\":\"mark_read\"}]'::jsonb) RETURNING id",
        "SELECT id FROM messages WHERE mailbox_id = {f.mailbox} AND NOT is_read ORDER BY id LIMIT 1",
    ],
    absent: &["{seed.0}", "{seed.1}"],
    effects: QUICK_STEP_APPLY_EFFECTS,
    notify: &["tag:{a.mailbox}", "tag:{f.mailbox}"],
    ..Case::new(
        FAMILY,
        "quick-step-apply-cross-tenant",
        "cross-tenant",
        "QuickStep/apply",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["QuickStep/apply",{"accountId":"{f.mailbox}","id":"{seed.0}","messageId":"{seed.1}"},"c1"]]}"#,
    )
};

const QUICK_STEP_APPLY_INVALID: Case = Case {
    mutator: true,
    effects: QUICK_STEP_APPLY_EFFECTS,
    ..Case::new(
        FAMILY,
        "quick-step-apply-invalid",
        "invalid-input",
        "QuickStep/apply",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["QuickStep/apply",{"accountId":"{a.mailbox}","id":"bad","messageId":"1"},"c1"]]}"#,
    )
};

const QUICK_STEP_APPLY_DELEGATE_PERSONAL: Case = Case {
    mutator: true,
    seed: &[
        DELEGATE_FULL_ACCESS,
        "INSERT INTO quick_steps (mailbox_id, name, actions) \
         VALUES ({f.mailbox}, 'Foreign Step', '[{\"type\":\"mark_read\"}]'::jsonb) RETURNING id",
        "SELECT id FROM messages WHERE mailbox_id = {f.mailbox} AND NOT is_read ORDER BY id LIMIT 1",
    ],
    effects: QUICK_STEP_APPLY_EFFECTS,
    notify: &["tag:{a.mailbox}", "tag:{f.mailbox}"],
    ..Case::new(
        FAMILY,
        "quick-step-apply-delegate-personal",
        "delegate-personal",
        "QuickStep/apply",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["QuickStep/apply",{"accountId":"{f.mailbox}","id":"{seed.0}","messageId":"{seed.1}"},"c1"]]}"#,
    )
};

const QUICK_STEP_APPLY_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    seed: &[
        "INSERT INTO quick_steps (mailbox_id, name, actions) \
         VALUES ({a.mailbox}, 'Mark Read', '[{\"type\":\"mark_read\"}]'::jsonb) RETURNING id",
        "SELECT id FROM messages WHERE mailbox_id = {a.mailbox} AND NOT is_read ORDER BY id LIMIT 1",
    ],
    effects: QUICK_STEP_APPLY_EFFECTS,
    notify: &["tag:{a.mailbox}", "tag:{f.mailbox}"],
    ..Case::new(
        FAMILY,
        "quick-step-apply-repeat",
        "repeat",
        "QuickStep/apply",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["QuickStep/apply",{"accountId":"{a.mailbox}","id":"{seed.0}","messageId":"{seed.1}"},"c1"]]}"#,
    )
};

replay!(quick_step_apply_success, QUICK_STEP_APPLY_SUCCESS);
replay!(quick_step_apply_not_found, QUICK_STEP_APPLY_NOT_FOUND);
replay!(quick_step_apply_cross_tenant, QUICK_STEP_APPLY_CROSS_TENANT);
replay!(quick_step_apply_invalid, QUICK_STEP_APPLY_INVALID);
replay!(
    quick_step_apply_delegate_personal,
    QUICK_STEP_APPLY_DELEGATE_PERSONAL
);
replay!(quick_step_apply_repeat, QUICK_STEP_APPLY_REPEAT);
status_mutant!(quick_step_apply_status_mutant, QUICK_STEP_APPLY_SUCCESS);

// --- EmailTemplate/list ---

const EMAIL_TEMPLATE_LIST_SUCCESS: Case = Case {
    seed: &[
        "INSERT INTO email_templates (mailbox_id, name, subject, body_html) \
         VALUES ({a.mailbox}, 'Greeting', 'Hello', '<p>Hi &amp; welcome</p>') RETURNING id",
        "INSERT INTO email_templates (mailbox_id, name, subject, body_html) \
         VALUES ({f.mailbox}, 'Foreign Template', 'Secret', '<p>Private</p>') RETURNING id",
    ],
    absent: &["{seed.1}", "Foreign Template", "Secret"],
    effects: EMAIL_TEMPLATE_EFFECTS,
    ..Case::new(
        FAMILY,
        "email-template-list-success",
        "success",
        "EmailTemplate/list",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["EmailTemplate/list",{"accountId":"{a.mailbox}"},"c1"]]}"#,
    )
};

const EMAIL_TEMPLATE_LIST_CROSS_TENANT: Case = Case {
    seed: &[
        "INSERT INTO email_templates (mailbox_id, name, subject, body_html) \
         VALUES ({f.mailbox}, 'Foreign Template', 'Secret', '<p>Private</p>') RETURNING id",
    ],
    absent: &["{seed.0}", "Foreign Template"],
    effects: EMAIL_TEMPLATE_EFFECTS,
    ..Case::new(
        FAMILY,
        "email-template-list-cross-tenant",
        "cross-tenant",
        "EmailTemplate/list",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["EmailTemplate/list",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};

const EMAIL_TEMPLATE_LIST_INVALID: Case = Case {
    effects: EMAIL_TEMPLATE_EFFECTS,
    ..Case::new(
        FAMILY,
        "email-template-list-invalid",
        "invalid-input",
        "EmailTemplate/list",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["EmailTemplate/list",{"accountId":7},"c1"]]}"#,
    )
};

const EMAIL_TEMPLATE_LIST_DELEGATE_PERSONAL: Case = Case {
    seed: &[DELEGATE_FULL_ACCESS],
    effects: EMAIL_TEMPLATE_EFFECTS,
    ..Case::new(
        FAMILY,
        "email-template-list-delegate-personal",
        "delegate-personal",
        "EmailTemplate/list",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["EmailTemplate/list",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};

replay!(email_template_list_success, EMAIL_TEMPLATE_LIST_SUCCESS);
replay!(
    email_template_list_cross_tenant,
    EMAIL_TEMPLATE_LIST_CROSS_TENANT
);
replay!(email_template_list_invalid, EMAIL_TEMPLATE_LIST_INVALID);
replay!(
    email_template_list_delegate_personal,
    EMAIL_TEMPLATE_LIST_DELEGATE_PERSONAL
);
status_mutant!(
    email_template_list_status_mutant,
    EMAIL_TEMPLATE_LIST_SUCCESS
);

// --- EmailTemplate/set ---

const EMAIL_TEMPLATE_SET_SUCCESS: Case = Case {
    mutator: true,
    effects: EMAIL_TEMPLATE_EFFECTS,
    scrub: &[("/methodResponses/0/1/created/id", "created.id")],
    ..Case::new(
        FAMILY,
        "email-template-set-success",
        "success",
        "EmailTemplate/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["EmailTemplate/set",{"accountId":"{a.mailbox}","name":"Out of Office","subject":"OOO","bodyHtml":"<p>Back soon & rested</p>"},"c1"]]}"#,
    )
};

const EMAIL_TEMPLATE_SET_CROSS_TENANT: Case = Case {
    mutator: true,
    effects: EMAIL_TEMPLATE_EFFECTS,
    ..Case::new(
        FAMILY,
        "email-template-set-cross-tenant",
        "cross-tenant",
        "EmailTemplate/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["EmailTemplate/set",{"accountId":"{f.mailbox}","name":"Steal","subject":"x","bodyHtml":"<p>x</p>"},"c1"]]}"#,
    )
};

const EMAIL_TEMPLATE_SET_INVALID: Case = Case {
    mutator: true,
    effects: EMAIL_TEMPLATE_EFFECTS,
    ..Case::new(
        FAMILY,
        "email-template-set-invalid",
        "invalid-input",
        "EmailTemplate/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["EmailTemplate/set",{"accountId":"{a.mailbox}","name":"","subject":"x","bodyHtml":"<p>x</p>"},"c1"]]}"#,
    )
};

const EMAIL_TEMPLATE_SET_DELEGATE_PERSONAL: Case = Case {
    mutator: true,
    seed: &[DELEGATE_FULL_ACCESS],
    effects: EMAIL_TEMPLATE_EFFECTS,
    ..Case::new(
        FAMILY,
        "email-template-set-delegate-personal",
        "delegate-personal",
        "EmailTemplate/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["EmailTemplate/set",{"accountId":"{f.mailbox}","name":"Delegate","subject":"x","bodyHtml":"<p>x</p>"},"c1"]]}"#,
    )
};

const EMAIL_TEMPLATE_SET_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    effects: EMAIL_TEMPLATE_EFFECTS,
    scrub: &[("/methodResponses/0/1/created/id", "created.id")],
    ..Case::new(
        FAMILY,
        "email-template-set-repeat",
        "repeat",
        "EmailTemplate/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["EmailTemplate/set",{"accountId":"{a.mailbox}","name":"Upsert","subject":"Subj","bodyHtml":"<p>Body</p>"},"c1"]]}"#,
    )
};

replay!(email_template_set_success, EMAIL_TEMPLATE_SET_SUCCESS);
replay!(
    email_template_set_cross_tenant,
    EMAIL_TEMPLATE_SET_CROSS_TENANT
);
replay!(email_template_set_invalid, EMAIL_TEMPLATE_SET_INVALID);
replay!(
    email_template_set_delegate_personal,
    EMAIL_TEMPLATE_SET_DELEGATE_PERSONAL
);
replay!(email_template_set_repeat, EMAIL_TEMPLATE_SET_REPEAT);
status_mutant!(email_template_set_status_mutant, EMAIL_TEMPLATE_SET_SUCCESS);

// --- EmailTemplate/delete ---

const EMAIL_TEMPLATE_DELETE_SUCCESS: Case = Case {
    mutator: true,
    seed: &[
        "INSERT INTO email_templates (mailbox_id, name, subject, body_html) \
         VALUES ({a.mailbox}, 'Delete Me', 'Subj', '<p>Body</p>') RETURNING id",
    ],
    effects: EMAIL_TEMPLATE_EFFECTS,
    ..Case::new(
        FAMILY,
        "email-template-delete-success",
        "success",
        "EmailTemplate/delete",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["EmailTemplate/delete",{"accountId":"{a.mailbox}","id":"{seed.0}"},"c1"]]}"#,
    )
};

const EMAIL_TEMPLATE_DELETE_CROSS_TENANT: Case = Case {
    mutator: true,
    seed: &[
        "INSERT INTO email_templates (mailbox_id, name, subject, body_html) \
         VALUES ({f.mailbox}, 'Foreign', 'Subj', '<p>Body</p>') RETURNING id",
    ],
    absent: &["{seed.0}"],
    effects: EMAIL_TEMPLATE_EFFECTS,
    ..Case::new(
        FAMILY,
        "email-template-delete-cross-tenant",
        "cross-tenant",
        "EmailTemplate/delete",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["EmailTemplate/delete",{"accountId":"{f.mailbox}","id":"{seed.0}"},"c1"]]}"#,
    )
};

const EMAIL_TEMPLATE_DELETE_INVALID: Case = Case {
    mutator: true,
    effects: EMAIL_TEMPLATE_EFFECTS,
    ..Case::new(
        FAMILY,
        "email-template-delete-invalid",
        "invalid-input",
        "EmailTemplate/delete",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["EmailTemplate/delete",{"accountId":"{a.mailbox}","id":"0"},"c1"]]}"#,
    )
};

const EMAIL_TEMPLATE_DELETE_DELEGATE_PERSONAL: Case = Case {
    mutator: true,
    seed: &[
        DELEGATE_FULL_ACCESS,
        "INSERT INTO email_templates (mailbox_id, name, subject, body_html) \
         VALUES ({f.mailbox}, 'Foreign', 'Subj', '<p>Body</p>') RETURNING id",
    ],
    effects: EMAIL_TEMPLATE_EFFECTS,
    ..Case::new(
        FAMILY,
        "email-template-delete-delegate-personal",
        "delegate-personal",
        "EmailTemplate/delete",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["EmailTemplate/delete",{"accountId":"{f.mailbox}","id":"{seed.0}"},"c1"]]}"#,
    )
};

const EMAIL_TEMPLATE_DELETE_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    seed: &[
        "INSERT INTO email_templates (mailbox_id, name, subject, body_html) \
         VALUES ({a.mailbox}, 'Delete Twice', 'Subj', '<p>Body</p>') RETURNING id",
    ],
    effects: EMAIL_TEMPLATE_EFFECTS,
    ..Case::new(
        FAMILY,
        "email-template-delete-repeat",
        "repeat",
        "EmailTemplate/delete",
        r#"{"using":["urn:ietf:params:jmap:core","urn:setjoin:params:jmap:mail"],"methodCalls":[["EmailTemplate/delete",{"accountId":"{a.mailbox}","id":"{seed.0}"},"c1"]]}"#,
    )
};

replay!(email_template_delete_success, EMAIL_TEMPLATE_DELETE_SUCCESS);
replay!(
    email_template_delete_cross_tenant,
    EMAIL_TEMPLATE_DELETE_CROSS_TENANT
);
replay!(email_template_delete_invalid, EMAIL_TEMPLATE_DELETE_INVALID);
replay!(
    email_template_delete_delegate_personal,
    EMAIL_TEMPLATE_DELETE_DELEGATE_PERSONAL
);
replay!(email_template_delete_repeat, EMAIL_TEMPLATE_DELETE_REPEAT);
status_mutant!(
    email_template_delete_status_mutant,
    EMAIL_TEMPLATE_DELETE_SUCCESS
);
