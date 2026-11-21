//! Frozen-Go parity oracle for #370 (`ContactCard/*`, 10 methods).
mod common;
#[allow(dead_code)]
mod jmap_family_oracle;

use jmap_family_oracle::{run, Case, Mutation};

const FAMILY: &str = "contact_card";

const CONTACT_EFFECTS: &[(&str, &str)] = &[
    (
        "addressbooks",
        "SELECT coalesce(jsonb_agg(jsonb_build_object('id',id,'mailbox_id',mailbox_id,'name',name,'is_default',is_default,'jmap_state',jmap_state) ORDER BY id),'[]'::jsonb)::text FROM addressbooks WHERE mailbox_id IN ({a.mailbox},{f.mailbox})",
    ),
    (
        "contacts",
        "SELECT coalesce(jsonb_agg(jsonb_build_object('id',c.id,'addressbook_id',c.addressbook_id,'vcard_uid',c.vcard_uid,'display_name',c.display_name,'first_name',c.first_name,'last_name',c.last_name,'company',c.company,'job_title',c.job_title,'department',c.department,'emails',c.emails,'phones',c.phones,'notes',c.notes,'categories',c.categories,'jmap_state',c.jmap_state) ORDER BY c.id),'[]'::jsonb)::text FROM contacts c JOIN addressbooks ab ON ab.id = c.addressbook_id WHERE ab.mailbox_id IN ({a.mailbox},{f.mailbox})",
    ),
    (
        "contact_group_members",
        "SELECT coalesce(jsonb_agg(jsonb_build_object('group_id',m.group_id,'contact_id',m.contact_id,'email',m.email) ORDER BY m.group_id,m.contact_id,m.email),'[]'::jsonb)::text FROM contact_group_members m JOIN contact_groups g ON g.id = m.group_id WHERE g.mailbox_id IN ({a.mailbox},{f.mailbox})",
    ),
    (
        "entity_state",
        "SELECT coalesce(jsonb_agg(jsonb_build_object('mailbox_id',mailbox_id,'datatype',datatype,'seq',seq) ORDER BY mailbox_id,datatype),'[]'::jsonb)::text FROM jmap_entity_state WHERE mailbox_id IN ({a.mailbox},{f.mailbox})",
    ),
    (
        "journal",
        "SELECT coalesce(jsonb_agg(jsonb_build_object('mailbox_id',mailbox_id,'datatype',datatype,'state_seq',state_seq,'entity_id',entity_id,'op',op) ORDER BY mailbox_id,datatype,state_seq,entity_id),'[]'::jsonb)::text FROM jmap_changes_journal WHERE mailbox_id IN ({a.mailbox},{f.mailbox})",
    ),
];

const SEED_DELEGATE: &[&str] = &[
    "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) VALUES ({f.mailbox}, {a.user}, 'full_access', {f.user})",
];
const SEED_DENY_ENTITLEMENT: &[&str] = &[
    "INSERT INTO user_app_entitlements (user_id, app, enabled) VALUES ({a.user}, 'contacts', false) ON CONFLICT (user_id, app) DO UPDATE SET enabled = false",
];
const NOTIFY_CONTACT: &[&str] = &["contact:{a.mailbox}"];

macro_rules! jmap {
    ($method:literal, $args:literal) => {
        concat!(
            r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:contacts"],"methodCalls":[["#,
            "\"",
            $method,
            "\",",
            $args,
            r#","c1"]]}"#
        )
    };
}

const fn base_case(
    name: &'static str,
    kind: &'static str,
    method: &'static str,
    request: &'static str,
) -> Case {
    Case {
        effects: CONTACT_EFFECTS,
        ..Case::new(FAMILY, name, kind, method, request)
    }
}

async fn replay(case: &Case) {
    run(case, Mutation::None).await.expect("golden replay");
}

async fn status_mutant(case: &Case) {
    let err = run(case, Mutation::Status)
        .await
        .expect_err("status mutant must fail golden comparison");
    assert!(
        err.to_string().starts_with("GOLDEN-DIFF "),
        "unexpected error for status mutant: {err}"
    );
    println!(
        "MUTANT-REJECTED: POST /jmap {} :: changed-status",
        case.method
    );
}

// ── ContactCard/get ──────────────────────────────────────────────────────────

const CONTACT_CARD_GET_SUCCESS: Case = Case {
    seed: &[
        "INSERT INTO addressbooks (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Contacts', TRUE) RETURNING id",
        "INSERT INTO contacts (addressbook_id, vcard_uid, display_name, first_name, last_name, emails) VALUES ({seed.0}, 'uid-a1', 'Alice Own', 'Alice', 'Own', '[{\"type\":\"work\",\"address\":\"alice@example.test\",\"is_primary\":true}]'::jsonb) RETURNING id",
        "INSERT INTO addressbooks (mailbox_id, name, is_default) VALUES ({f.mailbox}, 'Foreign Contacts', TRUE) RETURNING id",
        "INSERT INTO contacts (addressbook_id, vcard_uid, display_name, first_name, last_name, emails) VALUES ({seed.2}, 'uid-f1', 'Frank Foreign', 'Frank', 'Foreign', '[{\"type\":\"work\",\"address\":\"frank@example.test\",\"is_primary\":true}]'::jsonb) RETURNING id",
    ],
    ..base_case(
        "contact-card-get-success",
        "success",
        "ContactCard/get",
        jmap!(
            "ContactCard/get",
            r#"{"accountId":"{a.mailbox}","ids":["{seed.1}","{seed.3}","bad-id"]}"#
        ),
    )
};
const CONTACT_CARD_GET_CROSS_TENANT: Case = Case {
    absent: &["{f.mailbox}"],
    ..base_case(
        "contact-card-get-cross-tenant",
        "cross-tenant",
        "ContactCard/get",
        jmap!(
            "ContactCard/get",
            r#"{"accountId":"{f.mailbox}","ids":["1"]}"#
        ),
    )
};
const CONTACT_CARD_GET_INVALID_INPUT: Case = base_case(
    "contact-card-get-invalid-input",
    "invalid-input",
    "ContactCard/get",
    jmap!("ContactCard/get", r#"{"accountId":123,"ids":["1"]}"#),
);
const CONTACT_CARD_GET_DELEGATE_PERSONAL: Case = Case {
    seed: SEED_DELEGATE,
    ..base_case(
        "contact-card-get-delegate-personal",
        "delegate-personal",
        "ContactCard/get",
        jmap!(
            "ContactCard/get",
            r#"{"accountId":"{f.mailbox}","ids":["1"]}"#
        ),
    )
};
const CONTACT_CARD_GET_ENTITLEMENT_DENIED: Case = Case {
    seed: SEED_DENY_ENTITLEMENT,
    ..base_case(
        "contact-card-get-entitlement-denied",
        "entitlement-denied",
        "ContactCard/get",
        jmap!(
            "ContactCard/get",
            r#"{"accountId":"{a.mailbox}","ids":["1"]}"#
        ),
    )
};

#[tokio::test]
async fn contact_card_get_success() {
    replay(&CONTACT_CARD_GET_SUCCESS).await;
}
#[tokio::test]
async fn contact_card_get_cross_tenant() {
    replay(&CONTACT_CARD_GET_CROSS_TENANT).await;
}
#[tokio::test]
async fn contact_card_get_invalid_input() {
    replay(&CONTACT_CARD_GET_INVALID_INPUT).await;
}
#[tokio::test]
async fn contact_card_get_delegate_personal() {
    replay(&CONTACT_CARD_GET_DELEGATE_PERSONAL).await;
}
#[tokio::test]
async fn contact_card_get_entitlement_denied() {
    replay(&CONTACT_CARD_GET_ENTITLEMENT_DENIED).await;
}
#[tokio::test]
async fn contact_card_get_changed_status_mutant() {
    status_mutant(&CONTACT_CARD_GET_SUCCESS).await;
}
#[tokio::test]
async fn contact_card_get_no_tenant_filter_mutant() {
    run(
        &CONTACT_CARD_GET_SUCCESS,
        Mutation::NoTenantFilter {
            function: "jmap_contact_get(bigint,bigint[])",
            from: "ab.mailbox_id = p_mailbox_id",
        },
    )
    .await
    .expect("no-tenant-filter mutant must be rejected");
}

// ── ContactCard/query ────────────────────────────────────────────────────────

const CONTACT_CARD_QUERY_SUCCESS: Case = Case {
    seed: &[
        "INSERT INTO addressbooks (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Contacts', TRUE) RETURNING id",
        "INSERT INTO contacts (addressbook_id, vcard_uid, display_name, emails) VALUES ({seed.0}, 'uid-q1', 'Alice Query', '[{\"type\":\"work\",\"address\":\"alice@example.test\",\"is_primary\":true}]'::jsonb) RETURNING id",
        "INSERT INTO contacts (addressbook_id, vcard_uid, display_name, emails) VALUES ({seed.0}, 'uid-q2', 'Bob Query', '[{\"type\":\"work\",\"address\":\"bob@example.test\",\"is_primary\":true}]'::jsonb) RETURNING id",
        "INSERT INTO addressbooks (mailbox_id, name, is_default) VALUES ({f.mailbox}, 'Foreign', TRUE) RETURNING id",
        "INSERT INTO contacts (addressbook_id, vcard_uid, display_name, emails) VALUES ({seed.3}, 'uid-qf', 'Alice Foreign', '[{\"type\":\"work\",\"address\":\"f@example.test\",\"is_primary\":true}]'::jsonb) RETURNING id",
    ],
    ..base_case(
        "contact-card-query-success",
        "success",
        "ContactCard/query",
        jmap!(
            "ContactCard/query",
            r#"{"accountId":"{a.mailbox}","filter":{"inAddressBook":"{seed.0}","text":"alice"},"position":0,"limit":10}"#
        ),
    )
};
const CONTACT_CARD_QUERY_CROSS_TENANT: Case = Case {
    absent: &["{f.mailbox}"],
    ..base_case(
        "contact-card-query-cross-tenant",
        "cross-tenant",
        "ContactCard/query",
        jmap!("ContactCard/query", r#"{"accountId":"{f.mailbox}"}"#),
    )
};
const CONTACT_CARD_QUERY_INVALID_INPUT: Case = base_case(
    "contact-card-query-invalid-input",
    "invalid-input",
    "ContactCard/query",
    jmap!(
        "ContactCard/query",
        r#"{"accountId":"{a.mailbox}","limit":"bad"}"#
    ),
);
const CONTACT_CARD_QUERY_DELEGATE_PERSONAL: Case = Case {
    seed: SEED_DELEGATE,
    ..base_case(
        "contact-card-query-delegate-personal",
        "delegate-personal",
        "ContactCard/query",
        jmap!("ContactCard/query", r#"{"accountId":"{f.mailbox}"}"#),
    )
};
const CONTACT_CARD_QUERY_ENTITLEMENT_DENIED: Case = Case {
    seed: SEED_DENY_ENTITLEMENT,
    ..base_case(
        "contact-card-query-entitlement-denied",
        "entitlement-denied",
        "ContactCard/query",
        jmap!("ContactCard/query", r#"{"accountId":"{a.mailbox}"}"#),
    )
};

#[tokio::test]
async fn contact_card_query_success() {
    replay(&CONTACT_CARD_QUERY_SUCCESS).await;
}
#[tokio::test]
async fn contact_card_query_cross_tenant() {
    replay(&CONTACT_CARD_QUERY_CROSS_TENANT).await;
}
#[tokio::test]
async fn contact_card_query_invalid_input() {
    replay(&CONTACT_CARD_QUERY_INVALID_INPUT).await;
}
#[tokio::test]
async fn contact_card_query_delegate_personal() {
    replay(&CONTACT_CARD_QUERY_DELEGATE_PERSONAL).await;
}
#[tokio::test]
async fn contact_card_query_entitlement_denied() {
    replay(&CONTACT_CARD_QUERY_ENTITLEMENT_DENIED).await;
}
#[tokio::test]
async fn contact_card_query_changed_status_mutant() {
    status_mutant(&CONTACT_CARD_QUERY_SUCCESS).await;
}

// ── ContactCard/changes ──────────────────────────────────────────────────────

const CONTACT_CARD_CHANGES_SUCCESS: Case = Case {
    seed: &[
        "INSERT INTO addressbooks (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Contacts', TRUE) RETURNING id",
        "INSERT INTO contacts (addressbook_id, vcard_uid, display_name) VALUES ({seed.0}, 'uid-c1', 'Carol Changes') RETURNING id",
    ],
    ..base_case(
        "contact-card-changes-success",
        "success",
        "ContactCard/changes",
        jmap!(
            "ContactCard/changes",
            r#"{"accountId":"{a.mailbox}","sinceState":"0"}"#
        ),
    )
};
const CONTACT_CARD_CHANGES_CROSS_TENANT: Case = Case {
    absent: &["{f.mailbox}"],
    ..base_case(
        "contact-card-changes-cross-tenant",
        "cross-tenant",
        "ContactCard/changes",
        jmap!(
            "ContactCard/changes",
            r#"{"accountId":"{f.mailbox}","sinceState":"0"}"#
        ),
    )
};
const CONTACT_CARD_CHANGES_INVALID_INPUT: Case = base_case(
    "contact-card-changes-invalid-input",
    "invalid-input",
    "ContactCard/changes",
    jmap!(
        "ContactCard/changes",
        r#"{"accountId":"{a.mailbox}","sinceState":"not-a-state"}"#
    ),
);
const CONTACT_CARD_CHANGES_DELEGATE_PERSONAL: Case = Case {
    seed: SEED_DELEGATE,
    ..base_case(
        "contact-card-changes-delegate-personal",
        "delegate-personal",
        "ContactCard/changes",
        jmap!(
            "ContactCard/changes",
            r#"{"accountId":"{f.mailbox}","sinceState":"0"}"#
        ),
    )
};
const CONTACT_CARD_CHANGES_ENTITLEMENT_DENIED: Case = Case {
    seed: SEED_DENY_ENTITLEMENT,
    ..base_case(
        "contact-card-changes-entitlement-denied",
        "entitlement-denied",
        "ContactCard/changes",
        jmap!(
            "ContactCard/changes",
            r#"{"accountId":"{a.mailbox}","sinceState":"0"}"#
        ),
    )
};
const CONTACT_CARD_CHANGES_STATE_MISMATCH: Case = Case {
    seed: &[
        "INSERT INTO addressbooks (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Contacts', TRUE) RETURNING id",
    ],
    ..base_case(
        "contact-card-changes-state-mismatch",
        "state-mismatch",
        "ContactCard/changes",
        jmap!(
            "ContactCard/changes",
            r#"{"accountId":"{a.mailbox}","sinceState":"999"}"#
        ),
    )
};

#[tokio::test]
async fn contact_card_changes_success() {
    replay(&CONTACT_CARD_CHANGES_SUCCESS).await;
}
#[tokio::test]
async fn contact_card_changes_cross_tenant() {
    replay(&CONTACT_CARD_CHANGES_CROSS_TENANT).await;
}
#[tokio::test]
async fn contact_card_changes_invalid_input() {
    replay(&CONTACT_CARD_CHANGES_INVALID_INPUT).await;
}
#[tokio::test]
async fn contact_card_changes_delegate_personal() {
    replay(&CONTACT_CARD_CHANGES_DELEGATE_PERSONAL).await;
}
#[tokio::test]
async fn contact_card_changes_entitlement_denied() {
    replay(&CONTACT_CARD_CHANGES_ENTITLEMENT_DENIED).await;
}
#[tokio::test]
async fn contact_card_changes_state_mismatch() {
    replay(&CONTACT_CARD_CHANGES_STATE_MISMATCH).await;
}
#[tokio::test]
async fn contact_card_changes_changed_status_mutant() {
    status_mutant(&CONTACT_CARD_CHANGES_SUCCESS).await;
}

// ── ContactCard/set ──────────────────────────────────────────────────────────

const CONTACT_CARD_SET_SUCCESS: Case = Case {
    mutator: true,
    notify: NOTIFY_CONTACT,
    ..base_case(
        "contact-card-set-success",
        "success",
        "ContactCard/set",
        jmap!("ContactCard/set", r#"{"accountId":"{a.mailbox}"}"#),
    )
};
const CONTACT_CARD_SET_CROSS_TENANT: Case = Case {
    mutator: true,
    notify: NOTIFY_CONTACT,
    absent: &["{f.mailbox}"],
    ..base_case(
        "contact-card-set-cross-tenant",
        "cross-tenant",
        "ContactCard/set",
        jmap!("ContactCard/set", r#"{"accountId":"{f.mailbox}"}"#),
    )
};
const CONTACT_CARD_SET_INVALID_INPUT: Case = Case {
    mutator: true,
    notify: NOTIFY_CONTACT,
    ..base_case(
        "contact-card-set-invalid-input",
        "invalid-input",
        "ContactCard/set",
        jmap!(
            "ContactCard/set",
            r#"{"accountId":"{a.mailbox}","destroy":[1]}"#
        ),
    )
};
const CONTACT_CARD_SET_DELEGATE_PERSONAL: Case = Case {
    mutator: true,
    seed: SEED_DELEGATE,
    notify: NOTIFY_CONTACT,
    ..base_case(
        "contact-card-set-delegate-personal",
        "delegate-personal",
        "ContactCard/set",
        jmap!("ContactCard/set", r#"{"accountId":"{f.mailbox}"}"#),
    )
};
const CONTACT_CARD_SET_ENTITLEMENT_DENIED: Case = Case {
    mutator: true,
    seed: SEED_DENY_ENTITLEMENT,
    notify: NOTIFY_CONTACT,
    ..base_case(
        "contact-card-set-entitlement-denied",
        "entitlement-denied",
        "ContactCard/set",
        jmap!("ContactCard/set", r#"{"accountId":"{a.mailbox}"}"#),
    )
};
const CONTACT_CARD_SET_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    notify: NOTIFY_CONTACT,
    ..base_case(
        "contact-card-set-repeat",
        "repeat",
        "ContactCard/set",
        jmap!(
            "ContactCard/set",
            r#"{"accountId":"{a.mailbox}","create":{"k1":{"firstName":"Alice"}}}"#
        ),
    )
};

#[tokio::test]
async fn contact_card_set_success() {
    replay(&CONTACT_CARD_SET_SUCCESS).await;
}
#[tokio::test]
async fn contact_card_set_cross_tenant() {
    replay(&CONTACT_CARD_SET_CROSS_TENANT).await;
}
#[tokio::test]
async fn contact_card_set_invalid_input() {
    replay(&CONTACT_CARD_SET_INVALID_INPUT).await;
}
#[tokio::test]
async fn contact_card_set_delegate_personal() {
    replay(&CONTACT_CARD_SET_DELEGATE_PERSONAL).await;
}
#[tokio::test]
async fn contact_card_set_entitlement_denied() {
    replay(&CONTACT_CARD_SET_ENTITLEMENT_DENIED).await;
}
#[tokio::test]
async fn contact_card_set_repeat() {
    replay(&CONTACT_CARD_SET_REPEAT).await;
}
#[tokio::test]
async fn contact_card_set_changed_status_mutant() {
    status_mutant(&CONTACT_CARD_SET_SUCCESS).await;
}

// ── ContactCard/findDuplicates ───────────────────────────────────────────────

const CONTACT_CARD_FIND_DUPLICATES_SUCCESS: Case = Case {
    seed: &[
        "INSERT INTO addressbooks (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Contacts', TRUE) RETURNING id",
        "INSERT INTO contacts (addressbook_id, vcard_uid, display_name, emails) VALUES ({seed.0}, 'uid-d1', 'Dup One', '[{\"type\":\"work\",\"address\":\"dup@example.test\",\"is_primary\":true}]'::jsonb) RETURNING id",
        "INSERT INTO contacts (addressbook_id, vcard_uid, display_name, emails) VALUES ({seed.0}, 'uid-d2', 'Dup Two', '[{\"type\":\"home\",\"address\":\"DUP@example.test\",\"is_primary\":true}]'::jsonb) RETURNING id",
        "INSERT INTO addressbooks (mailbox_id, name, is_default) VALUES ({f.mailbox}, 'Foreign', TRUE) RETURNING id",
        "INSERT INTO contacts (addressbook_id, vcard_uid, display_name, emails) VALUES ({seed.3}, 'uid-df', 'Dup Foreign', '[{\"type\":\"work\",\"address\":\"dup@example.test\",\"is_primary\":true}]'::jsonb) RETURNING id",
    ],
    ..base_case(
        "contact-card-find-duplicates-success",
        "success",
        "ContactCard/findDuplicates",
        jmap!("ContactCard/findDuplicates", r#"{"accountId":"{a.mailbox}"}"#),
    )
};
const CONTACT_CARD_FIND_DUPLICATES_CROSS_TENANT: Case = Case {
    absent: &["{f.mailbox}"],
    ..base_case(
        "contact-card-find-duplicates-cross-tenant",
        "cross-tenant",
        "ContactCard/findDuplicates",
        jmap!(
            "ContactCard/findDuplicates",
            r#"{"accountId":"{f.mailbox}"}"#
        ),
    )
};
const CONTACT_CARD_FIND_DUPLICATES_INVALID_INPUT: Case = base_case(
    "contact-card-find-duplicates-invalid-input",
    "invalid-input",
    "ContactCard/findDuplicates",
    jmap!("ContactCard/findDuplicates", r#"{"accountId":42}"#),
);
const CONTACT_CARD_FIND_DUPLICATES_DELEGATE_PERSONAL: Case = Case {
    seed: SEED_DELEGATE,
    ..base_case(
        "contact-card-find-duplicates-delegate-personal",
        "delegate-personal",
        "ContactCard/findDuplicates",
        jmap!(
            "ContactCard/findDuplicates",
            r#"{"accountId":"{f.mailbox}"}"#
        ),
    )
};
const CONTACT_CARD_FIND_DUPLICATES_ENTITLEMENT_DENIED: Case = Case {
    seed: SEED_DENY_ENTITLEMENT,
    ..base_case(
        "contact-card-find-duplicates-entitlement-denied",
        "entitlement-denied",
        "ContactCard/findDuplicates",
        jmap!(
            "ContactCard/findDuplicates",
            r#"{"accountId":"{a.mailbox}"}"#
        ),
    )
};

#[tokio::test]
async fn contact_card_find_duplicates_success() {
    replay(&CONTACT_CARD_FIND_DUPLICATES_SUCCESS).await;
}
#[tokio::test]
async fn contact_card_find_duplicates_cross_tenant() {
    replay(&CONTACT_CARD_FIND_DUPLICATES_CROSS_TENANT).await;
}
#[tokio::test]
async fn contact_card_find_duplicates_invalid_input() {
    replay(&CONTACT_CARD_FIND_DUPLICATES_INVALID_INPUT).await;
}
#[tokio::test]
async fn contact_card_find_duplicates_delegate_personal() {
    replay(&CONTACT_CARD_FIND_DUPLICATES_DELEGATE_PERSONAL).await;
}
#[tokio::test]
async fn contact_card_find_duplicates_entitlement_denied() {
    replay(&CONTACT_CARD_FIND_DUPLICATES_ENTITLEMENT_DENIED).await;
}
#[tokio::test]
async fn contact_card_find_duplicates_changed_status_mutant() {
    status_mutant(&CONTACT_CARD_FIND_DUPLICATES_SUCCESS).await;
}

// ── ContactCard/merge ────────────────────────────────────────────────────────

const CONTACT_CARD_MERGE_SUCCESS: Case = Case {
    mutator: true,
    seed: &[
        "INSERT INTO addressbooks (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Contacts', TRUE) RETURNING id",
        "INSERT INTO contacts (addressbook_id, vcard_uid, display_name, emails, categories) VALUES ({seed.0}, 'uid-m1', 'Keep Name', '[{\"type\":\"work\",\"address\":\"keep@example.test\",\"is_primary\":true}]'::jsonb, ARRAY['team']) RETURNING id",
        "INSERT INTO contacts (addressbook_id, vcard_uid, display_name, first_name, emails, phones, categories) VALUES ({seed.0}, 'uid-m2', 'Drop Name', 'Alice', '[{\"type\":\"home\",\"address\":\"drop@example.test\",\"is_primary\":true}]'::jsonb, '[{\"type\":\"mobile\",\"number\":\"+15550100\"}]'::jsonb, ARRAY['vip']) RETURNING id",
        "INSERT INTO contact_groups (mailbox_id, name) VALUES ({a.mailbox}, 'Merge Group') RETURNING id",
        "INSERT INTO contact_group_members (group_id, contact_id) VALUES ({seed.3}, {seed.2}) RETURNING id",
    ],
    notify: NOTIFY_CONTACT,
    ..base_case(
        "contact-card-merge-success",
        "success",
        "ContactCard/merge",
        jmap!(
            "ContactCard/merge",
            r#"{"accountId":"{a.mailbox}","keepId":"{seed.1}","dropId":"{seed.2}"}"#
        ),
    )
};
const CONTACT_CARD_MERGE_CROSS_TENANT: Case = Case {
    mutator: true,
    notify: NOTIFY_CONTACT,
    absent: &["{f.mailbox}"],
    ..base_case(
        "contact-card-merge-cross-tenant",
        "cross-tenant",
        "ContactCard/merge",
        jmap!(
            "ContactCard/merge",
            r#"{"accountId":"{f.mailbox}","keepId":"1","dropId":"2"}"#
        ),
    )
};
const CONTACT_CARD_MERGE_INVALID_INPUT: Case = Case {
    mutator: true,
    notify: NOTIFY_CONTACT,
    ..base_case(
        "contact-card-merge-invalid-input",
        "invalid-input",
        "ContactCard/merge",
        jmap!(
            "ContactCard/merge",
            r#"{"accountId":"{a.mailbox}","keepId":"abc","dropId":"2"}"#
        ),
    )
};
const CONTACT_CARD_MERGE_DELEGATE_PERSONAL: Case = Case {
    mutator: true,
    seed: SEED_DELEGATE,
    notify: NOTIFY_CONTACT,
    ..base_case(
        "contact-card-merge-delegate-personal",
        "delegate-personal",
        "ContactCard/merge",
        jmap!(
            "ContactCard/merge",
            r#"{"accountId":"{f.mailbox}","keepId":"1","dropId":"2"}"#
        ),
    )
};
const CONTACT_CARD_MERGE_ENTITLEMENT_DENIED: Case = Case {
    mutator: true,
    seed: SEED_DENY_ENTITLEMENT,
    notify: NOTIFY_CONTACT,
    ..base_case(
        "contact-card-merge-entitlement-denied",
        "entitlement-denied",
        "ContactCard/merge",
        jmap!(
            "ContactCard/merge",
            r#"{"accountId":"{a.mailbox}","keepId":"1","dropId":"2"}"#
        ),
    )
};
const CONTACT_CARD_MERGE_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    seed: &[
        "INSERT INTO addressbooks (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Contacts', TRUE) RETURNING id",
        "INSERT INTO contacts (addressbook_id, vcard_uid, display_name, emails) VALUES ({seed.0}, 'uid-mr1', 'Keep', '[{\"type\":\"work\",\"address\":\"k@example.test\",\"is_primary\":true}]'::jsonb) RETURNING id",
        "INSERT INTO contacts (addressbook_id, vcard_uid, display_name, emails) VALUES ({seed.0}, 'uid-mr2', 'Drop', '[{\"type\":\"home\",\"address\":\"d@example.test\",\"is_primary\":true}]'::jsonb) RETURNING id",
    ],
    notify: NOTIFY_CONTACT,
    ..base_case(
        "contact-card-merge-repeat",
        "repeat",
        "ContactCard/merge",
        jmap!(
            "ContactCard/merge",
            r#"{"accountId":"{a.mailbox}","keepId":"{seed.1}","dropId":"{seed.2}"}"#
        ),
    )
};

#[tokio::test]
async fn contact_card_merge_success() {
    replay(&CONTACT_CARD_MERGE_SUCCESS).await;
}
#[tokio::test]
async fn contact_card_merge_cross_tenant() {
    replay(&CONTACT_CARD_MERGE_CROSS_TENANT).await;
}
#[tokio::test]
async fn contact_card_merge_invalid_input() {
    replay(&CONTACT_CARD_MERGE_INVALID_INPUT).await;
}
#[tokio::test]
async fn contact_card_merge_delegate_personal() {
    replay(&CONTACT_CARD_MERGE_DELEGATE_PERSONAL).await;
}
#[tokio::test]
async fn contact_card_merge_entitlement_denied() {
    replay(&CONTACT_CARD_MERGE_ENTITLEMENT_DENIED).await;
}
#[tokio::test]
async fn contact_card_merge_repeat() {
    replay(&CONTACT_CARD_MERGE_REPEAT).await;
}
#[tokio::test]
async fn contact_card_merge_changed_status_mutant() {
    status_mutant(&CONTACT_CARD_MERGE_SUCCESS).await;
}

// ── ContactCard/galSearch ────────────────────────────────────────────────────

const CONTACT_CARD_GAL_SEARCH_SUCCESS: Case = Case {
    scrub: &[
        ("/methodResponses/0/1/list/0/email", "f.email"),
        ("/methodResponses/0/1/list/0/addresses/0/email", "f.email"),
    ],
    ..base_case(
        "contact-card-gal-search-success",
        "success",
        "ContactCard/galSearch",
        jmap!(
            "ContactCard/galSearch",
            r#"{"accountId":"{a.mailbox}","text":"fam-contact_card-foreign","limit":10}"#
        ),
    )
};
const CONTACT_CARD_GAL_SEARCH_CROSS_TENANT: Case = Case {
    absent: &["{f.mailbox}"],
    ..base_case(
        "contact-card-gal-search-cross-tenant",
        "cross-tenant",
        "ContactCard/galSearch",
        jmap!(
            "ContactCard/galSearch",
            r#"{"accountId":"{f.mailbox}","text":"fam"}"#
        ),
    )
};
const CONTACT_CARD_GAL_SEARCH_INVALID_INPUT: Case = base_case(
    "contact-card-gal-search-invalid-input",
    "invalid-input",
    "ContactCard/galSearch",
    jmap!(
        "ContactCard/galSearch",
        r#"{"accountId":"{a.mailbox}","limit":"ten"}"#
    ),
);
const CONTACT_CARD_GAL_SEARCH_DELEGATE_PERSONAL: Case = Case {
    seed: SEED_DELEGATE,
    ..base_case(
        "contact-card-gal-search-delegate-personal",
        "delegate-personal",
        "ContactCard/galSearch",
        jmap!(
            "ContactCard/galSearch",
            r#"{"accountId":"{f.mailbox}","text":"fam"}"#
        ),
    )
};
const CONTACT_CARD_GAL_SEARCH_ENTITLEMENT_DENIED: Case = Case {
    seed: SEED_DENY_ENTITLEMENT,
    ..base_case(
        "contact-card-gal-search-entitlement-denied",
        "entitlement-denied",
        "ContactCard/galSearch",
        jmap!(
            "ContactCard/galSearch",
            r#"{"accountId":"{a.mailbox}","text":"fam"}"#
        ),
    )
};

#[tokio::test]
async fn contact_card_gal_search_success() {
    replay(&CONTACT_CARD_GAL_SEARCH_SUCCESS).await;
}
#[tokio::test]
async fn contact_card_gal_search_cross_tenant() {
    replay(&CONTACT_CARD_GAL_SEARCH_CROSS_TENANT).await;
}
#[tokio::test]
async fn contact_card_gal_search_invalid_input() {
    replay(&CONTACT_CARD_GAL_SEARCH_INVALID_INPUT).await;
}
#[tokio::test]
async fn contact_card_gal_search_delegate_personal() {
    replay(&CONTACT_CARD_GAL_SEARCH_DELEGATE_PERSONAL).await;
}
#[tokio::test]
async fn contact_card_gal_search_entitlement_denied() {
    replay(&CONTACT_CARD_GAL_SEARCH_ENTITLEMENT_DENIED).await;
}
#[tokio::test]
async fn contact_card_gal_search_changed_status_mutant() {
    status_mutant(&CONTACT_CARD_GAL_SEARCH_SUCCESS).await;
}

// ── ContactCard/directoryTree ────────────────────────────────────────────────

const CONTACT_CARD_DIRECTORY_TREE_SUCCESS: Case = Case {
    seed: &[
        "INSERT INTO departments (name, path, ldap_ou) VALUES ('Engineering', '/jmap370-eng', 'OU=jmap370-eng') RETURNING id",
        "UPDATE users SET department_id = {seed.0} WHERE id = {a.user}",
    ],
    ..base_case(
        "contact-card-directory-tree-success",
        "success",
        "ContactCard/directoryTree",
        jmap!("ContactCard/directoryTree", r#"{"accountId":"{a.mailbox}"}"#),
    )
};
const CONTACT_CARD_DIRECTORY_TREE_CROSS_TENANT: Case = Case {
    absent: &["{f.mailbox}"],
    ..base_case(
        "contact-card-directory-tree-cross-tenant",
        "cross-tenant",
        "ContactCard/directoryTree",
        jmap!(
            "ContactCard/directoryTree",
            r#"{"accountId":"{f.mailbox}"}"#
        ),
    )
};
const CONTACT_CARD_DIRECTORY_TREE_INVALID_INPUT: Case = base_case(
    "contact-card-directory-tree-invalid-input",
    "invalid-input",
    "ContactCard/directoryTree",
    jmap!("ContactCard/directoryTree", r#"{"accountId":true}"#),
);
const CONTACT_CARD_DIRECTORY_TREE_DELEGATE_PERSONAL: Case = Case {
    seed: SEED_DELEGATE,
    ..base_case(
        "contact-card-directory-tree-delegate-personal",
        "delegate-personal",
        "ContactCard/directoryTree",
        jmap!(
            "ContactCard/directoryTree",
            r#"{"accountId":"{f.mailbox}"}"#
        ),
    )
};
const CONTACT_CARD_DIRECTORY_TREE_ENTITLEMENT_DENIED: Case = Case {
    seed: SEED_DENY_ENTITLEMENT,
    ..base_case(
        "contact-card-directory-tree-entitlement-denied",
        "entitlement-denied",
        "ContactCard/directoryTree",
        jmap!(
            "ContactCard/directoryTree",
            r#"{"accountId":"{a.mailbox}"}"#
        ),
    )
};

#[tokio::test]
async fn contact_card_directory_tree_success() {
    replay(&CONTACT_CARD_DIRECTORY_TREE_SUCCESS).await;
}
#[tokio::test]
async fn contact_card_directory_tree_cross_tenant() {
    replay(&CONTACT_CARD_DIRECTORY_TREE_CROSS_TENANT).await;
}
#[tokio::test]
async fn contact_card_directory_tree_invalid_input() {
    replay(&CONTACT_CARD_DIRECTORY_TREE_INVALID_INPUT).await;
}
#[tokio::test]
async fn contact_card_directory_tree_delegate_personal() {
    replay(&CONTACT_CARD_DIRECTORY_TREE_DELEGATE_PERSONAL).await;
}
#[tokio::test]
async fn contact_card_directory_tree_entitlement_denied() {
    replay(&CONTACT_CARD_DIRECTORY_TREE_ENTITLEMENT_DENIED).await;
}
#[tokio::test]
async fn contact_card_directory_tree_changed_status_mutant() {
    status_mutant(&CONTACT_CARD_DIRECTORY_TREE_SUCCESS).await;
}

// ── ContactCard/directoryMembers ─────────────────────────────────────────────

const CONTACT_CARD_DIRECTORY_MEMBERS_SUCCESS: Case = Case {
    seed: &[
        "INSERT INTO departments (name, path, ldap_ou) VALUES ('Platform', '/jmap370-platform', 'OU=jmap370-platform') RETURNING id",
        "UPDATE users SET department_id = {seed.0} WHERE id = {a.user}",
    ],
    scrub: &[
        ("/methodResponses/0/1/list/0/email", "a.email"),
        ("/methodResponses/0/1/list/0/addresses/0/email", "a.email"),
    ],
    ..base_case(
        "contact-card-directory-members-success",
        "success",
        "ContactCard/directoryMembers",
        jmap!(
            "ContactCard/directoryMembers",
            r#"{"accountId":"{a.mailbox}","departmentId":{seed.0},"offset":0,"limit":10}"#
        ),
    )
};
const CONTACT_CARD_DIRECTORY_MEMBERS_CROSS_TENANT: Case = Case {
    absent: &["{f.mailbox}"],
    ..base_case(
        "contact-card-directory-members-cross-tenant",
        "cross-tenant",
        "ContactCard/directoryMembers",
        jmap!(
            "ContactCard/directoryMembers",
            r#"{"accountId":"{f.mailbox}","departmentId":1}"#
        ),
    )
};
const CONTACT_CARD_DIRECTORY_MEMBERS_INVALID_INPUT: Case = base_case(
    "contact-card-directory-members-invalid-input",
    "invalid-input",
    "ContactCard/directoryMembers",
    jmap!(
        "ContactCard/directoryMembers",
        r#"{"accountId":"{a.mailbox}","departmentId":"not-an-int"}"#
    ),
);
const CONTACT_CARD_DIRECTORY_MEMBERS_DELEGATE_PERSONAL: Case = Case {
    seed: SEED_DELEGATE,
    ..base_case(
        "contact-card-directory-members-delegate-personal",
        "delegate-personal",
        "ContactCard/directoryMembers",
        jmap!(
            "ContactCard/directoryMembers",
            r#"{"accountId":"{f.mailbox}","departmentId":1}"#
        ),
    )
};
const CONTACT_CARD_DIRECTORY_MEMBERS_ENTITLEMENT_DENIED: Case = Case {
    seed: SEED_DENY_ENTITLEMENT,
    ..base_case(
        "contact-card-directory-members-entitlement-denied",
        "entitlement-denied",
        "ContactCard/directoryMembers",
        jmap!(
            "ContactCard/directoryMembers",
            r#"{"accountId":"{a.mailbox}","departmentId":1}"#
        ),
    )
};

#[tokio::test]
async fn contact_card_directory_members_success() {
    replay(&CONTACT_CARD_DIRECTORY_MEMBERS_SUCCESS).await;
}
#[tokio::test]
async fn contact_card_directory_members_cross_tenant() {
    replay(&CONTACT_CARD_DIRECTORY_MEMBERS_CROSS_TENANT).await;
}
#[tokio::test]
async fn contact_card_directory_members_invalid_input() {
    replay(&CONTACT_CARD_DIRECTORY_MEMBERS_INVALID_INPUT).await;
}
#[tokio::test]
async fn contact_card_directory_members_delegate_personal() {
    replay(&CONTACT_CARD_DIRECTORY_MEMBERS_DELEGATE_PERSONAL).await;
}
#[tokio::test]
async fn contact_card_directory_members_entitlement_denied() {
    replay(&CONTACT_CARD_DIRECTORY_MEMBERS_ENTITLEMENT_DENIED).await;
}
#[tokio::test]
async fn contact_card_directory_members_changed_status_mutant() {
    status_mutant(&CONTACT_CARD_DIRECTORY_MEMBERS_SUCCESS).await;
}

// ── ContactCard/directorySearch ──────────────────────────────────────────────

const CONTACT_CARD_DIRECTORY_SEARCH_SUCCESS: Case = Case {
    scrub: &[
        ("/methodResponses/0/1/list/0/email", "f.email"),
        ("/methodResponses/0/1/list/0/addresses/0/email", "f.email"),
    ],
    ..base_case(
        "contact-card-directory-search-success",
        "success",
        "ContactCard/directorySearch",
        jmap!(
            "ContactCard/directorySearch",
            r#"{"accountId":"{a.mailbox}","query":"fam-contact_card-foreign","limit":10}"#
        ),
    )
};
const CONTACT_CARD_DIRECTORY_SEARCH_CROSS_TENANT: Case = Case {
    absent: &["{f.mailbox}"],
    ..base_case(
        "contact-card-directory-search-cross-tenant",
        "cross-tenant",
        "ContactCard/directorySearch",
        jmap!(
            "ContactCard/directorySearch",
            r#"{"accountId":"{f.mailbox}","query":"fam"}"#
        ),
    )
};
const CONTACT_CARD_DIRECTORY_SEARCH_INVALID_INPUT: Case = base_case(
    "contact-card-directory-search-invalid-input",
    "invalid-input",
    "ContactCard/directorySearch",
    jmap!(
        "ContactCard/directorySearch",
        r#"{"accountId":"{a.mailbox}","query":123}"#
    ),
);
const CONTACT_CARD_DIRECTORY_SEARCH_DELEGATE_PERSONAL: Case = Case {
    seed: SEED_DELEGATE,
    ..base_case(
        "contact-card-directory-search-delegate-personal",
        "delegate-personal",
        "ContactCard/directorySearch",
        jmap!(
            "ContactCard/directorySearch",
            r#"{"accountId":"{f.mailbox}","query":"fam"}"#
        ),
    )
};
const CONTACT_CARD_DIRECTORY_SEARCH_ENTITLEMENT_DENIED: Case = Case {
    seed: SEED_DENY_ENTITLEMENT,
    ..base_case(
        "contact-card-directory-search-entitlement-denied",
        "entitlement-denied",
        "ContactCard/directorySearch",
        jmap!(
            "ContactCard/directorySearch",
            r#"{"accountId":"{a.mailbox}","query":"fam"}"#
        ),
    )
};

#[tokio::test]
async fn contact_card_directory_search_success() {
    replay(&CONTACT_CARD_DIRECTORY_SEARCH_SUCCESS).await;
}
#[tokio::test]
async fn contact_card_directory_search_cross_tenant() {
    replay(&CONTACT_CARD_DIRECTORY_SEARCH_CROSS_TENANT).await;
}
#[tokio::test]
async fn contact_card_directory_search_invalid_input() {
    replay(&CONTACT_CARD_DIRECTORY_SEARCH_INVALID_INPUT).await;
}
#[tokio::test]
async fn contact_card_directory_search_delegate_personal() {
    replay(&CONTACT_CARD_DIRECTORY_SEARCH_DELEGATE_PERSONAL).await;
}
#[tokio::test]
async fn contact_card_directory_search_entitlement_denied() {
    replay(&CONTACT_CARD_DIRECTORY_SEARCH_ENTITLEMENT_DENIED).await;
}
#[tokio::test]
async fn contact_card_directory_search_changed_status_mutant() {
    status_mutant(&CONTACT_CARD_DIRECTORY_SEARCH_SUCCESS).await;
}
