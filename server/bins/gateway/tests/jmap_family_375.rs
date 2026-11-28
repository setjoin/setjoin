//! Frozen-Go parity oracle for #375 (`AddressBook/*` and `ContactGroup/*`, 7 methods).
use crate::jmap_family_oracle;

use jmap_family_oracle::{run, Case, Mutation};

const FAMILY: &str = "address_book";

const ADDRESS_BOOK_EFFECTS: &[(&str, &str)] = &[
    (
        "addressbooks",
        "SELECT coalesce(jsonb_agg(jsonb_build_object('id',id,'mailbox_id',mailbox_id,'name',name,'description',description,'is_default',is_default,'is_shared',is_shared,'jmap_state',jmap_state) ORDER BY id),'[]'::jsonb)::text FROM addressbooks WHERE mailbox_id IN ({a.mailbox},{f.mailbox})",
    ),
    (
        "contact_groups",
        "SELECT coalesce(jsonb_agg(jsonb_build_object('id',id,'mailbox_id',mailbox_id,'name',name,'jmap_state',jmap_state) ORDER BY id),'[]'::jsonb)::text FROM contact_groups WHERE mailbox_id IN ({a.mailbox},{f.mailbox})",
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
        effects: ADDRESS_BOOK_EFFECTS,
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

// ── AddressBook/get ──────────────────────────────────────────────────────────

const ADDRESS_BOOK_GET_SUCCESS: Case = Case {
    seed: &[
        "INSERT INTO addressbooks (mailbox_id, name, description, is_default) VALUES ({a.mailbox}, 'Contacts', 'Main', TRUE) RETURNING id",
        "INSERT INTO addressbooks (mailbox_id, name, description, is_default) VALUES ({f.mailbox}, 'Foreign Book', 'Hidden', TRUE) RETURNING id",
    ],
    ..base_case(
        "address-book-get-success",
        "success",
        "AddressBook/get",
        jmap!("AddressBook/get", r#"{"accountId":"{a.mailbox}","ids":null}"#),
    )
};
const ADDRESS_BOOK_GET_CROSS_TENANT: Case = Case {
    absent: &["{f.mailbox}"],
    ..base_case(
        "address-book-get-cross-tenant",
        "cross-tenant",
        "AddressBook/get",
        jmap!("AddressBook/get", r#"{"accountId":"{f.mailbox}"}"#),
    )
};
const ADDRESS_BOOK_GET_INVALID_INPUT: Case = base_case(
    "address-book-get-invalid-input",
    "invalid-input",
    "AddressBook/get",
    jmap!(
        "AddressBook/get",
        r#"{"accountId":"{a.mailbox}","ids":[1]}"#
    ),
);
const ADDRESS_BOOK_GET_DELEGATE_PERSONAL: Case = Case {
    seed: SEED_DELEGATE,
    ..base_case(
        "address-book-get-delegate-personal",
        "delegate-personal",
        "AddressBook/get",
        jmap!("AddressBook/get", r#"{"accountId":"{f.mailbox}"}"#),
    )
};
const ADDRESS_BOOK_GET_ENTITLEMENT_DENIED: Case = Case {
    seed: SEED_DENY_ENTITLEMENT,
    ..base_case(
        "address-book-get-entitlement-denied",
        "entitlement-denied",
        "AddressBook/get",
        jmap!("AddressBook/get", r#"{"accountId":"{a.mailbox}"}"#),
    )
};

#[tokio::test]
async fn address_book_get_success() {
    replay(&ADDRESS_BOOK_GET_SUCCESS).await;
}
#[tokio::test]
async fn address_book_get_cross_tenant() {
    replay(&ADDRESS_BOOK_GET_CROSS_TENANT).await;
}
#[tokio::test]
async fn address_book_get_invalid_input() {
    replay(&ADDRESS_BOOK_GET_INVALID_INPUT).await;
}
#[tokio::test]
async fn address_book_get_delegate_personal() {
    replay(&ADDRESS_BOOK_GET_DELEGATE_PERSONAL).await;
}
#[tokio::test]
async fn address_book_get_entitlement_denied() {
    replay(&ADDRESS_BOOK_GET_ENTITLEMENT_DENIED).await;
}
#[tokio::test]
async fn address_book_get_changed_status_mutant() {
    status_mutant(&ADDRESS_BOOK_GET_SUCCESS).await;
}
#[tokio::test]
async fn address_book_get_no_tenant_filter_mutant() {
    run(
        &ADDRESS_BOOK_GET_SUCCESS,
        Mutation::NoTenantFilter {
            function: "jmap_addressbook_get(bigint,bigint[])",
            from: "ab.mailbox_id = p_mailbox_id",
        },
    )
    .await
    .expect("no-tenant-filter mutant must be rejected");
}

// ── AddressBook/changes ──────────────────────────────────────────────────────

const ADDRESS_BOOK_CHANGES_SUCCESS: Case = Case {
    seed: &[
        "INSERT INTO addressbooks (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Contacts', TRUE) RETURNING id",
    ],
    ..base_case(
        "address-book-changes-success",
        "success",
        "AddressBook/changes",
        jmap!(
            "AddressBook/changes",
            r#"{"accountId":"{a.mailbox}","sinceState":"0"}"#
        ),
    )
};
const ADDRESS_BOOK_CHANGES_CROSS_TENANT: Case = Case {
    absent: &["{f.mailbox}"],
    ..base_case(
        "address-book-changes-cross-tenant",
        "cross-tenant",
        "AddressBook/changes",
        jmap!(
            "AddressBook/changes",
            r#"{"accountId":"{f.mailbox}","sinceState":"0"}"#
        ),
    )
};
const ADDRESS_BOOK_CHANGES_INVALID_INPUT: Case = base_case(
    "address-book-changes-invalid-input",
    "invalid-input",
    "AddressBook/changes",
    jmap!(
        "AddressBook/changes",
        r#"{"accountId":"{a.mailbox}","sinceState":"bad"}"#
    ),
);
const ADDRESS_BOOK_CHANGES_DELEGATE_PERSONAL: Case = Case {
    seed: SEED_DELEGATE,
    ..base_case(
        "address-book-changes-delegate-personal",
        "delegate-personal",
        "AddressBook/changes",
        jmap!(
            "AddressBook/changes",
            r#"{"accountId":"{f.mailbox}","sinceState":"0"}"#
        ),
    )
};
const ADDRESS_BOOK_CHANGES_ENTITLEMENT_DENIED: Case = Case {
    seed: SEED_DENY_ENTITLEMENT,
    ..base_case(
        "address-book-changes-entitlement-denied",
        "entitlement-denied",
        "AddressBook/changes",
        jmap!(
            "AddressBook/changes",
            r#"{"accountId":"{a.mailbox}","sinceState":"0"}"#
        ),
    )
};
const ADDRESS_BOOK_CHANGES_STATE_MISMATCH: Case = Case {
    seed: &[
        "INSERT INTO addressbooks (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Contacts', TRUE) RETURNING id",
    ],
    ..base_case(
        "address-book-changes-state-mismatch",
        "state-mismatch",
        "AddressBook/changes",
        jmap!(
            "AddressBook/changes",
            r#"{"accountId":"{a.mailbox}","sinceState":"999"}"#
        ),
    )
};

#[tokio::test]
async fn address_book_changes_success() {
    replay(&ADDRESS_BOOK_CHANGES_SUCCESS).await;
}
#[tokio::test]
async fn address_book_changes_cross_tenant() {
    replay(&ADDRESS_BOOK_CHANGES_CROSS_TENANT).await;
}
#[tokio::test]
async fn address_book_changes_invalid_input() {
    replay(&ADDRESS_BOOK_CHANGES_INVALID_INPUT).await;
}
#[tokio::test]
async fn address_book_changes_delegate_personal() {
    replay(&ADDRESS_BOOK_CHANGES_DELEGATE_PERSONAL).await;
}
#[tokio::test]
async fn address_book_changes_entitlement_denied() {
    replay(&ADDRESS_BOOK_CHANGES_ENTITLEMENT_DENIED).await;
}
#[tokio::test]
async fn address_book_changes_state_mismatch() {
    replay(&ADDRESS_BOOK_CHANGES_STATE_MISMATCH).await;
}
#[tokio::test]
async fn address_book_changes_changed_status_mutant() {
    status_mutant(&ADDRESS_BOOK_CHANGES_SUCCESS).await;
}

// ── AddressBook/set ──────────────────────────────────────────────────────────

const ADDRESS_BOOK_SET_SUCCESS: Case = Case {
    mutator: true,
    seed: &[
        "INSERT INTO addressbooks (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Default', TRUE) RETURNING id",
    ],
    scrub: &[("/methodResponses/0/1/created/k1/id", "created.k1")],
    ..base_case(
        "address-book-set-success",
        "success",
        "AddressBook/set",
        jmap!(
            "AddressBook/set",
            r#"{"accountId":"{a.mailbox}","create":{"k1":{"name":"Work Book","description":"Team"}}}"#
        ),
    )
};
const ADDRESS_BOOK_SET_CROSS_TENANT: Case = Case {
    mutator: true,
    absent: &["{f.mailbox}"],
    ..base_case(
        "address-book-set-cross-tenant",
        "cross-tenant",
        "AddressBook/set",
        jmap!("AddressBook/set", r#"{"accountId":"{f.mailbox}"}"#),
    )
};
const ADDRESS_BOOK_SET_INVALID_INPUT: Case = Case {
    mutator: true,
    ..base_case(
        "address-book-set-invalid-input",
        "invalid-input",
        "AddressBook/set",
        jmap!(
            "AddressBook/set",
            r#"{"accountId":"{a.mailbox}","destroy":[1]}"#
        ),
    )
};
const ADDRESS_BOOK_SET_DELEGATE_PERSONAL: Case = Case {
    mutator: true,
    seed: SEED_DELEGATE,
    ..base_case(
        "address-book-set-delegate-personal",
        "delegate-personal",
        "AddressBook/set",
        jmap!("AddressBook/set", r#"{"accountId":"{f.mailbox}"}"#),
    )
};
const ADDRESS_BOOK_SET_ENTITLEMENT_DENIED: Case = Case {
    mutator: true,
    seed: SEED_DENY_ENTITLEMENT,
    ..base_case(
        "address-book-set-entitlement-denied",
        "entitlement-denied",
        "AddressBook/set",
        jmap!("AddressBook/set", r#"{"accountId":"{a.mailbox}"}"#),
    )
};
const ADDRESS_BOOK_SET_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    seed: &[
        "INSERT INTO addressbooks (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Default', TRUE) RETURNING id",
    ],
    scrub: &[("/methodResponses/0/1/created/k1/id", "created.k1")],
    ..base_case(
        "address-book-set-repeat",
        "repeat",
        "AddressBook/set",
        jmap!(
            "AddressBook/set",
            r#"{"accountId":"{a.mailbox}","create":{"k1":{"name":"Repeat Book"}}}"#
        ),
    )
};

#[tokio::test]
async fn address_book_set_success() {
    replay(&ADDRESS_BOOK_SET_SUCCESS).await;
}
#[tokio::test]
async fn address_book_set_cross_tenant() {
    replay(&ADDRESS_BOOK_SET_CROSS_TENANT).await;
}
#[tokio::test]
async fn address_book_set_invalid_input() {
    replay(&ADDRESS_BOOK_SET_INVALID_INPUT).await;
}
#[tokio::test]
async fn address_book_set_delegate_personal() {
    replay(&ADDRESS_BOOK_SET_DELEGATE_PERSONAL).await;
}
#[tokio::test]
async fn address_book_set_entitlement_denied() {
    replay(&ADDRESS_BOOK_SET_ENTITLEMENT_DENIED).await;
}
#[tokio::test]
async fn address_book_set_repeat() {
    replay(&ADDRESS_BOOK_SET_REPEAT).await;
}
#[tokio::test]
async fn address_book_set_changed_status_mutant() {
    status_mutant(&ADDRESS_BOOK_SET_SUCCESS).await;
}

// ── ContactGroup/get ─────────────────────────────────────────────────────────

const CONTACT_GROUP_GET_SUCCESS: Case = Case {
    seed: &[
        "INSERT INTO addressbooks (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Contacts', TRUE) RETURNING id",
        "INSERT INTO contacts (addressbook_id, vcard_uid, display_name, emails) VALUES ({seed.0}, 'uid-cg1', 'Alice Group', '[{\"type\":\"work\",\"address\":\"alice@example.test\",\"is_primary\":true}]'::jsonb) RETURNING id",
        "INSERT INTO contact_groups (mailbox_id, name) VALUES ({a.mailbox}, 'Team') RETURNING id",
        "INSERT INTO contact_group_members (group_id, contact_id) VALUES ({seed.2}, {seed.1}) RETURNING id",
        "INSERT INTO contact_groups (mailbox_id, name) VALUES ({f.mailbox}, 'Foreign Team') RETURNING id",
    ],
    ..base_case(
        "contact-group-get-success",
        "success",
        "ContactGroup/get",
        jmap!(
            "ContactGroup/get",
            r#"{"accountId":"{a.mailbox}","ids":["{seed.2}","{seed.4}","bad"]}"#
        ),
    )
};
const CONTACT_GROUP_GET_CROSS_TENANT: Case = Case {
    absent: &["{f.mailbox}"],
    ..base_case(
        "contact-group-get-cross-tenant",
        "cross-tenant",
        "ContactGroup/get",
        jmap!("ContactGroup/get", r#"{"accountId":"{f.mailbox}"}"#),
    )
};
const CONTACT_GROUP_GET_INVALID_INPUT: Case = base_case(
    "contact-group-get-invalid-input",
    "invalid-input",
    "ContactGroup/get",
    jmap!("ContactGroup/get", r#"{"accountId":123}"#),
);
const CONTACT_GROUP_GET_DELEGATE_PERSONAL: Case = Case {
    seed: SEED_DELEGATE,
    ..base_case(
        "contact-group-get-delegate-personal",
        "delegate-personal",
        "ContactGroup/get",
        jmap!("ContactGroup/get", r#"{"accountId":"{f.mailbox}"}"#),
    )
};
const CONTACT_GROUP_GET_ENTITLEMENT_DENIED: Case = Case {
    seed: SEED_DENY_ENTITLEMENT,
    ..base_case(
        "contact-group-get-entitlement-denied",
        "entitlement-denied",
        "ContactGroup/get",
        jmap!("ContactGroup/get", r#"{"accountId":"{a.mailbox}"}"#),
    )
};

#[tokio::test]
async fn contact_group_get_success() {
    replay(&CONTACT_GROUP_GET_SUCCESS).await;
}
#[tokio::test]
async fn contact_group_get_cross_tenant() {
    replay(&CONTACT_GROUP_GET_CROSS_TENANT).await;
}
#[tokio::test]
async fn contact_group_get_invalid_input() {
    replay(&CONTACT_GROUP_GET_INVALID_INPUT).await;
}
#[tokio::test]
async fn contact_group_get_delegate_personal() {
    replay(&CONTACT_GROUP_GET_DELEGATE_PERSONAL).await;
}
#[tokio::test]
async fn contact_group_get_entitlement_denied() {
    replay(&CONTACT_GROUP_GET_ENTITLEMENT_DENIED).await;
}
#[tokio::test]
async fn contact_group_get_changed_status_mutant() {
    status_mutant(&CONTACT_GROUP_GET_SUCCESS).await;
}

// ── ContactGroup/query ───────────────────────────────────────────────────────

const CONTACT_GROUP_QUERY_SUCCESS: Case = Case {
    seed: &[
        "INSERT INTO contact_groups (mailbox_id, name) VALUES ({a.mailbox}, 'Alpha') RETURNING id",
        "INSERT INTO contact_groups (mailbox_id, name) VALUES ({a.mailbox}, 'Beta') RETURNING id",
        "INSERT INTO contact_groups (mailbox_id, name) VALUES ({f.mailbox}, 'Alpha Foreign') RETURNING id",
    ],
    ..base_case(
        "contact-group-query-success",
        "success",
        "ContactGroup/query",
        jmap!(
            "ContactGroup/query",
            r#"{"accountId":"{a.mailbox}","filter":{"text":"alp"}}"#
        ),
    )
};
const CONTACT_GROUP_QUERY_CROSS_TENANT: Case = Case {
    absent: &["{f.mailbox}"],
    ..base_case(
        "contact-group-query-cross-tenant",
        "cross-tenant",
        "ContactGroup/query",
        jmap!("ContactGroup/query", r#"{"accountId":"{f.mailbox}"}"#),
    )
};
const CONTACT_GROUP_QUERY_INVALID_INPUT: Case = base_case(
    "contact-group-query-invalid-input",
    "invalid-input",
    "ContactGroup/query",
    jmap!("ContactGroup/query", r#"{"accountId":false}"#),
);
const CONTACT_GROUP_QUERY_DELEGATE_PERSONAL: Case = Case {
    seed: SEED_DELEGATE,
    ..base_case(
        "contact-group-query-delegate-personal",
        "delegate-personal",
        "ContactGroup/query",
        jmap!("ContactGroup/query", r#"{"accountId":"{f.mailbox}"}"#),
    )
};
const CONTACT_GROUP_QUERY_ENTITLEMENT_DENIED: Case = Case {
    seed: SEED_DENY_ENTITLEMENT,
    ..base_case(
        "contact-group-query-entitlement-denied",
        "entitlement-denied",
        "ContactGroup/query",
        jmap!("ContactGroup/query", r#"{"accountId":"{a.mailbox}"}"#),
    )
};

#[tokio::test]
async fn contact_group_query_success() {
    replay(&CONTACT_GROUP_QUERY_SUCCESS).await;
}
#[tokio::test]
async fn contact_group_query_cross_tenant() {
    replay(&CONTACT_GROUP_QUERY_CROSS_TENANT).await;
}
#[tokio::test]
async fn contact_group_query_invalid_input() {
    replay(&CONTACT_GROUP_QUERY_INVALID_INPUT).await;
}
#[tokio::test]
async fn contact_group_query_delegate_personal() {
    replay(&CONTACT_GROUP_QUERY_DELEGATE_PERSONAL).await;
}
#[tokio::test]
async fn contact_group_query_entitlement_denied() {
    replay(&CONTACT_GROUP_QUERY_ENTITLEMENT_DENIED).await;
}
#[tokio::test]
async fn contact_group_query_changed_status_mutant() {
    status_mutant(&CONTACT_GROUP_QUERY_SUCCESS).await;
}

// ── ContactGroup/set ─────────────────────────────────────────────────────────

const CONTACT_GROUP_SET_SUCCESS: Case = Case {
    mutator: true,
    seed: &[
        "INSERT INTO addressbooks (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Contacts', TRUE) RETURNING id",
        "INSERT INTO contacts (addressbook_id, vcard_uid, display_name, emails) VALUES ({seed.0}, 'uid-gs1', 'Bob Member', '[{\"type\":\"work\",\"address\":\"bob@example.test\",\"is_primary\":true}]'::jsonb) RETURNING id",
        "INSERT INTO contact_groups (mailbox_id, name) VALUES ({a.mailbox}, 'Team Old') RETURNING id",
    ],
    notify: NOTIFY_CONTACT,
    ..base_case(
        "contact-group-set-success",
        "success",
        "ContactGroup/set",
        jmap!(
            "ContactGroup/set",
            r#"{"accountId":"{a.mailbox}","update":{"{seed.2}":{"name":"Team Renamed"}},"members":{"groupId":"{seed.2}","add":[{"contactId":"{seed.1}"},{"email":"free@example.test"}],"remove":[]}}"#
        ),
    )
};
const CONTACT_GROUP_SET_CROSS_TENANT: Case = Case {
    mutator: true,
    notify: NOTIFY_CONTACT,
    absent: &["{f.mailbox}"],
    ..base_case(
        "contact-group-set-cross-tenant",
        "cross-tenant",
        "ContactGroup/set",
        jmap!("ContactGroup/set", r#"{"accountId":"{f.mailbox}"}"#),
    )
};
const CONTACT_GROUP_SET_INVALID_INPUT: Case = Case {
    mutator: true,
    notify: NOTIFY_CONTACT,
    ..base_case(
        "contact-group-set-invalid-input",
        "invalid-input",
        "ContactGroup/set",
        jmap!(
            "ContactGroup/set",
            r#"{"accountId":"{a.mailbox}","members":{"groupId":"bad","add":[{"email":"a@b.test"}]}}"#
        ),
    )
};
const CONTACT_GROUP_SET_DELEGATE_PERSONAL: Case = Case {
    mutator: true,
    seed: SEED_DELEGATE,
    notify: NOTIFY_CONTACT,
    ..base_case(
        "contact-group-set-delegate-personal",
        "delegate-personal",
        "ContactGroup/set",
        jmap!("ContactGroup/set", r#"{"accountId":"{f.mailbox}"}"#),
    )
};
const CONTACT_GROUP_SET_ENTITLEMENT_DENIED: Case = Case {
    mutator: true,
    seed: SEED_DENY_ENTITLEMENT,
    notify: NOTIFY_CONTACT,
    ..base_case(
        "contact-group-set-entitlement-denied",
        "entitlement-denied",
        "ContactGroup/set",
        jmap!("ContactGroup/set", r#"{"accountId":"{a.mailbox}"}"#),
    )
};
const CONTACT_GROUP_SET_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    seed: &[
        "INSERT INTO addressbooks (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Contacts', TRUE) RETURNING id",
    ],
    scrub: &[("/methodResponses/0/1/created/k1/id", "created.k1")],
    notify: NOTIFY_CONTACT,
    ..base_case(
        "contact-group-set-repeat",
        "repeat",
        "ContactGroup/set",
        jmap!(
            "ContactGroup/set",
            r#"{"accountId":"{a.mailbox}","create":{"k1":{"name":"Repeat Group"}}}"#
        ),
    )
};

#[tokio::test]
async fn contact_group_set_success() {
    replay(&CONTACT_GROUP_SET_SUCCESS).await;
}
#[tokio::test]
async fn contact_group_set_cross_tenant() {
    replay(&CONTACT_GROUP_SET_CROSS_TENANT).await;
}
#[tokio::test]
async fn contact_group_set_invalid_input() {
    replay(&CONTACT_GROUP_SET_INVALID_INPUT).await;
}
#[tokio::test]
async fn contact_group_set_delegate_personal() {
    replay(&CONTACT_GROUP_SET_DELEGATE_PERSONAL).await;
}
#[tokio::test]
async fn contact_group_set_entitlement_denied() {
    replay(&CONTACT_GROUP_SET_ENTITLEMENT_DENIED).await;
}
#[tokio::test]
async fn contact_group_set_repeat() {
    replay(&CONTACT_GROUP_SET_REPEAT).await;
}
#[tokio::test]
async fn contact_group_set_changed_status_mutant() {
    status_mutant(&CONTACT_GROUP_SET_SUCCESS).await;
}

// ── ContactGroup/expand ──────────────────────────────────────────────────────

const CONTACT_GROUP_EXPAND_SUCCESS: Case = Case {
    seed: &[
        "INSERT INTO addressbooks (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Contacts', TRUE) RETURNING id",
        "INSERT INTO contacts (addressbook_id, vcard_uid, display_name, emails) VALUES ({seed.0}, 'uid-ex1', 'Alice Expand', '[{\"type\":\"work\",\"address\":\"alice@example.test\",\"is_primary\":true}]'::jsonb) RETURNING id",
        "INSERT INTO contact_groups (mailbox_id, name) VALUES ({a.mailbox}, 'Expand Team') RETURNING id",
        "INSERT INTO contact_group_members (group_id, contact_id) VALUES ({seed.2}, {seed.1})",
        "INSERT INTO contact_group_members (group_id, email) VALUES ({seed.2}, 'guest@example.test')",
    ],
    ..base_case(
        "contact-group-expand-success",
        "success",
        "ContactGroup/expand",
        jmap!(
            "ContactGroup/expand",
            r#"{"accountId":"{a.mailbox}","groupId":"{seed.2}"}"#
        ),
    )
};
const CONTACT_GROUP_EXPAND_CROSS_TENANT: Case = Case {
    absent: &["{f.mailbox}"],
    ..base_case(
        "contact-group-expand-cross-tenant",
        "cross-tenant",
        "ContactGroup/expand",
        jmap!(
            "ContactGroup/expand",
            r#"{"accountId":"{f.mailbox}","groupId":"1"}"#
        ),
    )
};
const CONTACT_GROUP_EXPAND_INVALID_INPUT: Case = base_case(
    "contact-group-expand-invalid-input",
    "invalid-input",
    "ContactGroup/expand",
    jmap!(
        "ContactGroup/expand",
        r#"{"accountId":"{a.mailbox}","groupId":"not-an-id"}"#
    ),
);
const CONTACT_GROUP_EXPAND_DELEGATE_PERSONAL: Case = Case {
    seed: SEED_DELEGATE,
    ..base_case(
        "contact-group-expand-delegate-personal",
        "delegate-personal",
        "ContactGroup/expand",
        jmap!(
            "ContactGroup/expand",
            r#"{"accountId":"{f.mailbox}","groupId":"1"}"#
        ),
    )
};
const CONTACT_GROUP_EXPAND_ENTITLEMENT_DENIED: Case = Case {
    seed: SEED_DENY_ENTITLEMENT,
    ..base_case(
        "contact-group-expand-entitlement-denied",
        "entitlement-denied",
        "ContactGroup/expand",
        jmap!(
            "ContactGroup/expand",
            r#"{"accountId":"{a.mailbox}","groupId":"1"}"#
        ),
    )
};

#[tokio::test]
async fn contact_group_expand_success() {
    replay(&CONTACT_GROUP_EXPAND_SUCCESS).await;
}
#[tokio::test]
async fn contact_group_expand_cross_tenant() {
    replay(&CONTACT_GROUP_EXPAND_CROSS_TENANT).await;
}
#[tokio::test]
async fn contact_group_expand_invalid_input() {
    replay(&CONTACT_GROUP_EXPAND_INVALID_INPUT).await;
}
#[tokio::test]
async fn contact_group_expand_delegate_personal() {
    replay(&CONTACT_GROUP_EXPAND_DELEGATE_PERSONAL).await;
}
#[tokio::test]
async fn contact_group_expand_entitlement_denied() {
    replay(&CONTACT_GROUP_EXPAND_ENTITLEMENT_DENIED).await;
}
#[tokio::test]
async fn contact_group_expand_changed_status_mutant() {
    status_mutant(&CONTACT_GROUP_EXPAND_SUCCESS).await;
}
