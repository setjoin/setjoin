//! #371 `Calendar/*` (7 methods including `Calendar/delegateList`) frozen-Go oracle suite.

mod common;
mod jmap_family_oracle;

use jmap_family_oracle::{run, verify_rust_journal_advances, Case, Mutation};
use setjoin_conformance::harness::{BoxError, Db};

const CALENDAR_EFFECTS: &[(&str, &str)] = &[
    (
        "calendars",
        "SELECT coalesce(jsonb_agg(jsonb_build_object(\
         'id',id,'mailbox_id',mailbox_id,'name',name,'color',color,\
         'description',description,'timezone',timezone,'is_default',is_default,\
         'is_shared',is_shared,'jmap_state',jmap_state) ORDER BY id),'[]'::jsonb)::text \
         FROM calendars WHERE mailbox_id IN ({a.mailbox},{f.mailbox})",
    ),
    (
        "calendar_acls",
        "SELECT coalesce(jsonb_agg(jsonb_build_object(\
         'calendar_id',a.calendar_id,'user_id',a.user_id,'permission',a.permission) \
         ORDER BY a.calendar_id,a.user_id),'[]'::jsonb)::text \
         FROM calendar_acls a JOIN calendars c ON c.id = a.calendar_id \
         WHERE c.mailbox_id IN ({a.mailbox},{f.mailbox})",
    ),
    (
        "entity_state",
        "SELECT coalesce(jsonb_agg(jsonb_build_object(\
         'mailbox_id',mailbox_id,'datatype',datatype,'seq',seq) \
         ORDER BY mailbox_id,datatype),'[]'::jsonb)::text \
         FROM jmap_entity_state WHERE mailbox_id IN ({a.mailbox},{f.mailbox})",
    ),
    (
        "changes_journal",
        "SELECT coalesce(jsonb_agg(jsonb_build_object(\
         'mailbox_id',mailbox_id,'datatype',datatype,'state_seq',state_seq,\
         'entity_id',entity_id,'op',op) ORDER BY mailbox_id,datatype,state_seq),'[]'::jsonb)::text \
         FROM jmap_changes_journal WHERE mailbox_id IN ({a.mailbox},{f.mailbox})",
    ),
];

/// Frozen Go (`calendar_a3.go:167`) ran `jmap_calendar_share_set` on unscoped
/// `h.pool`, so V097's trigger hit `insufficient_privilege` and swallowed the
/// `jmap_entity_state` / `jmap_changes_journal` bumps. Rust runs via
/// `ScopedExecutor` (`V097` advances both); keep `calendars` + `calendar_acls`
/// in Go comparison and assert Rust's journal bumps separately.
const CALENDAR_EFFECTS_NO_JOURNAL: &[(&str, &str)] = &[CALENDAR_EFFECTS[0], CALENDAR_EFFECTS[1]];

const DELEGATE_EFFECTS: &[(&str, &str)] = &[
    (
        "mailbox_delegates",
        "SELECT coalesce(jsonb_agg(jsonb_build_object(\
         'mailbox_id',mailbox_id,'user_id',user_id,'permission',permission) \
         ORDER BY mailbox_id,user_id,permission),'[]'::jsonb)::text \
         FROM mailbox_delegates WHERE mailbox_id IN ({a.mailbox},{f.mailbox})",
    ),
    (
        "calendars",
        "SELECT coalesce(jsonb_agg(jsonb_build_object(\
         'id',id,'mailbox_id',mailbox_id,'name',name,'jmap_state',jmap_state) \
         ORDER BY id),'[]'::jsonb)::text \
         FROM calendars WHERE mailbox_id IN ({a.mailbox},{f.mailbox})",
    ),
];

const NO_NOTIFY: &[&str] = &["calendar:{a.mailbox}", "calendar:{f.mailbox}"];

const fn call(body: &'static str) -> &'static str {
    body
}

const fn case(
    name: &'static str,
    kind: &'static str,
    method: &'static str,
    request: &'static str,
) -> Case {
    let mut c = Case::new("calendar", name, kind, method, request);
    c.effects = CALENDAR_EFFECTS;
    c
}

const fn mutator_case(
    name: &'static str,
    kind: &'static str,
    method: &'static str,
    request: &'static str,
) -> Case {
    let mut c = case(name, kind, method, request);
    c.mutator = true;
    c
}

// --- Calendar/get ---

const CALENDAR_GET_SUCCESS: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, color, description, timezone, is_default) \
         VALUES ({a.mailbox}, 'Work', '#224466', 'Work calendar', 'UTC', TRUE) RETURNING id",
        "INSERT INTO calendars (mailbox_id, name, color, description, timezone, is_default) \
         VALUES ({f.mailbox}, 'Foreign Cal', '#990000', 'Private', 'UTC', TRUE) RETURNING id",
    ],
    absent: &[],
    ..case(
        "calendar-get-success",
        "success",
        "Calendar/get",
        call(
            r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/get",{"accountId":"{a.mailbox}"},"c1"]]}"#,
        ),
    )
};

const CALENDAR_GET_IDS_NOT_FOUND: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, color, timezone, is_default) \
         VALUES ({a.mailbox}, 'Alpha', '#112233', 'UTC', TRUE) RETURNING id",
        "INSERT INTO calendars (mailbox_id, name, color, timezone, is_default) \
         VALUES ({f.mailbox}, 'Foreign', '#445566', 'UTC', TRUE) RETURNING id",
    ],
    absent: &["Foreign"],
    ..case(
        "calendar-get-ids-not-found",
        "success",
        "Calendar/get",
        call(
            r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/get",{"accountId":"{a.mailbox}","ids":["{seed.0}","{seed.1}","bad"],"properties":["id","name"]},"c1"]]}"#,
        ),
    )
};

const CALENDAR_GET_CROSS_TENANT: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({f.mailbox}, 'Foreign', TRUE) RETURNING id",
    ],
    absent: &["{seed.0}"],
    notify: NO_NOTIFY,
    ..case(
        "calendar-get-cross-tenant",
        "cross-tenant",
        "Calendar/get",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/get",{"accountId":"{f.mailbox}"},"c1"]]}"#),
    )
};

const CALENDAR_GET_INVALID_INPUT: Case = Case {
    notify: NO_NOTIFY,
    ..case(
        "calendar-get-invalid-input",
        "invalid-input",
        "Calendar/get",
        call(
            r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/get",{"accountId":"{a.mailbox}","ids":[123]},"c1"]]}"#,
        ),
    )
};

const CALENDAR_GET_DELEGATE_PERSONAL: Case = Case {
    seed: &[
        "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
         VALUES ({f.mailbox}, {a.user}, 'full_access', {f.user})",
    ],
    notify: NO_NOTIFY,
    ..case(
        "calendar-get-delegate-personal",
        "delegate-personal",
        "Calendar/get",
        call(
            r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/get",{"accountId":"{f.mailbox}"},"c1"]]}"#,
        ),
    )
};

const CALENDAR_GET_ENTITLEMENT_DENIED: Case = Case {
    seed: &[
        "INSERT INTO user_app_entitlements (user_id, app, enabled) VALUES ({a.user}, 'calendar', FALSE)",
    ],
    notify: NO_NOTIFY,
    ..case(
        "calendar-get-entitlement-denied",
        "entitlement-denied",
        "Calendar/get",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/get",{"accountId":"{a.mailbox}"},"c1"]]}"#),
    )
};

// --- Calendar/changes ---

const CALENDAR_CHANGES_SUCCESS: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Main', TRUE) RETURNING id",
        "UPDATE calendars SET name = 'Main Updated' WHERE mailbox_id = {a.mailbox}",
    ],
    ..case(
        "calendar-changes-success",
        "success",
        "Calendar/changes",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/changes",{"accountId":"{a.mailbox}","sinceState":"0"},"c1"]]}"#),
    )
};

const CALENDAR_CHANGES_STATE_MISMATCH: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Main', TRUE) RETURNING id",
    ],
    notify: NO_NOTIFY,
    ..case(
        "calendar-changes-state-mismatch",
        "state-mismatch",
        "Calendar/changes",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/changes",{"accountId":"{a.mailbox}","sinceState":"999999"},"c1"]]}"#),
    )
};

const CALENDAR_CHANGES_INVALID_INPUT: Case = Case {
    notify: NO_NOTIFY,
    ..case(
        "calendar-changes-invalid-input",
        "invalid-input",
        "Calendar/changes",
        call(
            r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/changes",{"accountId":"{a.mailbox}","sinceState":"bad"},"c1"]]}"#,
        ),
    )
};

const CALENDAR_CHANGES_CROSS_TENANT: Case = Case {
    notify: NO_NOTIFY,
    ..case(
        "calendar-changes-cross-tenant",
        "cross-tenant",
        "Calendar/changes",
        call(
            r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/changes",{"accountId":"{f.mailbox}","sinceState":"0"},"c1"]]}"#,
        ),
    )
};

const CALENDAR_CHANGES_DELEGATE_PERSONAL: Case = Case {
    seed: &[
        "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
         VALUES ({f.mailbox}, {a.user}, 'full_access', {f.user})",
    ],
    notify: NO_NOTIFY,
    ..case(
        "calendar-changes-delegate-personal",
        "delegate-personal",
        "Calendar/changes",
        call(
            r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/changes",{"accountId":"{f.mailbox}","sinceState":"0"},"c1"]]}"#,
        ),
    )
};

const CALENDAR_CHANGES_ENTITLEMENT_DENIED: Case = Case {
    seed: &[
        "INSERT INTO user_app_entitlements (user_id, app, enabled) VALUES ({a.user}, 'calendar', FALSE)",
    ],
    notify: NO_NOTIFY,
    ..case(
        "calendar-changes-entitlement-denied",
        "entitlement-denied",
        "Calendar/changes",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/changes",{"accountId":"{a.mailbox}","sinceState":"0"},"c1"]]}"#),
    )
};

// --- Calendar/set ---

const CALENDAR_SET_SUCCESS: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, color, description, timezone, is_default) \
         VALUES ({a.mailbox}, 'Original', '#000000', 'Old desc', 'UTC', TRUE) RETURNING id",
    ],
    notify: &["calendar:{a.mailbox}"],
    ..mutator_case(
        "calendar-set-success",
        "success",
        "Calendar/set",
        call(
            r##"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/set",{"accountId":"{a.mailbox}","update":{"{seed.0}":{"name":"Renamed","description":"New desc","color":"#112233","timeZone":"America/New_York"}}},"c1"]]}"##,
        ),
    )
};

const CALENDAR_SET_NO_UPDATE: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Keep', TRUE) RETURNING id",
    ],
    notify: NO_NOTIFY,
    ..mutator_case(
        "calendar-set-no-update",
        "success",
        "Calendar/set",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/set",{"accountId":"{a.mailbox}"},"c1"]]}"#),
    )
};

const CALENDAR_SET_FOREIGN_CALENDAR_NO_EFFECT: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({f.mailbox}, 'Foreign', TRUE) RETURNING id",
    ],
    notify: NO_NOTIFY,
    ..mutator_case(
        "calendar-set-foreign-calendar-no-effect",
        "success",
        "Calendar/set",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/set",{"accountId":"{a.mailbox}","update":{"{seed.0}":{"name":"Hijacked"}}},"c1"]]}"#),
    )
};

const CALENDAR_SET_REPEAT: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Initial', TRUE) RETURNING id",
    ],
    repeat: true,
    notify: &["calendar:{a.mailbox}"],
    ..mutator_case(
        "calendar-set-repeat",
        "repeat",
        "Calendar/set",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/set",{"accountId":"{a.mailbox}","update":{"{seed.0}":{"name":"Updated"}}},"c1"]]}"#),
    )
};

const CALENDAR_SET_CROSS_TENANT: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({f.mailbox}, 'Foreign', TRUE) RETURNING id",
    ],
    notify: NO_NOTIFY,
    ..mutator_case(
        "calendar-set-cross-tenant",
        "cross-tenant",
        "Calendar/set",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/set",{"accountId":"{f.mailbox}","update":{"{seed.0}":{"name":"Hijacked"}}},"c1"]]}"#),
    )
};

const CALENDAR_SET_INVALID_INPUT: Case = Case {
    notify: NO_NOTIFY,
    ..mutator_case(
        "calendar-set-invalid-input",
        "invalid-input",
        "Calendar/set",
        call(
            r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/set",{"accountId":123,"update":{}},"c1"]]}"#,
        ),
    )
};

const CALENDAR_SET_DELEGATE_PERSONAL: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({f.mailbox}, 'Foreign', TRUE) RETURNING id",
        "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
         VALUES ({f.mailbox}, {a.user}, 'full_access', {f.user})",
    ],
    notify: NO_NOTIFY,
    ..mutator_case(
        "calendar-set-delegate-personal",
        "delegate-personal",
        "Calendar/set",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/set",{"accountId":"{f.mailbox}","update":{"{seed.0}":{"name":"Delegated"}}},"c1"]]}"#),
    )
};

const CALENDAR_SET_DELEGATE_REVOKED: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({f.mailbox}, 'Foreign', TRUE) RETURNING id",
        "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
         VALUES ({f.mailbox}, {a.user}, 'full_access', {f.user})",
    ],
    between: &["DELETE FROM mailbox_delegates WHERE mailbox_id = {f.mailbox} AND user_id = {a.user}"],
    notify: NO_NOTIFY,
    ..mutator_case(
        "calendar-set-delegate-revoked",
        "delegate-revoked",
        "Calendar/set",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/set",{"accountId":"{f.mailbox}","update":{"{seed.0}":{"name":"Revoked"}}},"c1"]]}"#),
    )
};

const CALENDAR_SET_ENTITLEMENT_DENIED: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Own', TRUE) RETURNING id",
        "INSERT INTO user_app_entitlements (user_id, app, enabled) VALUES ({a.user}, 'calendar', FALSE)",
    ],
    notify: NO_NOTIFY,
    ..mutator_case(
        "calendar-set-entitlement-denied",
        "entitlement-denied",
        "Calendar/set",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/set",{"accountId":"{a.mailbox}","update":{"{seed.0}":{"name":"Blocked"}}},"c1"]]}"#),
    )
};

// --- Calendar/getShared ---

const CALENDAR_GET_SHARED_SUCCESS: Case = Case {
    seed: &[
        "UPDATE users SET email = 'foreign-' || {f.user} || '@oracle.test', \
         username = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.user}",
        "UPDATE mailboxes SET email = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.mailbox}",
        "INSERT INTO calendars (mailbox_id, name, color, description, timezone, is_default, is_shared) \
         VALUES ({f.mailbox}, 'Shared Cal', '#00aa55', 'Shared description', 'UTC', TRUE, TRUE) RETURNING id",
        "INSERT INTO calendar_acls (calendar_id, user_id, permission) VALUES ({seed.0}, {a.user}, 'read')",
    ],
    ..case(
        "calendar-get-shared-success",
        "success",
        "Calendar/getShared",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/getShared",{"accountId":"{a.mailbox}","ownerEmail":"foreign-{f.user}@oracle.test"},"c1"]]}"#),
    )
};

const CALENDAR_GET_SHARED_FOREIGN_OBJECT: Case = Case {
    seed: &[
        "UPDATE users SET email = 'foreign-' || {f.user} || '@oracle.test', \
         username = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.user}",
        "UPDATE mailboxes SET email = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.mailbox}",
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({f.mailbox}, 'Unshared Cal', TRUE) RETURNING id",
    ],
    absent: &["{seed.0}"],
    notify: NO_NOTIFY,
    ..case(
        "calendar-get-shared-foreign-object",
        "foreign-object",
        "Calendar/getShared",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/getShared",{"accountId":"{a.mailbox}","ownerEmail":"foreign-{f.user}@oracle.test"},"c1"]]}"#),
    )
};

const CALENDAR_GET_SHARED_CROSS_TENANT: Case = Case {
    seed: &[
        "UPDATE users SET email = 'foreign-' || {f.user} || '@oracle.test', \
         username = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.user}",
        "UPDATE mailboxes SET email = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.mailbox}",
    ],
    notify: NO_NOTIFY,
    ..case(
        "calendar-get-shared-cross-tenant",
        "cross-tenant",
        "Calendar/getShared",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/getShared",{"accountId":"{f.mailbox}","ownerEmail":"foreign-{f.user}@oracle.test"},"c1"]]}"#),
    )
};

const CALENDAR_GET_SHARED_INVALID_INPUT: Case = Case {
    notify: NO_NOTIFY,
    ..case(
        "calendar-get-shared-invalid-input",
        "invalid-input",
        "Calendar/getShared",
        call(
            r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/getShared",{"accountId":"{a.mailbox}"},"c1"]]}"#,
        ),
    )
};

const CALENDAR_GET_SHARED_DELEGATE_PERSONAL: Case = Case {
    seed: &[
        "UPDATE users SET email = 'foreign-' || {f.user} || '@oracle.test', \
         username = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.user}",
        "UPDATE mailboxes SET email = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.mailbox}",
        "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
         VALUES ({f.mailbox}, {a.user}, 'full_access', {f.user})",
    ],
    notify: NO_NOTIFY,
    ..case(
        "calendar-get-shared-delegate-personal",
        "delegate-personal",
        "Calendar/getShared",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/getShared",{"accountId":"{f.mailbox}","ownerEmail":"foreign-{f.user}@oracle.test"},"c1"]]}"#),
    )
};

const CALENDAR_GET_SHARED_ENTITLEMENT_DENIED: Case = Case {
    seed: &[
        "INSERT INTO user_app_entitlements (user_id, app, enabled) VALUES ({a.user}, 'calendar', FALSE)",
    ],
    notify: NO_NOTIFY,
    ..case(
        "calendar-get-shared-entitlement-denied",
        "entitlement-denied",
        "Calendar/getShared",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/getShared",{"accountId":"{a.mailbox}","ownerEmail":"nobody@oracle.invalid"},"c1"]]}"#),
    )
};

// --- Calendar/shareGet ---

const CALENDAR_SHARE_GET_SUCCESS: Case = Case {
    seed: &[
        "UPDATE users SET email = 'foreign-' || {f.user} || '@oracle.test', \
         username = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.user}",
        "UPDATE mailboxes SET email = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.mailbox}",
        "INSERT INTO calendars (mailbox_id, name, is_default, is_shared) \
         VALUES ({a.mailbox}, 'Team', TRUE, TRUE) RETURNING id",
        "INSERT INTO calendar_acls (calendar_id, user_id, permission) VALUES ({seed.0}, {f.user}, 'read')",
    ],
    ..case(
        "calendar-share-get-success",
        "success",
        "Calendar/shareGet",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/shareGet",{"accountId":"{a.mailbox}","calendarId":"{seed.0}"},"c1"]]}"#),
    )
};

const CALENDAR_SHARE_GET_FOREIGN_OBJECT: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({f.mailbox}, 'Foreign', TRUE) RETURNING id",
    ],
    notify: NO_NOTIFY,
    ..case(
        "calendar-share-get-foreign-object",
        "foreign-object",
        "Calendar/shareGet",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/shareGet",{"accountId":"{a.mailbox}","calendarId":"{seed.0}"},"c1"]]}"#),
    )
};

const CALENDAR_SHARE_GET_CROSS_TENANT: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({f.mailbox}, 'Foreign', TRUE) RETURNING id",
    ],
    notify: NO_NOTIFY,
    ..case(
        "calendar-share-get-cross-tenant",
        "cross-tenant",
        "Calendar/shareGet",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/shareGet",{"accountId":"{f.mailbox}","calendarId":"{seed.0}"},"c1"]]}"#),
    )
};

const CALENDAR_SHARE_GET_INVALID_INPUT: Case = Case {
    notify: NO_NOTIFY,
    ..case(
        "calendar-share-get-invalid-input",
        "invalid-input",
        "Calendar/shareGet",
        call(
            r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/shareGet",{"accountId":"{a.mailbox}","calendarId":"abc"},"c1"]]}"#,
        ),
    )
};

const CALENDAR_SHARE_GET_DELEGATE_PERSONAL: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({f.mailbox}, 'Foreign', TRUE) RETURNING id",
        "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
         VALUES ({f.mailbox}, {a.user}, 'full_access', {f.user})",
    ],
    notify: NO_NOTIFY,
    ..case(
        "calendar-share-get-delegate-personal",
        "delegate-personal",
        "Calendar/shareGet",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/shareGet",{"accountId":"{f.mailbox}","calendarId":"{seed.0}"},"c1"]]}"#),
    )
};

const CALENDAR_SHARE_GET_ENTITLEMENT_DENIED: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Own', TRUE) RETURNING id",
        "INSERT INTO user_app_entitlements (user_id, app, enabled) VALUES ({a.user}, 'calendar', FALSE)",
    ],
    notify: NO_NOTIFY,
    ..case(
        "calendar-share-get-entitlement-denied",
        "entitlement-denied",
        "Calendar/shareGet",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/shareGet",{"accountId":"{a.mailbox}","calendarId":"{seed.0}"},"c1"]]}"#),
    )
};

// --- Calendar/shareSet ---

const CALENDAR_SHARE_SET_SUCCESS: Case = Case {
    seed: &[
        "UPDATE users SET email = 'foreign-' || {f.user} || '@oracle.test', \
         username = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.user}",
        "UPDATE mailboxes SET email = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.mailbox}",
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Own', TRUE) RETURNING id",
    ],
    notify: &["calendar:{a.mailbox}"],
    effects: CALENDAR_EFFECTS_NO_JOURNAL,
    ..mutator_case(
        "calendar-share-set-success",
        "success",
        "Calendar/shareSet",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/shareSet",{"accountId":"{a.mailbox}","calendarId":"{seed.0}","grants":[{"userEmail":"foreign-{f.user}@oracle.test","level":"write"}]},"c1"]]}"#),
    )
};

const CALENDAR_SHARE_SET_REVOKE: Case = Case {
    seed: &[
        "UPDATE users SET email = 'foreign-' || {f.user} || '@oracle.test', \
         username = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.user}",
        "UPDATE mailboxes SET email = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.mailbox}",
        "INSERT INTO calendars (mailbox_id, name, is_default, is_shared) \
         VALUES ({a.mailbox}, 'Own', TRUE, TRUE) RETURNING id",
        "INSERT INTO calendar_acls (calendar_id, user_id, permission) VALUES ({seed.0}, {f.user}, 'read')",
    ],
    notify: &["calendar:{a.mailbox}"],
    effects: CALENDAR_EFFECTS_NO_JOURNAL,
    ..mutator_case(
        "calendar-share-set-revoke",
        "success",
        "Calendar/shareSet",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/shareSet",{"accountId":"{a.mailbox}","calendarId":"{seed.0}","revokes":[{"userEmail":"foreign-{f.user}@oracle.test"}]},"c1"]]}"#),
    )
};

const CALENDAR_SHARE_SET_ADMIN_GRANTEE: Case = Case {
    seed: &[
        "UPDATE users SET email = 'foreign-' || {f.user} || '@oracle.test', \
         username = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.user}",
        "UPDATE mailboxes SET email = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.mailbox}",
        "INSERT INTO calendars (mailbox_id, name, is_default, is_shared) \
         VALUES ({f.mailbox}, 'Managed', TRUE, TRUE) RETURNING id",
        "INSERT INTO calendar_acls (calendar_id, user_id, permission) VALUES ({seed.0}, {a.user}, 'admin')",
    ],
    notify: &["calendar:{f.mailbox}"],
    ..mutator_case(
        "calendar-share-set-admin-grantee",
        "success",
        "Calendar/shareSet",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/shareSet",{"accountId":"{a.mailbox}","calendarId":"{seed.0}","grants":[{"userEmail":"foreign-{f.user}@oracle.test","level":"read"}]},"c1"]]}"#),
    )
};

const CALENDAR_SHARE_SET_REPEAT: Case = Case {
    seed: &[
        "UPDATE users SET email = 'foreign-' || {f.user} || '@oracle.test', \
         username = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.user}",
        "UPDATE mailboxes SET email = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.mailbox}",
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Own', TRUE) RETURNING id",
    ],
    repeat: true,
    notify: &["calendar:{a.mailbox}"],
    effects: CALENDAR_EFFECTS_NO_JOURNAL,
    ..mutator_case(
        "calendar-share-set-repeat",
        "repeat",
        "Calendar/shareSet",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/shareSet",{"accountId":"{a.mailbox}","calendarId":"{seed.0}","grants":[{"userEmail":"foreign-{f.user}@oracle.test","level":"read"}]},"c1"]]}"#),
    )
};

const CALENDAR_SHARE_SET_CROSS_TENANT: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({f.mailbox}, 'Foreign', TRUE) RETURNING id",
    ],
    notify: NO_NOTIFY,
    ..mutator_case(
        "calendar-share-set-cross-tenant",
        "cross-tenant",
        "Calendar/shareSet",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/shareSet",{"accountId":"{f.mailbox}","calendarId":"{seed.0}","grants":[]},"c1"]]}"#),
    )
};

const CALENDAR_SHARE_SET_FOREIGN_OBJECT: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({f.mailbox}, 'Foreign', TRUE) RETURNING id",
    ],
    notify: NO_NOTIFY,
    ..mutator_case(
        "calendar-share-set-foreign-object",
        "foreign-object",
        "Calendar/shareSet",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/shareSet",{"accountId":"{a.mailbox}","calendarId":"{seed.0}","grants":[]},"c1"]]}"#),
    )
};

const CALENDAR_SHARE_SET_DELEGATE_INSUFFICIENT: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default, is_shared) \
         VALUES ({f.mailbox}, 'Foreign', TRUE, TRUE) RETURNING id",
        "INSERT INTO calendar_acls (calendar_id, user_id, permission) VALUES ({seed.0}, {a.user}, 'write')",
    ],
    notify: NO_NOTIFY,
    ..mutator_case(
        "calendar-share-set-delegate-insufficient",
        "delegate-insufficient",
        "Calendar/shareSet",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/shareSet",{"accountId":"{a.mailbox}","calendarId":"{seed.0}","grants":[]},"c1"]]}"#),
    )
};

const CALENDAR_SHARE_SET_DELEGATE_PERSONAL: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({f.mailbox}, 'Foreign', TRUE) RETURNING id",
        "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
         VALUES ({f.mailbox}, {a.user}, 'full_access', {f.user})",
    ],
    notify: NO_NOTIFY,
    ..mutator_case(
        "calendar-share-set-delegate-personal",
        "delegate-personal",
        "Calendar/shareSet",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/shareSet",{"accountId":"{f.mailbox}","calendarId":"{seed.0}","grants":[]},"c1"]]}"#),
    )
};

const CALENDAR_SHARE_SET_DELEGATE_REVOKED: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({f.mailbox}, 'Foreign', TRUE) RETURNING id",
        "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
         VALUES ({f.mailbox}, {a.user}, 'full_access', {f.user})",
    ],
    between: &["DELETE FROM mailbox_delegates WHERE mailbox_id = {f.mailbox} AND user_id = {a.user}"],
    notify: NO_NOTIFY,
    ..mutator_case(
        "calendar-share-set-delegate-revoked",
        "delegate-revoked",
        "Calendar/shareSet",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/shareSet",{"accountId":"{f.mailbox}","calendarId":"{seed.0}","grants":[]},"c1"]]}"#),
    )
};

const CALENDAR_SHARE_SET_INVALID_INPUT: Case = Case {
    notify: NO_NOTIFY,
    ..mutator_case(
        "calendar-share-set-invalid-input",
        "invalid-input",
        "Calendar/shareSet",
        call(
            r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/shareSet",{"accountId":"{a.mailbox}","calendarId":"abc","grants":[]},"c1"]]}"#,
        ),
    )
};

const CALENDAR_SHARE_SET_ENTITLEMENT_DENIED: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ({a.mailbox}, 'Own', TRUE) RETURNING id",
        "INSERT INTO user_app_entitlements (user_id, app, enabled) VALUES ({a.user}, 'calendar', FALSE)",
    ],
    notify: NO_NOTIFY,
    ..mutator_case(
        "calendar-share-set-entitlement-denied",
        "entitlement-denied",
        "Calendar/shareSet",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/shareSet",{"accountId":"{a.mailbox}","calendarId":"{seed.0}","grants":[]},"c1"]]}"#),
    )
};

// --- Calendar/delegateList ---

const fn delegate_case(name: &'static str, kind: &'static str, request: &'static str) -> Case {
    let mut c = Case::new("calendar", name, kind, "Calendar/delegateList", request);
    c.effects = DELEGATE_EFFECTS;
    c
}

const CALENDAR_DELEGATE_LIST_SUCCESS: Case = Case {
    seed: &[
        "UPDATE users SET email = 'foreign-' || {f.user} || '@oracle.test', \
         username = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.user}",
        "UPDATE mailboxes SET email = 'foreign-' || {f.user} || '@oracle.test' WHERE id = {f.mailbox}",
        "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
         VALUES ({f.mailbox}, {a.user}, 'manage_calendar', {f.user})",
        "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
         VALUES ({f.mailbox}, {a.user}, 'read', {f.user})",
    ],
    ..delegate_case(
        "calendar-delegate-list-success",
        "success",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/delegateList",{"accountId":"{a.mailbox}"},"c1"]]}"#),
    )
};

const CALENDAR_DELEGATE_LIST_CROSS_TENANT: Case = Case {
    notify: NO_NOTIFY,
    ..delegate_case(
        "calendar-delegate-list-cross-tenant",
        "cross-tenant",
        call(
            r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/delegateList",{"accountId":"{f.mailbox}"},"c1"]]}"#,
        ),
    )
};

const CALENDAR_DELEGATE_LIST_INVALID_INPUT: Case = Case {
    notify: NO_NOTIFY,
    ..delegate_case(
        "calendar-delegate-list-invalid-input",
        "invalid-input",
        call(
            r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/delegateList",{"accountId":123},"c1"]]}"#,
        ),
    )
};

const CALENDAR_DELEGATE_LIST_DELEGATE_PERSONAL: Case = Case {
    seed: &[
        "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
         VALUES ({f.mailbox}, {a.user}, 'full_access', {f.user})",
    ],
    notify: NO_NOTIFY,
    ..delegate_case(
        "calendar-delegate-list-delegate-personal",
        "delegate-personal",
        call(
            r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/delegateList",{"accountId":"{f.mailbox}"},"c1"]]}"#,
        ),
    )
};

const CALENDAR_DELEGATE_LIST_DELEGATE_REVOKED: Case = Case {
    seed: &[
        "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
         VALUES ({f.mailbox}, {a.user}, 'manage_calendar', {f.user})",
    ],
    between: &[
        "DELETE FROM mailbox_delegates WHERE mailbox_id = {f.mailbox} AND user_id = {a.user}",
    ],
    notify: NO_NOTIFY,
    ..delegate_case(
        "calendar-delegate-list-delegate-revoked",
        "delegate-revoked",
        call(
            r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/delegateList",{"accountId":"{f.mailbox}"},"c1"]]}"#,
        ),
    )
};

const CALENDAR_DELEGATE_LIST_ENTITLEMENT_DENIED: Case = Case {
    seed: &[
        "INSERT INTO user_app_entitlements (user_id, app, enabled) VALUES ({a.user}, 'calendar', FALSE)",
    ],
    notify: NO_NOTIFY,
    ..delegate_case(
        "calendar-delegate-list-entitlement-denied",
        "entitlement-denied",
        call(r#"{"using":["urn:ietf:params:jmap:calendars"],"methodCalls":[["Calendar/delegateList",{"accountId":"{a.mailbox}"},"c1"]]}"#),
    )
};

macro_rules! replay {
    ($name:ident, $case:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() -> Result<(), BoxError> {
            run(&$case, Mutation::None).await
        }
    };
}

macro_rules! status_mutant {
    ($name:ident, $case:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() -> Result<(), BoxError> {
            if Db::for_case(stringify!($name)).is_none() {
                return Ok(());
            }
            let diff = run(&$case, Mutation::Status)
                .await
                .expect_err("a changed status must fail the replay")
                .to_string();
            assert!(diff.contains("GOLDEN-DIFF /response/status"), "{diff}");
            println!("MUTANT-REJECTED: POST /jmap {} :: status", $case.method);
            Ok(())
        }
    };
}

// Calendar/get
replay!(calendar_get_success, CALENDAR_GET_SUCCESS);
replay!(calendar_get_ids_and_not_found, CALENDAR_GET_IDS_NOT_FOUND);
replay!(calendar_get_cross_tenant, CALENDAR_GET_CROSS_TENANT);
replay!(calendar_get_invalid_input, CALENDAR_GET_INVALID_INPUT);
replay!(
    calendar_get_delegate_personal,
    CALENDAR_GET_DELEGATE_PERSONAL
);
replay!(
    calendar_get_entitlement_denied,
    CALENDAR_GET_ENTITLEMENT_DENIED
);
status_mutant!(calendar_get_status_mutant, CALENDAR_GET_SUCCESS);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn calendar_get_no_tenant_filter_mutant() -> Result<(), BoxError> {
    run(
        &CALENDAR_GET_SUCCESS,
        Mutation::NoTenantFilter {
            function: "jmap_calendar_get(bigint,bigint[])",
            from: "c.mailbox_id = p_mailbox_id",
        },
    )
    .await
}

// Calendar/changes
replay!(calendar_changes_success, CALENDAR_CHANGES_SUCCESS);
replay!(
    calendar_changes_state_mismatch,
    CALENDAR_CHANGES_STATE_MISMATCH
);
replay!(
    calendar_changes_invalid_input,
    CALENDAR_CHANGES_INVALID_INPUT
);
replay!(calendar_changes_cross_tenant, CALENDAR_CHANGES_CROSS_TENANT);
replay!(
    calendar_changes_delegate_personal,
    CALENDAR_CHANGES_DELEGATE_PERSONAL
);
replay!(
    calendar_changes_entitlement_denied,
    CALENDAR_CHANGES_ENTITLEMENT_DENIED
);
status_mutant!(calendar_changes_status_mutant, CALENDAR_CHANGES_SUCCESS);

// Calendar/set
replay!(calendar_set_success, CALENDAR_SET_SUCCESS);
replay!(calendar_set_no_update, CALENDAR_SET_NO_UPDATE);
replay!(
    calendar_set_foreign_calendar_no_effect,
    CALENDAR_SET_FOREIGN_CALENDAR_NO_EFFECT
);
replay!(calendar_set_repeat, CALENDAR_SET_REPEAT);
replay!(calendar_set_cross_tenant, CALENDAR_SET_CROSS_TENANT);
replay!(calendar_set_invalid_input, CALENDAR_SET_INVALID_INPUT);
replay!(
    calendar_set_delegate_personal,
    CALENDAR_SET_DELEGATE_PERSONAL
);
replay!(calendar_set_delegate_revoked, CALENDAR_SET_DELEGATE_REVOKED);
replay!(
    calendar_set_entitlement_denied,
    CALENDAR_SET_ENTITLEMENT_DENIED
);
status_mutant!(calendar_set_status_mutant, CALENDAR_SET_SUCCESS);

// Calendar/getShared
replay!(calendar_get_shared_success, CALENDAR_GET_SHARED_SUCCESS);
replay!(
    calendar_get_shared_foreign_object,
    CALENDAR_GET_SHARED_FOREIGN_OBJECT
);
replay!(
    calendar_get_shared_cross_tenant,
    CALENDAR_GET_SHARED_CROSS_TENANT
);
replay!(
    calendar_get_shared_invalid_input,
    CALENDAR_GET_SHARED_INVALID_INPUT
);
replay!(
    calendar_get_shared_delegate_personal,
    CALENDAR_GET_SHARED_DELEGATE_PERSONAL
);
replay!(
    calendar_get_shared_entitlement_denied,
    CALENDAR_GET_SHARED_ENTITLEMENT_DENIED
);
status_mutant!(
    calendar_get_shared_status_mutant,
    CALENDAR_GET_SHARED_SUCCESS
);

// Calendar/shareGet
replay!(calendar_share_get_success, CALENDAR_SHARE_GET_SUCCESS);
replay!(
    calendar_share_get_foreign_object,
    CALENDAR_SHARE_GET_FOREIGN_OBJECT
);
replay!(
    calendar_share_get_cross_tenant,
    CALENDAR_SHARE_GET_CROSS_TENANT
);
replay!(
    calendar_share_get_invalid_input,
    CALENDAR_SHARE_GET_INVALID_INPUT
);
replay!(
    calendar_share_get_delegate_personal,
    CALENDAR_SHARE_GET_DELEGATE_PERSONAL
);
replay!(
    calendar_share_get_entitlement_denied,
    CALENDAR_SHARE_GET_ENTITLEMENT_DENIED
);
status_mutant!(calendar_share_get_status_mutant, CALENDAR_SHARE_GET_SUCCESS);

// Calendar/shareSet
replay!(calendar_share_set_success, CALENDAR_SHARE_SET_SUCCESS);
replay!(calendar_share_set_revoke, CALENDAR_SHARE_SET_REVOKE);
replay!(
    calendar_share_set_admin_grantee,
    CALENDAR_SHARE_SET_ADMIN_GRANTEE
);
replay!(calendar_share_set_repeat, CALENDAR_SHARE_SET_REPEAT);
replay!(
    calendar_share_set_cross_tenant,
    CALENDAR_SHARE_SET_CROSS_TENANT
);
replay!(
    calendar_share_set_foreign_object,
    CALENDAR_SHARE_SET_FOREIGN_OBJECT
);
replay!(
    calendar_share_set_delegate_insufficient,
    CALENDAR_SHARE_SET_DELEGATE_INSUFFICIENT
);
replay!(
    calendar_share_set_delegate_personal,
    CALENDAR_SHARE_SET_DELEGATE_PERSONAL
);
replay!(
    calendar_share_set_delegate_revoked,
    CALENDAR_SHARE_SET_DELEGATE_REVOKED
);
replay!(
    calendar_share_set_invalid_input,
    CALENDAR_SHARE_SET_INVALID_INPUT
);
replay!(
    calendar_share_set_entitlement_denied,
    CALENDAR_SHARE_SET_ENTITLEMENT_DENIED
);
status_mutant!(calendar_share_set_status_mutant, CALENDAR_SHARE_SET_SUCCESS);

// Calendar/delegateList
replay!(
    calendar_delegate_list_success,
    CALENDAR_DELEGATE_LIST_SUCCESS
);
replay!(
    calendar_delegate_list_cross_tenant,
    CALENDAR_DELEGATE_LIST_CROSS_TENANT
);
replay!(
    calendar_delegate_list_invalid_input,
    CALENDAR_DELEGATE_LIST_INVALID_INPUT
);
replay!(
    calendar_delegate_list_delegate_personal,
    CALENDAR_DELEGATE_LIST_DELEGATE_PERSONAL
);
replay!(
    calendar_delegate_list_delegate_revoked,
    CALENDAR_DELEGATE_LIST_DELEGATE_REVOKED
);
replay!(
    calendar_delegate_list_entitlement_denied,
    CALENDAR_DELEGATE_LIST_ENTITLEMENT_DENIED
);
status_mutant!(
    calendar_delegate_list_status_mutant,
    CALENDAR_DELEGATE_LIST_SUCCESS
);

#[tokio::test]
async fn calendar_share_set_advances_rust_journal() {
    verify_rust_journal_advances(&CALENDAR_SHARE_SET_SUCCESS, &["Calendar"])
        .await
        .unwrap();
}
