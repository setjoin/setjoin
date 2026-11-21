//! #369: JMAP CalendarEvent/* (13 methods) recorded Go-parity oracle and mutants.
#[allow(dead_code, unused_imports)]
mod common;
#[allow(dead_code, unused_imports)]
mod jmap_family_oracle;

use jmap_family_oracle::{run, Case, Mutation};
use serde_json::Value;
use setjoin_conformance::harness::BoxError;

const CAP_CALENDARS: &str = "urn:ietf:params:jmap:calendars";

const EFFECT_CALENDARS: (&str, &str) = (
    "calendars",
    "SELECT COALESCE(jsonb_agg((to_jsonb(c) - 'created_at' - 'updated_at') ORDER BY c.id), '[]'::jsonb)::text \
     FROM calendars c WHERE c.mailbox_id IN ({a.mailbox},{f.mailbox})",
);

const EFFECT_EVENTS: (&str, &str) = (
    "calendar_events",
    "SELECT COALESCE(jsonb_agg( \
       CASE WHEN ce.organizer_email IS NOT NULL \
            THEN jsonb_set(to_jsonb(ce) - 'created_at' - 'updated_at' - 'etag', '{organizer_email}', to_jsonb(regexp_replace(ce.organizer_email, 'oracle-[0-9a-f]+\\.test', 'oracle.test'))) \
            ELSE to_jsonb(ce) - 'created_at' - 'updated_at' - 'etag' \
       END ORDER BY ce.id), '[]'::jsonb)::text \
     FROM calendar_events ce JOIN calendars c ON c.id = ce.calendar_id \
     WHERE c.mailbox_id IN ({a.mailbox},{f.mailbox})",
);

const EFFECT_EVENTS_NO_ID: (&str, &str) = (
    "calendar_events",
    "SELECT COALESCE(jsonb_agg( \
       CASE WHEN ce.organizer_email IS NOT NULL \
            THEN jsonb_set(to_jsonb(ce) - 'id' - 'uid' - 'created_at' - 'updated_at' - 'etag', '{organizer_email}', to_jsonb(regexp_replace(ce.organizer_email, 'oracle-[0-9a-f]+\\.test', 'oracle.test'))) \
            ELSE to_jsonb(ce) - 'id' - 'uid' - 'created_at' - 'updated_at' - 'etag' \
       END ORDER BY ce.calendar_id, ce.start_at, ce.title), '[]'::jsonb)::text \
     FROM calendar_events ce JOIN calendars c ON c.id = ce.calendar_id \
     WHERE c.mailbox_id IN ({a.mailbox},{f.mailbox})",
);

const EFFECT_ATTENDEES: (&str, &str) = (
    "event_attendees",
    "SELECT COALESCE(jsonb_agg( \
       jsonb_set(to_jsonb(ea) - 'id', '{email}', to_jsonb(regexp_replace(ea.email, 'oracle-[0-9a-f]+\\.test', 'oracle.test'))) \
       ORDER BY ea.event_id, regexp_replace(ea.email, 'oracle-[0-9a-f]+\\.test', 'oracle.test')), '[]'::jsonb)::text \
     FROM event_attendees ea JOIN calendar_events ce ON ce.id = ea.event_id \
     JOIN calendars c ON c.id = ce.calendar_id WHERE c.mailbox_id IN ({a.mailbox},{f.mailbox})",
);

const EFFECT_ENTITY_STATE: (&str, &str) = (
    "entity_state",
    "SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY s.datatype), '[]'::jsonb)::text \
     FROM jmap_entity_state s WHERE s.mailbox_id IN ({a.mailbox},{f.mailbox})",
);

const SEED_OWN_CALENDAR: &str =
    "INSERT INTO calendars (mailbox_id, name, timezone, is_default) VALUES ({a.mailbox}, 'Own Cal', 'UTC', true) RETURNING id";

const SEED_FOREIGN_CALENDAR: &str =
    "INSERT INTO calendars (mailbox_id, name, timezone, is_default) VALUES ({f.mailbox}, 'Foreign Cal', 'UTC', true) RETURNING id";

const SEED_OWN_EVENT: &str =
    "INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, status) \
     VALUES ({seed.0}, 'uid-own-1', 'Own event', '2026-11-22T10:00:00Z'::timestamptz, '2026-11-22T11:00:00Z'::timestamptz, 'confirmed') RETURNING id";

const SEED_FOREIGN_EVENT_ON_CAL1: &str =
    "INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, status) \
     VALUES ({seed.1}, 'uid-foreign-1', 'Foreign event', '2026-11-22T18:00:00Z'::timestamptz, '2026-11-22T19:00:00Z'::timestamptz, 'confirmed') RETURNING id";

const SEED_FOREIGN_EVENT_ON_CAL2: &str =
    "INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, status) \
     VALUES ({seed.2}, 'uid-foreign-2', 'Foreign event', '2026-11-22T18:00:00Z'::timestamptz, '2026-11-22T19:00:00Z'::timestamptz, 'confirmed') RETURNING id";

const SEED_DELEGATE_FULL: &str =
    "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
     VALUES ({f.mailbox}, {a.user}, 'full_access', {f.user})";

const SEED_DELEGATE_CALENDAR: &str =
    "INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by) \
     VALUES ({f.mailbox}, {a.user}, 'manage_calendar', {f.user})";

const SEED_DENY_CALENDAR_APP: &str =
    "INSERT INTO user_app_entitlements (user_id, app, enabled) VALUES ({a.user}, 'calendar', false)";

const SEED_FOREIGN_EMAIL_PROBE: &str =
    "INSERT INTO calendars (mailbox_id, name, timezone, resource_type, capacity, booking_policy) \
     VALUES ({f.mailbox}, 'MgrEmailProbe', 'UTC', 'room', 4, 'auto-accept') RETURNING id";

const SETUP_RESOURCE_LIST: &[&str] = &[
    r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/resourceList",{"accountId":"{a.mailbox}"},"r0"]]}"#,
];

fn manager_email_var(prior: &[String]) -> Result<Vec<(String, String)>, BoxError> {
    let doc: Value = serde_json::from_str(prior.first().ok_or("missing setup response")?)?;
    let list = doc
        .pointer("/methodResponses/0/1/list")
        .and_then(Value::as_array)
        .ok_or("missing resourceList list array")?;
    for entry in list {
        if entry.get("name").and_then(Value::as_str) == Some("MgrEmailProbe") {
            let email = entry
                .get("email")
                .and_then(Value::as_str)
                .ok_or("missing email on probe resource")?;
            return Ok(vec![("manager_email".to_owned(), email.to_owned())]);
        }
    }
    Err("MgrEmailProbe resource not found".into())
}

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

// ---------------------------------------------------------------------------
// CalendarEvent/get
// ---------------------------------------------------------------------------

const CALENDAR_EVENT_GET_SUCCESS: Case = Case {
    seed: &[
        SEED_OWN_CALENDAR,
        SEED_OWN_EVENT,
        SEED_FOREIGN_CALENDAR,
        SEED_FOREIGN_EVENT_ON_CAL2,
    ],
    absent: &["Foreign event"],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-get-success",
        "success",
        "CalendarEvent/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/get",{"accountId":"{a.mailbox}","ids":["{seed.1}","{seed.3}"]},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_GET_NO_TENANT_MUTANT: Case = Case {
    absent: &[],
    ..CALENDAR_EVENT_GET_SUCCESS
};
const CALENDAR_EVENT_GET_CROSS_TENANT: Case = Case {
    seed: &[
        SEED_FOREIGN_CALENDAR,
        "INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, status) \
         VALUES ({seed.0}, 'uid-ct-1', 'Foreign event', '2026-11-22T18:00:00Z'::timestamptz, '2026-11-22T19:00:00Z'::timestamptz, 'confirmed') RETURNING id",
    ],
    absent: &["{seed.1}", "Foreign event"],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-get-cross-tenant",
        "cross-tenant",
        "CalendarEvent/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/get",{"accountId":"{f.mailbox}","ids":["{seed.1}"]},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_GET_INVALID_INPUT: Case = Case {
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-get-invalid-input",
        "invalid-input",
        "CalendarEvent/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/get",{"accountId":"{a.mailbox}","ids":"bad"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_GET_DELEGATE_PERSONAL: Case = Case {
    seed: &[SEED_DELEGATE_FULL],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-get-delegate-personal",
        "delegate-personal",
        "CalendarEvent/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/get",{"accountId":"{f.mailbox}","ids":null},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_GET_ENTITLEMENT_DENIED: Case = Case {
    seed: &[SEED_OWN_CALENDAR, SEED_OWN_EVENT, SEED_DENY_CALENDAR_APP],
    absent: &["{seed.1}", "Own event"],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-get-entitlement-denied",
        "entitlement-denied",
        "CalendarEvent/get",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/get",{"accountId":"{a.mailbox}","ids":["{seed.1}"]},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// CalendarEvent/query
// ---------------------------------------------------------------------------

const CALENDAR_EVENT_QUERY_SUCCESS: Case = Case {
    seed: &[
        SEED_OWN_CALENDAR,
        SEED_OWN_EVENT,
        SEED_FOREIGN_CALENDAR,
        SEED_FOREIGN_EVENT_ON_CAL2,
    ],
    absent: &["{seed.3}"],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-query-success",
        "success",
        "CalendarEvent/query",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/query",{"accountId":"{a.mailbox}","filter":{"after":"2026-11-20T00:00:00Z","before":"2026-11-25T00:00:00Z"},"position":0,"limit":50},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_QUERY_CROSS_TENANT: Case = Case {
    seed: &[SEED_FOREIGN_CALENDAR],
    absent: &["{seed.0}"],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-query-cross-tenant",
        "cross-tenant",
        "CalendarEvent/query",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/query",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_QUERY_INVALID_INPUT: Case = Case {
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-query-invalid-input",
        "invalid-input",
        "CalendarEvent/query",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/query",{"accountId":"{a.mailbox}","limit":"bad"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_QUERY_DELEGATE_PERSONAL: Case = Case {
    seed: &[SEED_DELEGATE_FULL],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-query-delegate-personal",
        "delegate-personal",
        "CalendarEvent/query",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/query",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_QUERY_ENTITLEMENT_DENIED: Case = Case {
    seed: &[SEED_OWN_CALENDAR, SEED_OWN_EVENT, SEED_DENY_CALENDAR_APP],
    absent: &["{seed.1}"],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-query-entitlement-denied",
        "entitlement-denied",
        "CalendarEvent/query",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/query",{"accountId":"{a.mailbox}"},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// CalendarEvent/changes
// ---------------------------------------------------------------------------

const CALENDAR_EVENT_CHANGES_SUCCESS: Case = Case {
    seed: &[
        SEED_OWN_CALENDAR,
        SEED_FOREIGN_CALENDAR,
        SEED_FOREIGN_EVENT_ON_CAL2,
    ],
    setup: &[
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/set",{"accountId":"{a.mailbox}","create":{"d1":{"calendarId":"{seed.0}","uid":"uid-changes-delta","title":"Delta event","start":"2026-11-22T12:00:00Z","end":"2026-11-22T13:00:00Z"}}},"s0"]]}"#,
    ],
    absent: &["{seed.2}"],
    scrub: &[("/methodResponses/0/1/created/0", "created")],
    effects: &[EFFECT_EVENTS_NO_ID, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-changes-success",
        "success",
        "CalendarEvent/changes",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/changes",{"accountId":"{a.mailbox}","sinceState":"0"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_CHANGES_CROSS_TENANT: Case = Case {
    seed: &[SEED_FOREIGN_CALENDAR, SEED_FOREIGN_EVENT_ON_CAL1],
    absent: &["{seed.1}"],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-changes-cross-tenant",
        "cross-tenant",
        "CalendarEvent/changes",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/changes",{"accountId":"{f.mailbox}","sinceState":"0"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_CHANGES_INVALID_INPUT: Case = Case {
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-changes-invalid-input",
        "invalid-input",
        "CalendarEvent/changes",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/changes",{"accountId":"{a.mailbox}","sinceState":123},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_CHANGES_STATE_MISMATCH: Case = Case {
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-changes-state-mismatch",
        "state-mismatch",
        "CalendarEvent/changes",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/changes",{"accountId":"{a.mailbox}","sinceState":"999999"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_CHANGES_DELEGATE_PERSONAL: Case = Case {
    seed: &[SEED_DELEGATE_FULL],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-changes-delegate-personal",
        "delegate-personal",
        "CalendarEvent/changes",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/changes",{"accountId":"{f.mailbox}","sinceState":"0"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_CHANGES_ENTITLEMENT_DENIED: Case = Case {
    seed: &[SEED_OWN_CALENDAR, SEED_DENY_CALENDAR_APP],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-changes-entitlement-denied",
        "entitlement-denied",
        "CalendarEvent/changes",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/changes",{"accountId":"{a.mailbox}","sinceState":"0"},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// CalendarEvent/set
// ---------------------------------------------------------------------------

const CALENDAR_EVENT_SET_SUCCESS: Case = Case {
    mutator: true,
    seed: &[SEED_OWN_CALENDAR],
    notify: &["calendar:{a.mailbox}"],
    scrub: &[("/methodResponses/0/1/created/c1", "created")],
    effects: &[EFFECT_EVENTS_NO_ID, EFFECT_ATTENDEES, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-set-success",
        "success",
        "CalendarEvent/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/set",{"accountId":"{a.mailbox}","create":{"c1":{"calendarId":"{seed.0}","uid":"uid-set-create-1","title":"Created meeting","start":"2026-11-22T14:00:00Z","end":"2026-11-22T15:00:00Z","attendees":[{"email":"guest@static.test","name":"Guest","role":"required"}]}}},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_SET_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    seed: &[SEED_OWN_CALENDAR, SEED_OWN_EVENT],
    notify: &["calendar:{a.mailbox}"],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-set-repeat",
        "repeat",
        "CalendarEvent/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/set",{"accountId":"{a.mailbox}","update":{"{seed.1}":{"title":"Repeated update","status":"tentative"}}},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_SET_UPDATE_DESTROY: Case = Case {
    mutator: true,
    seed: &[
        SEED_OWN_CALENDAR,
        SEED_OWN_EVENT,
        "INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, status) \
         VALUES ({seed.0}, 'uid-del-1', 'Delete event', '2026-11-22T15:00:00Z'::timestamptz, '2026-11-22T16:00:00Z'::timestamptz, 'confirmed') RETURNING id",
        SEED_FOREIGN_CALENDAR,
        "INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, status) \
         VALUES ({seed.3}, 'uid-for-keep', 'Foreign event', '2026-11-22T18:00:00Z'::timestamptz, '2026-11-22T19:00:00Z'::timestamptz, 'confirmed') RETURNING id",
    ],
    absent: &["{seed.4}", "Foreign event"],
    notify: &["calendar:{a.mailbox}"],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-set-update-destroy",
        "success",
        "CalendarEvent/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/set",{"accountId":"{a.mailbox}","update":{"{seed.1}":{"title":"Updated title"}},"destroy":["{seed.2}","bad-id"]},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_SET_CROSS_TENANT: Case = Case {
    mutator: true,
    seed: &[SEED_FOREIGN_CALENDAR],
    absent: &["{seed.0}"],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-set-cross-tenant",
        "cross-tenant",
        "CalendarEvent/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/set",{"accountId":"{f.mailbox}","create":{"c1":{"calendarId":"{seed.0}","title":"Nope","start":"2026-11-22T10:00:00Z","end":"2026-11-22T11:00:00Z"}}},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_SET_INVALID_INPUT: Case = Case {
    mutator: true,
    seed: &[SEED_OWN_CALENDAR],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-set-invalid-input",
        "invalid-input",
        "CalendarEvent/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/set",{"accountId":"{a.mailbox}","destroy":"bad"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_SET_DELEGATE_PERSONAL: Case = Case {
    mutator: true,
    seed: &[SEED_DELEGATE_FULL, SEED_FOREIGN_CALENDAR],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-set-delegate-personal",
        "delegate-personal",
        "CalendarEvent/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/set",{"accountId":"{f.mailbox}","create":{"c1":{"calendarId":"{seed.1}","title":"Delegate nope","start":"2026-11-22T10:00:00Z","end":"2026-11-22T11:00:00Z"}}},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_SET_ENTITLEMENT_DENIED: Case = Case {
    mutator: true,
    seed: &[SEED_OWN_CALENDAR, SEED_DENY_CALENDAR_APP],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-set-entitlement-denied",
        "entitlement-denied",
        "CalendarEvent/set",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/set",{"accountId":"{a.mailbox}","create":{"c1":{"calendarId":"{seed.0}","title":"Denied","start":"2026-11-22T10:00:00Z","end":"2026-11-22T11:00:00Z"}}},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// CalendarEvent/import
// ---------------------------------------------------------------------------

const CALENDAR_EVENT_IMPORT_SUCCESS: Case = Case {
    mutator: true,
    seed: &[SEED_OWN_CALENDAR],
    effects: &[EFFECT_EVENTS_NO_ID, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-import-success",
        "success",
        "CalendarEvent/import",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/import",{"accountId":"{a.mailbox}","calendarId":"{seed.0}","ics":"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\nBEGIN:VEVENT\r\nUID:ics-import-1@static.test\r\nDTSTART:20261124T090000Z\r\nDTEND:20261124T100000Z\r\nSUMMARY:Imported sync\r\nEND:VEVENT\r\nEND:VCALENDAR","strategy":"skip"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_IMPORT_REPEAT: Case = Case {
    name: "calendar-event-import-repeat",
    kind: "repeat",
    repeat: true,
    notify: &[],
    ..CALENDAR_EVENT_IMPORT_SUCCESS
};
const CALENDAR_EVENT_IMPORT_CROSS_TENANT: Case = Case {
    mutator: true,
    seed: &[SEED_FOREIGN_CALENDAR],
    absent: &["{seed.0}"],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-import-cross-tenant",
        "cross-tenant",
        "CalendarEvent/import",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/import",{"accountId":"{f.mailbox}","calendarId":"{seed.0}","ics":"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\nDTSTART:20261124T090000Z\r\nDTEND:20261124T100000Z\r\nSUMMARY:X\r\nEND:VEVENT\r\nEND:VCALENDAR"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_IMPORT_INVALID_INPUT: Case = Case {
    mutator: true,
    seed: &[SEED_OWN_CALENDAR],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-import-invalid-input",
        "invalid-input",
        "CalendarEvent/import",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/import",{"accountId":"{a.mailbox}","calendarId":"{seed.0}","ics":""},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_IMPORT_DELEGATE_PERSONAL: Case = Case {
    mutator: true,
    seed: &[SEED_DELEGATE_FULL, SEED_FOREIGN_CALENDAR],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-import-delegate-personal",
        "delegate-personal",
        "CalendarEvent/import",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/import",{"accountId":"{f.mailbox}","calendarId":"{seed.1}","ics":"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\nDTSTART:20261124T090000Z\r\nDTEND:20261124T100000Z\r\nSUMMARY:X\r\nEND:VEVENT\r\nEND:VCALENDAR"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_IMPORT_ENTITLEMENT_DENIED: Case = Case {
    mutator: true,
    seed: &[SEED_OWN_CALENDAR, SEED_DENY_CALENDAR_APP],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-import-entitlement-denied",
        "entitlement-denied",
        "CalendarEvent/import",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/import",{"accountId":"{a.mailbox}","calendarId":"{seed.0}","ics":"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\nDTSTART:20261124T090000Z\r\nDTEND:20261124T100000Z\r\nSUMMARY:X\r\nEND:VEVENT\r\nEND:VCALENDAR"},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// CalendarEvent/freeBusy
// ---------------------------------------------------------------------------

const CALENDAR_EVENT_FREE_BUSY_SUCCESS: Case = Case {
    seed: &[
        SEED_OWN_CALENDAR,
        SEED_OWN_EVENT,
        SEED_FOREIGN_CALENDAR,
        SEED_FOREIGN_EVENT_ON_CAL2,
    ],
    absent: &["18:00:00"],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-free-busy-success",
        "success",
        "CalendarEvent/freeBusy",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/freeBusy",{"accountId":"{a.mailbox}","userIds":["{a.user}"],"start":"2026-11-22T00:00:00Z","end":"2026-11-23T00:00:00Z"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_FREE_BUSY_CROSS_TENANT: Case = Case {
    seed: &[SEED_FOREIGN_CALENDAR],
    absent: &["{seed.0}"],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-free-busy-cross-tenant",
        "cross-tenant",
        "CalendarEvent/freeBusy",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/freeBusy",{"accountId":"{f.mailbox}","userIds":["{f.user}"],"start":"2026-11-22T00:00:00Z","end":"2026-11-23T00:00:00Z"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_FREE_BUSY_INVALID_INPUT: Case = Case {
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-free-busy-invalid-input",
        "invalid-input",
        "CalendarEvent/freeBusy",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/freeBusy",{"accountId":"{a.mailbox}","userIds":["bad"],"start":"2026-11-22T00:00:00Z","end":"2026-11-23T00:00:00Z"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_FREE_BUSY_DELEGATE_PERSONAL: Case = Case {
    seed: &[SEED_DELEGATE_FULL],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-free-busy-delegate-personal",
        "delegate-personal",
        "CalendarEvent/freeBusy",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/freeBusy",{"accountId":"{f.mailbox}","userIds":["{f.user}"],"start":"2026-11-22T00:00:00Z","end":"2026-11-23T00:00:00Z"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_FREE_BUSY_ENTITLEMENT_DENIED: Case = Case {
    seed: &[SEED_DENY_CALENDAR_APP],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-free-busy-entitlement-denied",
        "entitlement-denied",
        "CalendarEvent/freeBusy",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/freeBusy",{"accountId":"{a.mailbox}","userIds":["{a.user}"],"start":"2026-11-22T00:00:00Z","end":"2026-11-23T00:00:00Z"},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// CalendarEvent/queryFreeSlots
// ---------------------------------------------------------------------------

const CALENDAR_EVENT_QUERY_FREE_SLOTS_SUCCESS: Case = Case {
    seed: &[SEED_OWN_CALENDAR, SEED_OWN_EVENT],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-query-free-slots-success",
        "success",
        "CalendarEvent/queryFreeSlots",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/queryFreeSlots",{"accountId":"{a.mailbox}","userIds":["{a.user}"],"start":"2026-11-23T00:00:00Z","end":"2026-11-24T00:00:00Z","durationMinutes":30,"maxSlots":5},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_QUERY_FREE_SLOTS_CROSS_TENANT: Case = Case {
    seed: &[SEED_FOREIGN_CALENDAR],
    absent: &["{seed.0}"],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-query-free-slots-cross-tenant",
        "cross-tenant",
        "CalendarEvent/queryFreeSlots",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/queryFreeSlots",{"accountId":"{f.mailbox}","userIds":["{f.user}"],"start":"2026-11-23T00:00:00Z","end":"2026-11-24T00:00:00Z"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_QUERY_FREE_SLOTS_INVALID_INPUT: Case = Case {
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-query-free-slots-invalid-input",
        "invalid-input",
        "CalendarEvent/queryFreeSlots",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/queryFreeSlots",{"accountId":"{a.mailbox}","userIds":[],"start":"2026-11-23T00:00:00Z","end":"2026-11-24T00:00:00Z"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_QUERY_FREE_SLOTS_DELEGATE_PERSONAL: Case = Case {
    seed: &[SEED_DELEGATE_FULL],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-query-free-slots-delegate-personal",
        "delegate-personal",
        "CalendarEvent/queryFreeSlots",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/queryFreeSlots",{"accountId":"{f.mailbox}","userIds":["{f.user}"],"start":"2026-11-23T00:00:00Z","end":"2026-11-24T00:00:00Z"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_QUERY_FREE_SLOTS_ENTITLEMENT_DENIED: Case = Case {
    seed: &[SEED_DENY_CALENDAR_APP],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-query-free-slots-entitlement-denied",
        "entitlement-denied",
        "CalendarEvent/queryFreeSlots",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/queryFreeSlots",{"accountId":"{a.mailbox}","userIds":["{a.user}"],"start":"2026-11-23T00:00:00Z","end":"2026-11-24T00:00:00Z"},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// CalendarEvent/rsvp
// ---------------------------------------------------------------------------

const SEED_OWN_ATTENDEE: &str =
    "INSERT INTO event_attendees (event_id, email, name, role, status) \
     SELECT {seed.1}, email, 'Alice', 'required', 'needs-action' FROM mailboxes WHERE id = {a.mailbox} RETURNING id";

const SEED_FOREIGN_ATTENDEE: &str =
    "INSERT INTO event_attendees (event_id, email, name, role, status) \
     SELECT {seed.1}, email, 'Manager', 'required', 'needs-action' FROM mailboxes WHERE id = {f.mailbox} RETURNING id";

const CALENDAR_EVENT_RSVP_SUCCESS: Case = Case {
    mutator: true,
    seed: &[SEED_OWN_CALENDAR, SEED_OWN_EVENT, SEED_OWN_ATTENDEE],
    notify: &["calendar:{a.mailbox}"],
    effects: &[EFFECT_ATTENDEES, EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-rsvp-success",
        "success",
        "CalendarEvent/rsvp",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/rsvp",{"accountId":"{a.mailbox}","eventId":"{seed.1}","status":"accepted"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_RSVP_REPEAT: Case = Case {
    name: "calendar-event-rsvp-repeat",
    kind: "repeat",
    repeat: true,
    ..CALENDAR_EVENT_RSVP_SUCCESS
};
const CALENDAR_EVENT_RSVP_DELEGATE: Case = Case {
    mutator: true,
    seed: &[
        SEED_FOREIGN_CALENDAR,
        SEED_FOREIGN_EVENT_ON_CAL1,
        SEED_FOREIGN_ATTENDEE,
        SEED_DELEGATE_CALENDAR,
        SEED_FOREIGN_EMAIL_PROBE,
    ],
    setup: SETUP_RESOURCE_LIST,
    vars: manager_email_var,
    notify: &["calendar:{f.mailbox}"],
    effects: &[EFFECT_ATTENDEES, EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-rsvp-delegate",
        "success",
        "CalendarEvent/rsvp",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/rsvp",{"accountId":"{a.mailbox}","eventId":"{seed.1}","status":"tentative","onBehalfOf":"{var.manager_email}"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_RSVP_CROSS_TENANT: Case = Case {
    mutator: true,
    seed: &[SEED_FOREIGN_CALENDAR, SEED_FOREIGN_EVENT_ON_CAL1],
    absent: &["{seed.1}"],
    effects: &[EFFECT_ATTENDEES, EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-rsvp-cross-tenant",
        "cross-tenant",
        "CalendarEvent/rsvp",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/rsvp",{"accountId":"{f.mailbox}","eventId":"{seed.1}","status":"accepted"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_RSVP_INVALID_INPUT: Case = Case {
    mutator: true,
    seed: &[SEED_OWN_CALENDAR, SEED_OWN_EVENT],
    effects: &[EFFECT_ATTENDEES, EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-rsvp-invalid-input",
        "invalid-input",
        "CalendarEvent/rsvp",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/rsvp",{"accountId":"{a.mailbox}","eventId":"{seed.1}","status":"bogus"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_RSVP_DELEGATE_PERSONAL: Case = Case {
    mutator: true,
    seed: &[
        SEED_DELEGATE_FULL,
        SEED_FOREIGN_CALENDAR,
        "INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, status) \
         VALUES ({seed.1}, 'uid-rsvp-dp', 'Foreign event', '2026-11-22T18:00:00Z'::timestamptz, '2026-11-22T19:00:00Z'::timestamptz, 'confirmed') RETURNING id",
    ],
    effects: &[EFFECT_ATTENDEES, EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-rsvp-delegate-personal",
        "delegate-personal",
        "CalendarEvent/rsvp",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/rsvp",{"accountId":"{f.mailbox}","eventId":"{seed.2}","status":"accepted"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_RSVP_ENTITLEMENT_DENIED: Case = Case {
    mutator: true,
    seed: &[
        SEED_OWN_CALENDAR,
        SEED_OWN_EVENT,
        SEED_OWN_ATTENDEE,
        SEED_DENY_CALENDAR_APP,
    ],
    effects: &[EFFECT_ATTENDEES, EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-rsvp-entitlement-denied",
        "entitlement-denied",
        "CalendarEvent/rsvp",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/rsvp",{"accountId":"{a.mailbox}","eventId":"{seed.1}","status":"accepted"},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// CalendarEvent/counter
// ---------------------------------------------------------------------------

const SEED_OWN_MEETING_FOR_COUNTER: &str =
    "INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, status, is_meeting, organizer_email, organizer_name) \
     VALUES ({seed.0}, 'uid-counter-1', 'Design review', '2026-11-22T10:00:00Z'::timestamptz, '2026-11-22T11:00:00Z'::timestamptz, 'confirmed', true, 'org@static.test', 'Organizer') RETURNING id";

const CALENDAR_EVENT_COUNTER_SUCCESS: Case = Case {
    seed: &[
        SEED_OWN_CALENDAR,
        SEED_OWN_MEETING_FOR_COUNTER,
        SEED_OWN_ATTENDEE,
    ],
    scrub: &[("/methodResponses/0/1/attendeeEmail", "attendee-email")],
    effects: &[EFFECT_EVENTS, EFFECT_ATTENDEES],
    ..Case::new(
        "calendar_event",
        "calendar-event-counter-success",
        "success",
        "CalendarEvent/counter",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/counter",{"accountId":"{a.mailbox}","eventId":"{seed.1}","start":"2026-11-23T14:00:00Z","end":"2026-11-23T15:00:00Z"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_COUNTER_CROSS_TENANT: Case = Case {
    seed: &[SEED_FOREIGN_CALENDAR, SEED_FOREIGN_EVENT_ON_CAL1],
    absent: &["{seed.1}"],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-counter-cross-tenant",
        "cross-tenant",
        "CalendarEvent/counter",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/counter",{"accountId":"{f.mailbox}","eventId":"{seed.1}","start":"2026-11-23T14:00:00Z","end":"2026-11-23T15:00:00Z"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_COUNTER_INVALID_INPUT: Case = Case {
    seed: &[SEED_OWN_CALENDAR, SEED_OWN_MEETING_FOR_COUNTER],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-counter-invalid-input",
        "invalid-input",
        "CalendarEvent/counter",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/counter",{"accountId":"{a.mailbox}","eventId":"{seed.1}","start":"","end":""},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_COUNTER_DELEGATE_PERSONAL: Case = Case {
    seed: &[
        SEED_DELEGATE_FULL,
        SEED_FOREIGN_CALENDAR,
        "INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, status) \
         VALUES ({seed.1}, 'uid-counter-dp', 'Foreign event', '2026-11-22T18:00:00Z'::timestamptz, '2026-11-22T19:00:00Z'::timestamptz, 'confirmed') RETURNING id",
    ],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-counter-delegate-personal",
        "delegate-personal",
        "CalendarEvent/counter",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/counter",{"accountId":"{f.mailbox}","eventId":"{seed.2}","start":"2026-11-23T14:00:00Z","end":"2026-11-23T15:00:00Z"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_COUNTER_ENTITLEMENT_DENIED: Case = Case {
    seed: &[
        SEED_OWN_CALENDAR,
        SEED_OWN_MEETING_FOR_COUNTER,
        SEED_OWN_ATTENDEE,
        SEED_DENY_CALENDAR_APP,
    ],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-counter-entitlement-denied",
        "entitlement-denied",
        "CalendarEvent/counter",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/counter",{"accountId":"{a.mailbox}","eventId":"{seed.1}","start":"2026-11-23T14:00:00Z","end":"2026-11-23T15:00:00Z"},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// CalendarEvent/getShared
// ---------------------------------------------------------------------------

const CALENDAR_EVENT_GET_SHARED_SUCCESS: Case = Case {
    seed: &[
        SEED_FOREIGN_CALENDAR,
        "INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, status, classification) \
         VALUES ({seed.0}, 'uid-shared-pub', 'Shared public event', '2026-11-22T10:00:00Z'::timestamptz, '2026-11-22T11:00:00Z'::timestamptz, 'confirmed', 'PUBLIC') RETURNING id",
        "INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, status, classification) \
         VALUES ({seed.0}, 'uid-shared-priv', 'Secret private event', '2026-11-22T12:00:00Z'::timestamptz, '2026-11-22T13:00:00Z'::timestamptz, 'confirmed', 'PRIVATE') RETURNING id",
        "INSERT INTO calendar_acls (calendar_id, user_id, permission) VALUES ({seed.0}, {a.user}, 'read')",
        SEED_FOREIGN_EMAIL_PROBE,
    ],
    setup: SETUP_RESOURCE_LIST,
    vars: manager_email_var,
    absent: &["Secret private event"],
    scrub: &[("/methodResponses/0/1/ownerEmail", "owner-email")],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-get-shared-success",
        "success",
        "CalendarEvent/getShared",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/getShared",{"accountId":"{a.mailbox}","ownerEmail":"{var.manager_email}"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_GET_SHARED_CROSS_TENANT: Case = Case {
    seed: &[SEED_FOREIGN_CALENDAR],
    absent: &["{seed.0}"],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-get-shared-cross-tenant",
        "cross-tenant",
        "CalendarEvent/getShared",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/getShared",{"accountId":"{f.mailbox}","ownerEmail":"other@static.test"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_GET_SHARED_INVALID_INPUT: Case = Case {
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-get-shared-invalid-input",
        "invalid-input",
        "CalendarEvent/getShared",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/getShared",{"accountId":"{a.mailbox}","ownerEmail":""},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_GET_SHARED_DELEGATE_PERSONAL: Case = Case {
    seed: &[SEED_DELEGATE_FULL],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-get-shared-delegate-personal",
        "delegate-personal",
        "CalendarEvent/getShared",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/getShared",{"accountId":"{f.mailbox}","ownerEmail":"other@static.test"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_GET_SHARED_ENTITLEMENT_DENIED: Case = Case {
    seed: &[SEED_DENY_CALENDAR_APP],
    effects: &[EFFECT_EVENTS],
    ..Case::new(
        "calendar_event",
        "calendar-event-get-shared-entitlement-denied",
        "entitlement-denied",
        "CalendarEvent/getShared",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/getShared",{"accountId":"{a.mailbox}","ownerEmail":"other@static.test"},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// CalendarEvent/setOccurrence
// ---------------------------------------------------------------------------

const SEED_OWN_RECURRING_MASTER: &str =
    "INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, rrule, status) \
     VALUES ({seed.0}, 'uid-rec-1', 'Daily standup', '2026-11-22T10:00:00Z'::timestamptz, '2026-11-22T10:30:00Z'::timestamptz, 'FREQ=DAILY;COUNT=3', 'confirmed') RETURNING id";

const CALENDAR_EVENT_SET_OCCURRENCE_SUCCESS: Case = Case {
    mutator: true,
    seed: &[SEED_OWN_CALENDAR, SEED_OWN_RECURRING_MASTER],
    notify: &["calendar:{a.mailbox}"],
    scrub: &[("/methodResponses/0/1/eventId", "occurrence-event")],
    effects: &[EFFECT_EVENTS_NO_ID, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-set-occurrence-success",
        "success",
        "CalendarEvent/setOccurrence",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/setOccurrence",{"accountId":"{a.mailbox}","masterId":"{seed.1}","recurrenceId":"2026-11-23T10:00:00Z","scope":"this","patch":{"title":"Moved standup"}},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_SET_OCCURRENCE_REPEAT: Case = Case {
    mutator: true,
    repeat: true,
    seed: &[SEED_OWN_CALENDAR, SEED_OWN_RECURRING_MASTER],
    notify: &["calendar:{a.mailbox}"],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-set-occurrence-repeat",
        "repeat",
        "CalendarEvent/setOccurrence",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/setOccurrence",{"accountId":"{a.mailbox}","masterId":"{seed.1}","recurrenceId":"2026-11-23T10:00:00Z","scope":"series","patch":{"title":"Series standup"}},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_SET_OCCURRENCE_CROSS_TENANT: Case = Case {
    mutator: true,
    seed: &[
        SEED_FOREIGN_CALENDAR,
        "INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, rrule, status) \
         VALUES ({seed.0}, 'uid-rec-ct', 'Foreign recurring', '2026-11-22T10:00:00Z'::timestamptz, '2026-11-22T10:30:00Z'::timestamptz, 'FREQ=DAILY;COUNT=3', 'confirmed') RETURNING id",
    ],
    absent: &["{seed.1}"],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-set-occurrence-cross-tenant",
        "cross-tenant",
        "CalendarEvent/setOccurrence",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/setOccurrence",{"accountId":"{f.mailbox}","masterId":"{seed.1}","recurrenceId":"2026-11-23T10:00:00Z","scope":"this","patch":{"title":"Nope"}},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_SET_OCCURRENCE_INVALID_INPUT: Case = Case {
    mutator: true,
    seed: &[SEED_OWN_CALENDAR, SEED_OWN_RECURRING_MASTER],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-set-occurrence-invalid-input",
        "invalid-input",
        "CalendarEvent/setOccurrence",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/setOccurrence",{"accountId":"{a.mailbox}","masterId":"{seed.1}","recurrenceId":"2026-11-23T10:00:00Z","scope":"bogus","patch":{}},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_SET_OCCURRENCE_DELEGATE_PERSONAL: Case = Case {
    mutator: true,
    seed: &[
        SEED_DELEGATE_FULL,
        SEED_FOREIGN_CALENDAR,
        "INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, rrule, status) \
         VALUES ({seed.1}, 'uid-rec-dp', 'Foreign recurring', '2026-11-22T10:00:00Z'::timestamptz, '2026-11-22T10:30:00Z'::timestamptz, 'FREQ=DAILY;COUNT=3', 'confirmed') RETURNING id",
    ],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-set-occurrence-delegate-personal",
        "delegate-personal",
        "CalendarEvent/setOccurrence",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/setOccurrence",{"accountId":"{f.mailbox}","masterId":"{seed.2}","recurrenceId":"2026-11-23T10:00:00Z","scope":"this","patch":{"title":"Nope"}},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_SET_OCCURRENCE_ENTITLEMENT_DENIED: Case = Case {
    mutator: true,
    seed: &[
        SEED_OWN_CALENDAR,
        SEED_OWN_RECURRING_MASTER,
        SEED_DENY_CALENDAR_APP,
    ],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-set-occurrence-entitlement-denied",
        "entitlement-denied",
        "CalendarEvent/setOccurrence",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/setOccurrence",{"accountId":"{a.mailbox}","masterId":"{seed.1}","recurrenceId":"2026-11-23T10:00:00Z","scope":"this","patch":{"title":"Denied"}},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// CalendarEvent/resourceList
// ---------------------------------------------------------------------------

const CALENDAR_EVENT_RESOURCE_LIST_SUCCESS: Case = Case {
    seed: &[
        "INSERT INTO calendars (mailbox_id, name, timezone, resource_type, capacity, booking_policy) \
         VALUES ({f.mailbox}, 'Conf Room A', 'UTC', 'room', 8, 'auto-accept') RETURNING id",
    ],
    scrub: &[("/methodResponses/0/1/list/0/email", "room-email")],
    effects: &[EFFECT_CALENDARS],
    ..Case::new(
        "calendar_event",
        "calendar-event-resource-list-success",
        "success",
        "CalendarEvent/resourceList",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/resourceList",{"accountId":"{a.mailbox}"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_RESOURCE_LIST_CROSS_TENANT: Case = Case {
    seed: &[SEED_FOREIGN_CALENDAR],
    absent: &["{seed.0}"],
    effects: &[EFFECT_CALENDARS],
    ..Case::new(
        "calendar_event",
        "calendar-event-resource-list-cross-tenant",
        "cross-tenant",
        "CalendarEvent/resourceList",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/resourceList",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_RESOURCE_LIST_INVALID_INPUT: Case = Case {
    effects: &[EFFECT_CALENDARS],
    ..Case::new(
        "calendar_event",
        "calendar-event-resource-list-invalid-input",
        "invalid-input",
        "CalendarEvent/resourceList",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/resourceList",{"accountId":"not-an-id"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_RESOURCE_LIST_DELEGATE_PERSONAL: Case = Case {
    seed: &[SEED_DELEGATE_FULL],
    effects: &[EFFECT_CALENDARS],
    ..Case::new(
        "calendar_event",
        "calendar-event-resource-list-delegate-personal",
        "delegate-personal",
        "CalendarEvent/resourceList",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/resourceList",{"accountId":"{f.mailbox}"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_RESOURCE_LIST_ENTITLEMENT_DENIED: Case = Case {
    seed: &[SEED_DENY_CALENDAR_APP],
    effects: &[EFFECT_CALENDARS],
    ..Case::new(
        "calendar_event",
        "calendar-event-resource-list-entitlement-denied",
        "entitlement-denied",
        "CalendarEvent/resourceList",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/resourceList",{"accountId":"{a.mailbox}"},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// CalendarEvent/sendUpdate
// ---------------------------------------------------------------------------

const SEED_OWN_MEETING_FOR_UPDATE: &str =
    "INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, status, is_meeting, organizer_email, organizer_name) \
     SELECT {seed.0}, 'uid-send-upd-1', 'Updated Sync', '2026-11-22T10:00:00Z'::timestamptz, '2026-11-22T11:00:00Z'::timestamptz, 'confirmed', true, email, 'Alice' \
     FROM mailboxes WHERE id = {a.mailbox} RETURNING id";

const SEED_UPDATE_GUEST: &str =
    "INSERT INTO event_attendees (event_id, email, name, role, status) \
     VALUES ({seed.1}, 'guest@static.test', 'Guest', 'required', 'needs-action') RETURNING id";

const CALENDAR_EVENT_SEND_UPDATE_SUCCESS: Case = Case {
    mutator: true,
    seed: &[
        SEED_OWN_CALENDAR,
        SEED_OWN_MEETING_FOR_UPDATE,
        SEED_UPDATE_GUEST,
    ],
    notify: &["calendar:{a.mailbox}"],
    scrub: &[("/methodResponses/0/1/organizerEmail", "organizer-email")],
    effects: &[EFFECT_EVENTS, EFFECT_ATTENDEES, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-send-update-success",
        "success",
        "CalendarEvent/sendUpdate",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/sendUpdate",{"accountId":"{a.mailbox}","eventId":"{seed.1}"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_SEND_UPDATE_REPEAT: Case = Case {
    name: "calendar-event-send-update-repeat",
    kind: "repeat",
    repeat: true,
    ..CALENDAR_EVENT_SEND_UPDATE_SUCCESS
};
const CALENDAR_EVENT_SEND_UPDATE_CROSS_TENANT: Case = Case {
    mutator: true,
    seed: &[SEED_FOREIGN_CALENDAR, SEED_FOREIGN_EVENT_ON_CAL1],
    absent: &["{seed.1}"],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-send-update-cross-tenant",
        "cross-tenant",
        "CalendarEvent/sendUpdate",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/sendUpdate",{"accountId":"{f.mailbox}","eventId":"{seed.1}"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_SEND_UPDATE_INVALID_INPUT: Case = Case {
    mutator: true,
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-send-update-invalid-input",
        "invalid-input",
        "CalendarEvent/sendUpdate",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/sendUpdate",{"accountId":"{a.mailbox}","eventId":"bad"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_SEND_UPDATE_DELEGATE_PERSONAL: Case = Case {
    mutator: true,
    seed: &[
        SEED_DELEGATE_FULL,
        SEED_FOREIGN_CALENDAR,
        "INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, status) \
         VALUES ({seed.1}, 'uid-su-dp', 'Foreign event', '2026-11-22T18:00:00Z'::timestamptz, '2026-11-22T19:00:00Z'::timestamptz, 'confirmed') RETURNING id",
    ],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-send-update-delegate-personal",
        "delegate-personal",
        "CalendarEvent/sendUpdate",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/sendUpdate",{"accountId":"{f.mailbox}","eventId":"{seed.2}"},"c1"]]}"#,
    )
};
const CALENDAR_EVENT_SEND_UPDATE_ENTITLEMENT_DENIED: Case = Case {
    mutator: true,
    seed: &[
        SEED_OWN_CALENDAR,
        SEED_OWN_MEETING_FOR_UPDATE,
        SEED_UPDATE_GUEST,
        SEED_DENY_CALENDAR_APP,
    ],
    effects: &[EFFECT_EVENTS, EFFECT_ENTITY_STATE],
    ..Case::new(
        "calendar_event",
        "calendar-event-send-update-entitlement-denied",
        "entitlement-denied",
        "CalendarEvent/sendUpdate",
        r#"{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:calendars"],"methodCalls":[["CalendarEvent/sendUpdate",{"accountId":"{a.mailbox}","eventId":"{seed.1}"},"c1"]]}"#,
    )
};

// ---------------------------------------------------------------------------
// Test wiring (matches route-catalog.d/jmap-369.json selectors 1:1)
// ---------------------------------------------------------------------------

macro_rules! oracle_test {
    ($name:ident, $case:expr) => {
        #[tokio::test]
        async fn $name() -> Result<(), BoxError> {
            assert_eq!($case.family, "calendar_event");
            assert!($case.request.contains(CAP_CALENDARS));
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

// CalendarEvent/get
oracle_test!(calendar_event_get_success, CALENDAR_EVENT_GET_SUCCESS);
oracle_test!(
    calendar_event_get_cross_tenant,
    CALENDAR_EVENT_GET_CROSS_TENANT
);
oracle_test!(
    calendar_event_get_invalid_input,
    CALENDAR_EVENT_GET_INVALID_INPUT
);
oracle_test!(
    calendar_event_get_delegate_personal,
    CALENDAR_EVENT_GET_DELEGATE_PERSONAL
);
oracle_test!(
    calendar_event_get_entitlement_denied,
    CALENDAR_EVENT_GET_ENTITLEMENT_DENIED
);
status_mutant_test!(calendar_event_get_status_mutant, CALENDAR_EVENT_GET_SUCCESS);

#[tokio::test]
async fn calendar_event_get_no_tenant_filter_mutant() -> Result<(), BoxError> {
    run(
        &CALENDAR_EVENT_GET_NO_TENANT_MUTANT,
        Mutation::NoTenantFilter {
            function: "jmap_calendar_event_get(bigint,bigint[])",
            from: "c.mailbox_id = p_mailbox_id",
        },
    )
    .await
}

// CalendarEvent/query
oracle_test!(calendar_event_query_success, CALENDAR_EVENT_QUERY_SUCCESS);
oracle_test!(
    calendar_event_query_cross_tenant,
    CALENDAR_EVENT_QUERY_CROSS_TENANT
);
oracle_test!(
    calendar_event_query_invalid_input,
    CALENDAR_EVENT_QUERY_INVALID_INPUT
);
oracle_test!(
    calendar_event_query_delegate_personal,
    CALENDAR_EVENT_QUERY_DELEGATE_PERSONAL
);
oracle_test!(
    calendar_event_query_entitlement_denied,
    CALENDAR_EVENT_QUERY_ENTITLEMENT_DENIED
);
status_mutant_test!(
    calendar_event_query_status_mutant,
    CALENDAR_EVENT_QUERY_SUCCESS
);

// CalendarEvent/changes
oracle_test!(
    calendar_event_changes_success,
    CALENDAR_EVENT_CHANGES_SUCCESS
);
oracle_test!(
    calendar_event_changes_cross_tenant,
    CALENDAR_EVENT_CHANGES_CROSS_TENANT
);
oracle_test!(
    calendar_event_changes_invalid_input,
    CALENDAR_EVENT_CHANGES_INVALID_INPUT
);
oracle_test!(
    calendar_event_changes_state_mismatch,
    CALENDAR_EVENT_CHANGES_STATE_MISMATCH
);
oracle_test!(
    calendar_event_changes_delegate_personal,
    CALENDAR_EVENT_CHANGES_DELEGATE_PERSONAL
);
oracle_test!(
    calendar_event_changes_entitlement_denied,
    CALENDAR_EVENT_CHANGES_ENTITLEMENT_DENIED
);
status_mutant_test!(
    calendar_event_changes_status_mutant,
    CALENDAR_EVENT_CHANGES_SUCCESS
);

// CalendarEvent/set
oracle_test!(calendar_event_set_success, CALENDAR_EVENT_SET_SUCCESS);
oracle_test!(calendar_event_set_repeat, CALENDAR_EVENT_SET_REPEAT);
oracle_test!(
    calendar_event_set_update_destroy,
    CALENDAR_EVENT_SET_UPDATE_DESTROY
);
oracle_test!(
    calendar_event_set_cross_tenant,
    CALENDAR_EVENT_SET_CROSS_TENANT
);
oracle_test!(
    calendar_event_set_invalid_input,
    CALENDAR_EVENT_SET_INVALID_INPUT
);
oracle_test!(
    calendar_event_set_delegate_personal,
    CALENDAR_EVENT_SET_DELEGATE_PERSONAL
);
oracle_test!(
    calendar_event_set_entitlement_denied,
    CALENDAR_EVENT_SET_ENTITLEMENT_DENIED
);
status_mutant_test!(calendar_event_set_status_mutant, CALENDAR_EVENT_SET_SUCCESS);

// CalendarEvent/import
oracle_test!(calendar_event_import_success, CALENDAR_EVENT_IMPORT_SUCCESS);
oracle_test!(calendar_event_import_repeat, CALENDAR_EVENT_IMPORT_REPEAT);
oracle_test!(
    calendar_event_import_cross_tenant,
    CALENDAR_EVENT_IMPORT_CROSS_TENANT
);
oracle_test!(
    calendar_event_import_invalid_input,
    CALENDAR_EVENT_IMPORT_INVALID_INPUT
);
oracle_test!(
    calendar_event_import_delegate_personal,
    CALENDAR_EVENT_IMPORT_DELEGATE_PERSONAL
);
oracle_test!(
    calendar_event_import_entitlement_denied,
    CALENDAR_EVENT_IMPORT_ENTITLEMENT_DENIED
);
status_mutant_test!(
    calendar_event_import_status_mutant,
    CALENDAR_EVENT_IMPORT_SUCCESS
);

// CalendarEvent/freeBusy
oracle_test!(
    calendar_event_free_busy_success,
    CALENDAR_EVENT_FREE_BUSY_SUCCESS
);
oracle_test!(
    calendar_event_free_busy_cross_tenant,
    CALENDAR_EVENT_FREE_BUSY_CROSS_TENANT
);
oracle_test!(
    calendar_event_free_busy_invalid_input,
    CALENDAR_EVENT_FREE_BUSY_INVALID_INPUT
);
oracle_test!(
    calendar_event_free_busy_delegate_personal,
    CALENDAR_EVENT_FREE_BUSY_DELEGATE_PERSONAL
);
oracle_test!(
    calendar_event_free_busy_entitlement_denied,
    CALENDAR_EVENT_FREE_BUSY_ENTITLEMENT_DENIED
);
status_mutant_test!(
    calendar_event_free_busy_status_mutant,
    CALENDAR_EVENT_FREE_BUSY_SUCCESS
);

// CalendarEvent/queryFreeSlots
oracle_test!(
    calendar_event_query_free_slots_success,
    CALENDAR_EVENT_QUERY_FREE_SLOTS_SUCCESS
);
oracle_test!(
    calendar_event_query_free_slots_cross_tenant,
    CALENDAR_EVENT_QUERY_FREE_SLOTS_CROSS_TENANT
);
oracle_test!(
    calendar_event_query_free_slots_invalid_input,
    CALENDAR_EVENT_QUERY_FREE_SLOTS_INVALID_INPUT
);
oracle_test!(
    calendar_event_query_free_slots_delegate_personal,
    CALENDAR_EVENT_QUERY_FREE_SLOTS_DELEGATE_PERSONAL
);
oracle_test!(
    calendar_event_query_free_slots_entitlement_denied,
    CALENDAR_EVENT_QUERY_FREE_SLOTS_ENTITLEMENT_DENIED
);
status_mutant_test!(
    calendar_event_query_free_slots_status_mutant,
    CALENDAR_EVENT_QUERY_FREE_SLOTS_SUCCESS
);

// CalendarEvent/rsvp
oracle_test!(calendar_event_rsvp_success, CALENDAR_EVENT_RSVP_SUCCESS);
oracle_test!(calendar_event_rsvp_repeat, CALENDAR_EVENT_RSVP_REPEAT);
oracle_test!(calendar_event_rsvp_delegate, CALENDAR_EVENT_RSVP_DELEGATE);
oracle_test!(
    calendar_event_rsvp_cross_tenant,
    CALENDAR_EVENT_RSVP_CROSS_TENANT
);
oracle_test!(
    calendar_event_rsvp_invalid_input,
    CALENDAR_EVENT_RSVP_INVALID_INPUT
);
oracle_test!(
    calendar_event_rsvp_delegate_personal,
    CALENDAR_EVENT_RSVP_DELEGATE_PERSONAL
);
oracle_test!(
    calendar_event_rsvp_entitlement_denied,
    CALENDAR_EVENT_RSVP_ENTITLEMENT_DENIED
);
status_mutant_test!(
    calendar_event_rsvp_status_mutant,
    CALENDAR_EVENT_RSVP_SUCCESS
);

// CalendarEvent/counter
oracle_test!(
    calendar_event_counter_success,
    CALENDAR_EVENT_COUNTER_SUCCESS
);
oracle_test!(
    calendar_event_counter_cross_tenant,
    CALENDAR_EVENT_COUNTER_CROSS_TENANT
);
oracle_test!(
    calendar_event_counter_invalid_input,
    CALENDAR_EVENT_COUNTER_INVALID_INPUT
);
oracle_test!(
    calendar_event_counter_delegate_personal,
    CALENDAR_EVENT_COUNTER_DELEGATE_PERSONAL
);
oracle_test!(
    calendar_event_counter_entitlement_denied,
    CALENDAR_EVENT_COUNTER_ENTITLEMENT_DENIED
);
status_mutant_test!(
    calendar_event_counter_status_mutant,
    CALENDAR_EVENT_COUNTER_SUCCESS
);

// CalendarEvent/getShared
oracle_test!(
    calendar_event_get_shared_success,
    CALENDAR_EVENT_GET_SHARED_SUCCESS
);
oracle_test!(
    calendar_event_get_shared_cross_tenant,
    CALENDAR_EVENT_GET_SHARED_CROSS_TENANT
);
oracle_test!(
    calendar_event_get_shared_invalid_input,
    CALENDAR_EVENT_GET_SHARED_INVALID_INPUT
);
oracle_test!(
    calendar_event_get_shared_delegate_personal,
    CALENDAR_EVENT_GET_SHARED_DELEGATE_PERSONAL
);
oracle_test!(
    calendar_event_get_shared_entitlement_denied,
    CALENDAR_EVENT_GET_SHARED_ENTITLEMENT_DENIED
);
status_mutant_test!(
    calendar_event_get_shared_status_mutant,
    CALENDAR_EVENT_GET_SHARED_SUCCESS
);

// CalendarEvent/setOccurrence
oracle_test!(
    calendar_event_set_occurrence_success,
    CALENDAR_EVENT_SET_OCCURRENCE_SUCCESS
);
oracle_test!(
    calendar_event_set_occurrence_repeat,
    CALENDAR_EVENT_SET_OCCURRENCE_REPEAT
);
oracle_test!(
    calendar_event_set_occurrence_cross_tenant,
    CALENDAR_EVENT_SET_OCCURRENCE_CROSS_TENANT
);
oracle_test!(
    calendar_event_set_occurrence_invalid_input,
    CALENDAR_EVENT_SET_OCCURRENCE_INVALID_INPUT
);
oracle_test!(
    calendar_event_set_occurrence_delegate_personal,
    CALENDAR_EVENT_SET_OCCURRENCE_DELEGATE_PERSONAL
);
oracle_test!(
    calendar_event_set_occurrence_entitlement_denied,
    CALENDAR_EVENT_SET_OCCURRENCE_ENTITLEMENT_DENIED
);
status_mutant_test!(
    calendar_event_set_occurrence_status_mutant,
    CALENDAR_EVENT_SET_OCCURRENCE_SUCCESS
);

// CalendarEvent/resourceList
oracle_test!(
    calendar_event_resource_list_success,
    CALENDAR_EVENT_RESOURCE_LIST_SUCCESS
);
oracle_test!(
    calendar_event_resource_list_cross_tenant,
    CALENDAR_EVENT_RESOURCE_LIST_CROSS_TENANT
);
oracle_test!(
    calendar_event_resource_list_invalid_input,
    CALENDAR_EVENT_RESOURCE_LIST_INVALID_INPUT
);
oracle_test!(
    calendar_event_resource_list_delegate_personal,
    CALENDAR_EVENT_RESOURCE_LIST_DELEGATE_PERSONAL
);
oracle_test!(
    calendar_event_resource_list_entitlement_denied,
    CALENDAR_EVENT_RESOURCE_LIST_ENTITLEMENT_DENIED
);
status_mutant_test!(
    calendar_event_resource_list_status_mutant,
    CALENDAR_EVENT_RESOURCE_LIST_SUCCESS
);

// CalendarEvent/sendUpdate
oracle_test!(
    calendar_event_send_update_success,
    CALENDAR_EVENT_SEND_UPDATE_SUCCESS
);
oracle_test!(
    calendar_event_send_update_repeat,
    CALENDAR_EVENT_SEND_UPDATE_REPEAT
);
oracle_test!(
    calendar_event_send_update_cross_tenant,
    CALENDAR_EVENT_SEND_UPDATE_CROSS_TENANT
);
oracle_test!(
    calendar_event_send_update_invalid_input,
    CALENDAR_EVENT_SEND_UPDATE_INVALID_INPUT
);
oracle_test!(
    calendar_event_send_update_delegate_personal,
    CALENDAR_EVENT_SEND_UPDATE_DELEGATE_PERSONAL
);
oracle_test!(
    calendar_event_send_update_entitlement_denied,
    CALENDAR_EVENT_SEND_UPDATE_ENTITLEMENT_DENIED
);
status_mutant_test!(
    calendar_event_send_update_status_mutant,
    CALENDAR_EVENT_SEND_UPDATE_SUCCESS
);
