//! #369 CalendarEvent/* (frozen Go calendar.go:103-900, calendar_a3.go, calendar_import.go).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use chrono::{DateTime, Datelike, FixedOffset, Timelike, Utc};
use serde_json::Value;

use super::args::{decode, Kind};
use super::seam::{
    self, ics, not_found, parse_id_list, query, read, read_rows, read_sql, rsvp_on_behalf,
    send_imip, since_state, write, write_sql, Imip, ScopedQuery, Type,
};
use super::{
    always, go_compact, go_map, parse_id, Answer, Cx, Gate, Handled, Method, MethodError, Reply,
};

const CAPABILITY: &str = "urn:ietf:params:jmap:calendars";
const MAX_IMPORT_ICS_BYTES: usize = 1 << 20;
const MAX_IMPORT_EVENTS: usize = 1000;

pub(super) const METHODS: &[Method] = &[
    Method {
        name: "CalendarEvent/get",
        capability: CAPABILITY,
        app: "calendar",
        gate: Gate::Personal,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: get,
    },
    Method {
        name: "CalendarEvent/query",
        capability: CAPABILITY,
        app: "calendar",
        gate: Gate::Personal,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: query_events,
    },
    Method {
        name: "CalendarEvent/changes",
        capability: CAPABILITY,
        app: "calendar",
        gate: Gate::Personal,
        account: true,
        mutator: false,
        state: true,
        ready: always,
        run: changes,
    },
    Method {
        name: "CalendarEvent/set",
        capability: CAPABILITY,
        app: "calendar",
        gate: Gate::Personal,
        account: true,
        mutator: true,
        state: false,
        ready: always,
        run: set,
    },
    Method {
        name: "CalendarEvent/import",
        capability: CAPABILITY,
        app: "calendar",
        gate: Gate::Personal,
        account: true,
        mutator: true,
        state: false,
        ready: always,
        run: import_ics,
    },
    Method {
        name: "CalendarEvent/freeBusy",
        capability: CAPABILITY,
        app: "calendar",
        gate: Gate::Personal,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: free_busy,
    },
    Method {
        name: "CalendarEvent/queryFreeSlots",
        capability: CAPABILITY,
        app: "calendar",
        gate: Gate::Personal,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: query_free_slots,
    },
    Method {
        name: "CalendarEvent/rsvp",
        capability: CAPABILITY,
        app: "calendar",
        gate: Gate::Personal,
        account: true,
        mutator: true,
        state: false,
        ready: always,
        run: rsvp,
    },
    Method {
        name: "CalendarEvent/counter",
        capability: CAPABILITY,
        app: "calendar",
        gate: Gate::Personal,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: counter,
    },
    Method {
        name: "CalendarEvent/getShared",
        capability: CAPABILITY,
        app: "calendar",
        gate: Gate::Personal,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: get_shared,
    },
    Method {
        name: "CalendarEvent/setOccurrence",
        capability: CAPABILITY,
        app: "calendar",
        gate: Gate::Personal,
        account: true,
        mutator: true,
        state: false,
        ready: always,
        run: set_occurrence,
    },
    Method {
        name: "CalendarEvent/resourceList",
        capability: CAPABILITY,
        app: "calendar",
        gate: Gate::Personal,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: resource_list,
    },
    Method {
        name: "CalendarEvent/sendUpdate",
        capability: CAPABILITY,
        app: "calendar",
        gate: Gate::Personal,
        account: true,
        mutator: true,
        state: false,
        ready: always,
        run: send_update,
    },
];

fn invalid_arg_id(field: &str) -> MethodError {
    let mut detail = String::from("invalid ");
    detail.push_str(field);
    MethodError::new("invalidArguments", &detail)
}

fn parse_arg(value: &str, field: &str) -> Result<i64, MethodError> {
    parse_id(value).ok_or_else(|| invalid_arg_id(field))
}

fn non_null_raw(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim).filter(|s| !s.is_empty() && *s != "null")
}

fn get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("ids", Kind::Strings),
                ("properties", Kind::Strings),
            ],
        )?;
        let scope = seam::resolve(cx, args.str("accountId")).await?;
        let (pg_ids, bad) = match args.strings("ids") {
            Some(ids) => parse_id_list(ids),
            None => (None, Vec::new()),
        };
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT jmap_calendar_event_get($1,$3::bigint[])::text"),
            &[(&pg_ids, Type::INT8_ARRAY)],
        )
        .await?;
        let out = if bad.is_empty() {
            raw
        } else {
            not_found(&raw, &bad)
        };
        Ok(Answer {
            name: cx.method().name,
            args: out,
        })
    })
}

fn query_events<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("filter", Kind::Raw),
                ("sort", Kind::Raw),
                ("position", Kind::Int),
                ("limit", Kind::Int),
            ],
        )?;
        let scope = seam::resolve(cx, args.str("accountId")).await?;
        let filter = non_null_raw(args.raw("filter"));
        let sort = non_null_raw(args.raw("sort"));
        let position = i32::try_from(args.int("position"))
            .map_err(|_| MethodError::new("invalidArguments", "invalid arguments"))?;
        let raw_limit = args.int("limit");
        let limit = if raw_limit <= 0 || raw_limit > 256 {
            50i32
        } else {
            raw_limit as i32
        };
        let out = read(
            cx,
            &scope,
            read_sql!(
                "SELECT jmap_calendar_event_query($1,$3::text::jsonb,$4::text::jsonb,$5,$6)::text"
            ),
            &[
                (&filter, Type::TEXT),
                (&sort, Type::TEXT),
                (&position, Type::INT4),
                (&limit, Type::INT4),
            ],
        )
        .await?;
        Ok(Answer {
            name: cx.method().name,
            args: out,
        })
    })
}

fn changes<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = decode(
            cx.args(),
            "",
            &[("accountId", Kind::Str), ("sinceState", Kind::Str)],
        )?;
        let scope = seam::resolve(cx, args.str("accountId")).await?;
        let since = args.str("sinceState");
        since_state(since)?;
        let out = read(
            cx,
            &scope,
            read_sql!("SELECT jmap_calendar_event_changes($1,$3)::text"),
            &[(&since, Type::TEXT)],
        )
        .await?;
        Ok(Answer {
            name: cx.method().name,
            args: out,
        })
    })
}

fn is_json_object_raw(raw: Option<&str>) -> Option<&str> {
    let text = non_null_raw(raw)?;
    text.starts_with('{').then_some(text)
}

fn set<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("create", Kind::Raw),
                ("update", Kind::Raw),
                ("destroy", Kind::Strings),
            ],
        )?;
        let scope = seam::resolve(cx, args.str("accountId")).await?;
        let create_raw = is_json_object_raw(args.raw("create"));
        let update_raw = is_json_object_raw(args.raw("update"));
        let destroy_ids = args.strings("destroy").filter(|ids| !ids.is_empty());

        let mut create_out = None;
        if let Some(creates) = create_raw {
            let raw = write(
                cx,
                &scope,
                "calendar_event.create",
                write_sql!("SELECT jmap_calendar_event_set_create($1,$2,$4,$5::text::jsonb)::text"),
                &[(&cx.email(), Type::TEXT), (&creates, Type::TEXT)],
            )
            .await?;
            create_out = Some(finalize_create(cx, &scope, creates, &raw).await);
        }

        let mut update_out = None;
        if let Some(updates) = update_raw {
            let raw = write(
                cx,
                &scope,
                "calendar_event.update",
                write_sql!("SELECT jmap_calendar_event_set_update($1,$4::text::jsonb)::text"),
                &[(&updates, Type::TEXT)],
            )
            .await?;
            update_out = Some(raw);
        }

        let mut destroy_out = None;
        if let Some(ids) = destroy_ids {
            let (pg_ids, bad) = parse_id_list(ids);
            let raw = write(
                cx,
                &scope,
                "calendar_event.destroy",
                write_sql!("SELECT jmap_calendar_event_set_destroy($1,$4::bigint[])::text"),
                &[(&pg_ids, Type::INT8_ARRAY)],
            )
            .await?;
            destroy_out = Some(if bad.is_empty() {
                raw
            } else {
                add_not_destroyed(&raw, &bad)
            });
        }

        let merged = merge_set_results(
            create_out.as_deref(),
            update_out.as_deref(),
            destroy_out.as_deref(),
        );
        Ok(Answer {
            name: cx.method().name,
            args: merged,
        })
    })
}

async fn finalize_create(cx: &Cx<'_>, scope: &seam::Scope, creates_raw: &str, raw: &str) -> String {
    let Ok(mut resp_obj) = serde_json::from_str::<BTreeMap<String, Value>>(raw) else {
        return raw.to_owned();
    };
    let Some(created_obj) = resp_obj.get("created").and_then(Value::as_object) else {
        return raw.to_owned();
    };

    let mut id_to_client: BTreeMap<String, String> = BTreeMap::new();
    let mut event_ids: Vec<i64> = Vec::new();
    for (client_key, val) in created_obj {
        if let Some(id_str) = val.as_str() {
            if let Some(id_num) = parse_id(id_str) {
                id_to_client.insert(id_str.to_owned(), client_key.clone());
                event_ids.push(id_num);
            }
        }
    }
    if event_ids.is_empty() {
        return raw.to_owned();
    }

    if let Ok(bookings_raw) = write(
        cx,
        scope,
        "calendar_event.finalize_bookings",
        write_sql!("SELECT calendar_finalize_create_bookings($1,$4::bigint[])::text"),
        &[(&event_ids, Type::INT8_ARRAY)],
    )
    .await
    {
        if let Some(remapped) = merge_resource_bookings(&bookings_raw, &id_to_client) {
            resp_obj.insert("resourceBookings".to_owned(), remapped);
        }
    }

    let org_email = extract_delegated_from(creates_raw).unwrap_or_else(|| cx.email().to_owned());
    if let Ok(invite_rows) = read_rows(
        cx,
        scope,
        read_sql!("SELECT calendar_finalize_create_invites($1,$3::bigint[],$4,$5)::text"),
        &[
            (&event_ids, Type::INT8_ARRAY),
            (&org_email, Type::TEXT),
            (&"", Type::TEXT),
        ],
    )
    .await
    {
        for payload in invite_rows {
            send_invite_from_payload(cx, &payload);
        }
    }

    serde_json::to_string(&resp_obj).unwrap_or_else(|_| raw.to_owned())
}

fn merge_resource_bookings(
    bookings_raw: &str,
    id_to_client: &BTreeMap<String, String>,
) -> Option<Value> {
    let parsed = serde_json::from_str::<BTreeMap<String, Value>>(bookings_raw).ok()?;
    let mut remapped = serde_json::Map::new();
    for (event_id, booking) in parsed {
        let key = id_to_client.get(&event_id).cloned().unwrap_or(event_id);
        remapped.insert(key, booking);
    }
    (!remapped.is_empty()).then_some(Value::Object(remapped))
}

fn extract_delegated_from(creates_raw: &str) -> Option<String> {
    let parsed = serde_json::from_str::<BTreeMap<String, Value>>(creates_raw).ok()?;
    for val in parsed.values() {
        if let Some(email) = val
            .get("delegatedFrom")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            return Some(email.to_owned());
        }
    }
    None
}

fn add_not_destroyed(raw: &str, bad: &[String]) -> String {
    let Ok(mut obj) = serde_json::from_str::<BTreeMap<String, Value>>(raw) else {
        return raw.to_owned();
    };
    let mut err_map = obj
        .get("notDestroyed")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for id in bad {
        let mut entry = serde_json::Map::new();
        entry.insert("type".to_owned(), Value::String("notFound".to_owned()));
        err_map.insert(id.clone(), Value::Object(entry));
    }
    obj.insert("notDestroyed".to_owned(), Value::Object(err_map));
    serde_json::to_string(&obj).unwrap_or_else(|_| raw.to_owned())
}

fn merge_set_results(create: Option<&str>, update: Option<&str>, destroy: Option<&str>) -> String {
    let parts: Vec<&str> = [create, update, destroy].into_iter().flatten().collect();
    if parts.is_empty() {
        return "{}".to_owned();
    }
    if parts.len() == 1 {
        return go_compact(parts[0]).unwrap_or_else(|| parts[0].to_owned());
    }
    let mut merged: BTreeMap<String, Value> = BTreeMap::new();
    for part in parts {
        let Ok(obj) = serde_json::from_str::<BTreeMap<String, Value>>(part) else {
            continue;
        };
        for (k, v) in obj {
            merged.insert(k, v);
        }
    }
    let entries: Vec<(&str, Value)> = merged
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();
    go_map(entries)
}

fn import_ics<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("calendarId", Kind::Str),
                ("ics", Kind::Str),
                ("strategy", Kind::Str),
            ],
        )?;
        let ics_data = args.str("ics");
        if ics_data.is_empty() {
            return Err(MethodError::new("invalidArguments", "ics is required"));
        }
        if ics_data.len() > MAX_IMPORT_ICS_BYTES {
            return Err(MethodError::new("invalidArguments", "ics file too large"));
        }
        let scope = seam::resolve(cx, args.str("accountId")).await?;
        let cal_id = parse_arg(args.str("calendarId"), "calendarId")?;

        let components = ics::split_components(ics_data);
        let mut events = Vec::new();
        let mut parse_errors = Vec::new();
        for comp in components {
            match ics::parse_component(&comp) {
                Ok(ev) => events.push(ev),
                Err(err) => {
                    let mut msg = String::from("parse error: ");
                    msg.push_str(err);
                    parse_errors.push(msg);
                }
            }
        }
        if events.len() > MAX_IMPORT_EVENTS {
            return Err(MethodError::new(
                "invalidArguments",
                "too many events in ics file",
            ));
        }

        let events_json = ics::events_to_json(&events);
        let strategy = match args.str("strategy") {
            "" => "skip",
            s => s,
        };
        let raw = write(
            cx,
            &scope,
            "calendar_event.import",
            write_sql!("SELECT calendar_import_ics($1,$2,$4,$5,$6::text::jsonb,$7)::text"),
            &[
                (&cx.email(), Type::TEXT),
                (&cal_id, Type::INT8),
                (&events_json, Type::TEXT),
                (&strategy, Type::TEXT),
            ],
        )
        .await?;

        let out = if parse_errors.is_empty() {
            raw
        } else {
            attach_parse_errors(&raw, &parse_errors)
        };
        Ok(Answer {
            name: cx.method().name,
            args: out,
        })
    })
}

fn attach_parse_errors(raw: &str, parse_errors: &[String]) -> String {
    let Ok(mut obj) = serde_json::from_str::<BTreeMap<String, Value>>(raw) else {
        return raw.to_owned();
    };
    obj.insert(
        "parseErrors".to_owned(),
        Value::Array(
            parse_errors
                .iter()
                .map(|s| Value::String(s.clone()))
                .collect(),
        ),
    );
    serde_json::to_string(&obj).unwrap_or_else(|_| raw.to_owned())
}

fn parse_user_ids(ids: &[String]) -> Result<Vec<i64>, MethodError> {
    let mut parsed = Vec::with_capacity(ids.len());
    for (idx, id) in ids.iter().enumerate() {
        let Some(v) = parse_id(id) else {
            let mut detail = String::new();
            let _ = write!(&mut detail, "invalid userIds[{idx}]");
            return Err(MethodError::new("invalidArguments", &detail));
        };
        parsed.push(v);
    }
    Ok(parsed)
}

fn free_busy<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("userIds", Kind::Strings),
                ("start", Kind::Str),
                ("end", Kind::Str),
            ],
        )?;
        let scope = seam::resolve(cx, args.str("accountId")).await?;
        let user_ids = match args.strings("userIds") {
            Some(ids) if !ids.is_empty() => Some(parse_user_ids(ids)?),
            _ => None,
        };
        let start = args.str("start");
        let end = args.str("end");
        let out = read(
            cx,
            &scope,
            read_sql!(
                "SELECT calendar_free_busy($1,$3::bigint[],$4::text::timestamptz,$5::text::timestamptz)::text"
            ),
            &[
                (&user_ids, Type::INT8_ARRAY),
                (&start, Type::TEXT),
                (&end, Type::TEXT),
            ],
        )
        .await?;
        Ok(Answer {
            name: cx.method().name,
            args: out,
        })
    })
}

fn query_free_slots<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("userIds", Kind::Strings),
                ("start", Kind::Str),
                ("end", Kind::Str),
                ("durationMinutes", Kind::Int),
                ("slotIntervalMinutes", Kind::Int),
                ("workingStartTime", Kind::Str),
                ("workingEndTime", Kind::Str),
                ("maxSlots", Kind::Int),
            ],
        )?;
        let scope = seam::resolve(cx, args.str("accountId")).await?;
        let user_ids = parse_user_ids(args.strings("userIds").unwrap_or(&[]))?;
        if user_ids.is_empty() {
            return Err(MethodError::new(
                "invalidArguments",
                "at least one userId is required",
            ));
        }
        let duration = match args.int("durationMinutes") {
            n if n > 0 => i32::try_from(n).unwrap_or(i32::MAX),
            _ => 30,
        };
        let slot_interval = match args.int("slotIntervalMinutes") {
            n if n > 0 => i32::try_from(n).unwrap_or(i32::MAX),
            _ => 15,
        };
        let work_start = match args.str("workingStartTime") {
            "" => "09:00",
            s => s,
        };
        let work_end = match args.str("workingEndTime") {
            "" => "17:00",
            s => s,
        };
        let max_slots = match args.int("maxSlots") {
            n if n > 0 && n <= 100 => n as i32,
            _ => 20,
        };
        let start = args.str("start");
        let end = args.str("end");

        let out = read(
            cx,
            &scope,
            read_sql!(
                "SELECT calendar_find_free_slots($1,$3::bigint[],$4::text::timestamptz,$5::text::timestamptz,$6,$7,$8::text::time,$9::text::time,$10)::text"
            ),
            &[
                (&user_ids, Type::INT8_ARRAY),
                (&start, Type::TEXT),
                (&end, Type::TEXT),
                (&duration, Type::INT4),
                (&slot_interval, Type::INT4),
                (&work_start, Type::TEXT),
                (&work_end, Type::TEXT),
                (&max_slots, Type::INT4),
            ],
        )
        .await?;
        Ok(Answer {
            name: cx.method().name,
            args: out,
        })
    })
}

fn rsvp<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("eventId", Kind::Str),
                ("status", Kind::Str),
                ("onBehalfOf", Kind::Str),
            ],
        )?;
        let status = args.str("status");
        if !matches!(status, "accepted" | "tentative" | "declined") {
            return Err(MethodError::new(
                "invalidArguments",
                "status must be accepted, tentative, or declined",
            ));
        }
        let event_id = args.str("eventId").trim().parse::<i64>().unwrap_or(0);
        let on_behalf_of = args.str("onBehalfOf");
        let out = if on_behalf_of.is_empty() {
            let scope = seam::resolve(cx, args.str("accountId")).await?;
            write(
                cx,
                &scope,
                "calendar_event.rsvp",
                write_sql!("SELECT jmap_calendar_event_rsvp($1,$4,$5,$6)::text"),
                &[
                    (&event_id, Type::INT8),
                    (&cx.email(), Type::TEXT),
                    (&status, Type::TEXT),
                ],
            )
            .await?
        } else {
            rsvp_on_behalf(cx, on_behalf_of, event_id, status).await?
        };
        Ok(Answer {
            name: cx.method().name,
            args: out,
        })
    })
}

fn counter<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("eventId", Kind::Str),
                ("start", Kind::Str),
                ("end", Kind::Str),
            ],
        )?;
        let start = args.str("start");
        let end = args.str("end");
        if start.is_empty() || end.is_empty() {
            return Err(MethodError::new(
                "invalidArguments",
                "start and end are required",
            ));
        }
        let scope = seam::resolve(cx, args.str("accountId")).await?;
        let event_id = args.str("eventId").trim().parse::<i64>().unwrap_or(0);
        let attendee_name: Option<&str> = None;
        let out = read(
            cx,
            &scope,
            read_sql!(
                "SELECT jmap_calendar_event_counter($1,$3,$4::text::timestamptz,$5::text::timestamptz,$6,$7)::text"
            ),
            &[
                (&event_id, Type::INT8),
                (&start, Type::TEXT),
                (&end, Type::TEXT),
                (&cx.email(), Type::TEXT),
                (&attendee_name, Type::TEXT),
            ],
        )
        .await?;
        send_counter_from_payload(cx, &out);
        Ok(Answer {
            name: cx.method().name,
            args: out,
        })
    })
}

fn get_shared<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("ownerEmail", Kind::Str),
                ("after", Kind::Str),
                ("before", Kind::Str),
            ],
        )?;
        let scope = seam::resolve(cx, args.str("accountId")).await?;
        let owner_email = args.str("ownerEmail");
        if owner_email.is_empty() {
            return Err(MethodError::new(
                "invalidArguments",
                "ownerEmail is required",
            ));
        }
        let after = non_empty_str(args.str("after"));
        let before = non_empty_str(args.str("before"));
        let out = query(
            cx,
            &scope,
            ScopedQuery::CalendarEventGetShared {
                owner_email,
                after,
                before,
            },
        )
        .await?;
        Ok(Answer {
            name: cx.method().name,
            args: out,
        })
    })
}

fn non_empty_str(s: &str) -> Option<&str> {
    (!s.is_empty()).then_some(s)
}

fn set_occurrence<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("masterId", Kind::Str),
                ("recurrenceId", Kind::Str),
                ("scope", Kind::Str),
                ("patch", Kind::Raw),
            ],
        )?;
        let scope = seam::resolve(cx, args.str("accountId")).await?;
        let master_id = parse_arg(args.str("masterId"), "masterId")?;
        let occ_scope = args.str("scope");
        if !matches!(occ_scope, "this" | "following" | "series") {
            return Err(MethodError::new(
                "invalidArguments",
                "scope must be this, following, or series",
            ));
        }
        let patch = non_null_raw(args.raw("patch")).unwrap_or("{}");
        let recurrence_id = args.str("recurrenceId");
        let out = write(
            cx,
            &scope,
            "calendar_event.set_occurrence",
            write_sql!(
                "SELECT jmap_calendar_event_set_occurrence($1,$4,$5::text::timestamptz,$6,$7::text::jsonb)::text"
            ),
            &[
                (&master_id, Type::INT8),
                (&recurrence_id, Type::TEXT),
                (&occ_scope, Type::TEXT),
                (&patch, Type::TEXT),
            ],
        )
        .await?;
        if let Some(payload) = extract_invite_payload(&out) {
            send_invite_from_payload(cx, &payload);
        }
        Ok(Answer {
            name: cx.method().name,
            args: out,
        })
    })
}

fn resource_list<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = decode(cx.args(), "", &[("accountId", Kind::Str)])?;
        let scope = seam::resolve(cx, args.str("accountId")).await?;
        let out = read(
            cx,
            &scope,
            read_sql!("SELECT jmap_calendar_resource_list($1)::text"),
            &[],
        )
        .await?;
        Ok(Answer {
            name: cx.method().name,
            args: out,
        })
    })
}

fn send_update<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = decode(
            cx.args(),
            "",
            &[("accountId", Kind::Str), ("eventId", Kind::Str)],
        )?;
        let scope = seam::resolve(cx, args.str("accountId")).await?;
        let event_id = parse_arg(args.str("eventId"), "eventId")?;
        let out = write(
            cx,
            &scope,
            "calendar_event.send_update",
            write_sql!("SELECT jmap_calendar_event_send_update($1,$4)::text"),
            &[(&event_id, Type::INT8)],
        )
        .await?;
        send_invite_from_payload(cx, &out);
        Ok(Answer {
            name: cx.method().name,
            args: out,
        })
    })
}

fn extract_invite_payload(result: &str) -> Option<String> {
    let val = serde_json::from_str::<Value>(result).ok()?;
    let payload = val.get("invitePayload")?;
    (!payload.is_null())
        .then(|| serde_json::to_string(payload).ok())
        .flatten()
}

// ---- iMIP MIME construction (caldav/imip.go + calendar.go + calendar_a3.go) ----

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct InvitePayload {
    #[serde(rename = "type")]
    kind: String,
    method: String,
    uid: String,
    title: String,
    description: String,
    location: String,
    start: String,
    end: String,
    all_day: bool,
    timezone: String,
    rrule: String,
    recurrence_id: String,
    sequence: i64,
    status: String,
    organizer_email: String,
    organizer_name: String,
    attendees: Vec<PayloadAttendee>,
}

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct PayloadAttendee {
    email: String,
    name: String,
    role: String,
    participation_status: String,
    expect_reply: bool,
    delegated_from: String,
}

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct CounterPayload {
    uid: String,
    title: String,
    description: String,
    location: String,
    start: String,
    end: String,
    all_day: bool,
    timezone: String,
    sequence: i64,
    organizer_email: String,
    organizer_name: String,
    attendee_email: String,
    attendee_name: String,
}

struct BuiltImip {
    uid: String,
    from: String,
    recipients: Vec<String>,
    mime: String,
}

fn send_invite_from_payload(cx: &Cx<'_>, payload: &str) {
    if let Ok(Some(built)) = build_invite_mime(payload) {
        send_imip(
            cx,
            Imip {
                message_id: built.uid,
                from: built.from,
                recipients: built.recipients,
                mime: built.mime,
            },
        );
    }
}

fn send_counter_from_payload(cx: &Cx<'_>, payload: &str) {
    if let Ok(built) = build_counter_mime(payload) {
        send_imip(
            cx,
            Imip {
                message_id: built.uid,
                from: built.from,
                recipients: built.recipients,
                mime: built.mime,
            },
        );
    }
}

fn build_invite_mime(payload: &str) -> Result<Option<BuiltImip>, &'static str> {
    let p: InvitePayload = serde_json::from_str(payload).map_err(|_| "invalid invite payload")?;
    if !p.kind.is_empty() || p.attendees.is_empty() {
        return Ok(None);
    }
    let start = DateTime::parse_from_rfc3339(&p.start).map_err(|_| "invalid start")?;
    let end = DateTime::parse_from_rfc3339(&p.end).map_err(|_| "invalid end")?;
    let recurrence_id = if p.recurrence_id.is_empty() {
        None
    } else {
        Some(DateTime::parse_from_rfc3339(&p.recurrence_id).map_err(|_| "invalid recurrenceId")?)
    };
    let method = if p.method.eq_ignore_ascii_case("CANCEL") {
        "CANCEL"
    } else {
        "REQUEST"
    };

    let mut recipients = Vec::new();
    for att in &p.attendees {
        if !att.email.is_empty() && att.email != p.organizer_email {
            recipients.push(att.email.clone());
        }
    }
    if recipients.is_empty() {
        return Ok(None);
    }

    let mime = render_imip_mime(RenderParams {
        method,
        uid: &p.uid,
        title: &p.title,
        description: &p.description,
        location: &p.location,
        start,
        end,
        all_day: p.all_day,
        timezone: &p.timezone,
        rrule: &p.rrule,
        recurrence_id,
        sequence: p.sequence,
        status: &p.status,
        organizer_email: &p.organizer_email,
        organizer_name: &p.organizer_name,
        attendees: &p.attendees,
        from_email: &p.organizer_email,
        from_name: &p.organizer_name,
    });

    Ok(Some(BuiltImip {
        uid: p.uid,
        from: p.organizer_email,
        recipients,
        mime,
    }))
}

fn build_counter_mime(payload: &str) -> Result<BuiltImip, &'static str> {
    let p: CounterPayload = serde_json::from_str(payload).map_err(|_| "invalid counter payload")?;
    if p.organizer_email.is_empty() || p.attendee_email.is_empty() {
        return Err("counter payload missing organizer or attendee");
    }
    let start = DateTime::parse_from_rfc3339(&p.start).map_err(|_| "invalid start")?;
    let end = DateTime::parse_from_rfc3339(&p.end).map_err(|_| "invalid end")?;

    let att = [PayloadAttendee {
        email: p.attendee_email.clone(),
        name: p.attendee_name.clone(),
        role: "attendee".to_owned(),
        participation_status: String::new(),
        expect_reply: false,
        delegated_from: String::new(),
    }];
    let mime = render_imip_mime(RenderParams {
        method: "COUNTER",
        uid: &p.uid,
        title: &p.title,
        description: &p.description,
        location: &p.location,
        start,
        end,
        all_day: p.all_day,
        timezone: &p.timezone,
        rrule: "",
        recurrence_id: None,
        sequence: p.sequence,
        status: "",
        organizer_email: &p.organizer_email,
        organizer_name: &p.organizer_name,
        attendees: &att,
        from_email: &p.attendee_email,
        from_name: &p.attendee_name,
    });

    Ok(BuiltImip {
        uid: p.uid,
        from: p.attendee_email,
        recipients: vec![p.organizer_email],
        mime,
    })
}

struct RenderParams<'a> {
    method: &'a str,
    uid: &'a str,
    title: &'a str,
    description: &'a str,
    location: &'a str,
    start: DateTime<FixedOffset>,
    end: DateTime<FixedOffset>,
    all_day: bool,
    timezone: &'a str,
    rrule: &'a str,
    recurrence_id: Option<DateTime<FixedOffset>>,
    sequence: i64,
    status: &'a str,
    organizer_email: &'a str,
    organizer_name: &'a str,
    attendees: &'a [PayloadAttendee],
    from_email: &'a str,
    from_name: &'a str,
}

fn render_imip_mime(p: RenderParams<'_>) -> String {
    let now = Utc::now();
    let nanos = now.timestamp_nanos_opt().unwrap_or(0);
    let mut boundary = String::from("mailserver-imip-");
    let _ = write!(&mut boundary, "{nanos}");

    let safe_from_name = strip_header_ctrl(p.from_name);
    let safe_from_email = strip_header_ctrl(p.from_email);
    let safe_title = strip_header_ctrl(p.title);
    let label = match p.method {
        "REQUEST" => "Invitation",
        "CANCEL" => "Cancellation",
        "COUNTER" => "Counter Proposal",
        _ => "Notification",
    };

    let known_tz = !p.timezone.is_empty()
        && p.timezone != "UTC"
        && valid_tzid(p.timezone)
        && matches!(ics::load_location(p.timezone), ics::Zone::Tz(_));

    let mut text = String::new();
    let _ = writeln!(&mut text, "{label}: {safe_title}");
    text.push_str("When: ");
    push_human_time(&mut text, p.start, p.all_day, p.timezone);
    if !p.all_day {
        text.push_str(" - ");
        push_human_time(&mut text, p.end, p.all_day, p.timezone);
    }
    text.push('\n');
    if !p.location.is_empty() {
        let _ = writeln!(&mut text, "Where: {}", p.location);
    }
    if !p.organizer_email.is_empty() {
        let _ = writeln!(
            &mut text,
            "Organizer: {} <{}>",
            p.organizer_name, p.organizer_email
        );
    }
    if !p.attendees.is_empty() {
        text.push_str("Attendees:\n");
        for att in p.attendees {
            let _ = writeln!(
                &mut text,
                "  - {} <{}> ({})",
                att.name, att.email, att.participation_status
            );
        }
    }
    if !p.description.is_empty() {
        let _ = writeln!(&mut text, "\n{}", p.description);
    }

    let ical = build_itip_calendar(&p, known_tz, now);

    let mut to_addrs = Vec::new();
    if !p.organizer_email.is_empty() && p.organizer_email != p.from_email {
        let mut entry = strip_header_ctrl(p.organizer_name);
        entry.push_str(" <");
        entry.push_str(&strip_header_ctrl(p.organizer_email));
        entry.push('>');
        to_addrs.push(entry);
    }
    for att in p.attendees {
        if att.email != p.from_email {
            let mut entry = strip_header_ctrl(&att.name);
            entry.push_str(" <");
            entry.push_str(&strip_header_ctrl(&att.email));
            entry.push('>');
            to_addrs.push(entry);
        }
    }
    if to_addrs.is_empty() {
        to_addrs.push(safe_from_email.clone());
    }

    let mut date_str = String::new();
    push_rfc1123z(&mut date_str, now);

    let mut mail = String::new();
    let _ = write!(
        &mut mail,
        "From: {safe_from_name} <{safe_from_email}>\r\n\
         To: {}\r\n\
         Subject: {label}: {safe_title}\r\n\
         Date: {date_str}\r\n\
         Message-ID: <{nanos}@mailserver>\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/alternative; boundary={boundary}\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         {text}\r\n\
         --{boundary}\r\n\
         Content-Type: text/calendar; method={}; component=VEVENT; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\
         \r\n\
         {ical}\r\n\
         --{boundary}--\r\n",
        to_addrs.join(", "),
        p.method,
    );
    mail
}

fn build_itip_calendar(p: &RenderParams<'_>, known_tz: bool, now: DateTime<Utc>) -> String {
    let mut cal = String::new();
    let _ = write!(
        &mut cal,
        "BEGIN:VCALENDAR\r\n\
         VERSION:2.0\r\n\
         METHOD:{}\r\n\
         PRODID:-//Mailserver//iMIP//EN\r\n\
         BEGIN:VEVENT\r\n",
        p.method,
    );
    cal.push_str("DTSTAMP:");
    push_ical_utc(&mut cal, now);
    cal.push_str("\r\n");
    let _ = write!(&mut cal, "SEQUENCE:{}\r\n", p.sequence);
    push_folded(&mut cal, "UID:", &escape_ical_text(p.uid));
    push_folded(&mut cal, "SUMMARY:", &escape_ical_text(p.title));
    if !p.description.is_empty() {
        push_folded(&mut cal, "DESCRIPTION:", &escape_ical_text(p.description));
    }
    if !p.location.is_empty() {
        push_folded(&mut cal, "LOCATION:", &escape_ical_text(p.location));
    }

    if p.all_day {
        cal.push_str("DTSTART;VALUE=DATE:");
        push_ical_date(&mut cal, p.start);
        cal.push_str("\r\nDTEND;VALUE=DATE:");
        push_ical_date(&mut cal, p.end);
        cal.push_str("\r\n");
    } else if known_tz {
        let safe_tz = param_value(p.timezone);
        cal.push_str("DTSTART;TZID=");
        cal.push_str(&safe_tz);
        cal.push(':');
        push_ical_local(&mut cal, p.start);
        cal.push_str("\r\nDTEND;TZID=");
        cal.push_str(&safe_tz);
        cal.push(':');
        push_ical_local(&mut cal, p.end);
        cal.push_str("\r\n");
    } else {
        cal.push_str("DTSTART:");
        push_ical_utc(&mut cal, p.start.with_timezone(&Utc));
        cal.push_str("\r\nDTEND:");
        push_ical_utc(&mut cal, p.end.with_timezone(&Utc));
        cal.push_str("\r\n");
    }

    if !p.status.is_empty() {
        let _ = write!(&mut cal, "STATUS:{}\r\n", p.status.to_ascii_uppercase());
    }
    if let Some(rule) = clean_rrule(p.rrule) {
        cal.push_str("RRULE:");
        cal.push_str(&rule);
        cal.push_str("\r\n");
    }
    if let Some(rec_id) = p.recurrence_id {
        cal.push_str("RECURRENCE-ID:");
        push_ical_utc(&mut cal, rec_id.with_timezone(&Utc));
        cal.push_str("\r\n");
    }

    let org = PayloadAttendee {
        email: p.organizer_email.to_owned(),
        name: p.organizer_name.to_owned(),
        role: "organizer".to_owned(),
        ..Default::default()
    };
    if let Some(line) = build_attendee_line("ORGANIZER", &org) {
        cal.push_str(&line);
        cal.push_str("\r\n");
    }
    for att in p.attendees {
        if let Some(line) = build_attendee_line("ATTENDEE", att) {
            cal.push_str(&line);
            cal.push_str("\r\n");
        }
    }
    cal.push_str("END:VEVENT\r\nEND:VCALENDAR\r\n");
    cal
}

fn valid_tzid(tzid: &str) -> bool {
    !tzid.is_empty()
        && tzid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '+' | '.'))
}

fn strip_header_ctrl(s: &str) -> String {
    s.chars()
        .filter(|&c| c != '\r' && c != '\n' && c != '\0')
        .collect()
}

fn strip_param_ctrl(s: &str) -> String {
    s.chars()
        .filter(|&c| (c as u32) >= 0x20 && (c as u32) != 0x7F)
        .collect()
}

fn param_value(s: &str) -> String {
    let cleaned = strip_param_ctrl(s);
    if cleaned.is_empty() {
        return "\"\"".to_owned();
    }
    if cleaned.chars().any(|c| matches!(c, '"' | ';' | ':' | ',')) {
        let mut quoted = String::with_capacity(cleaned.len() + 2);
        quoted.push('"');
        for c in cleaned.chars() {
            match c {
                '"' => {}
                '\\' => quoted.push_str("\\\\"),
                _ => quoted.push(c),
            }
        }
        quoted.push('"');
        quoted
    } else {
        cleaned
    }
}

fn param_value_quoted(s: &str) -> String {
    let cleaned = strip_param_ctrl(s);
    let mut quoted = String::with_capacity(cleaned.len() + 2);
    quoted.push('"');
    for c in cleaned.chars() {
        match c {
            '"' => {}
            '\\' => quoted.push_str("\\\\"),
            _ => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

fn escape_ical_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\r' | '\0' => {}
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

fn push_folded(out: &mut String, prefix: &str, value: &str) {
    let mut full = String::with_capacity(prefix.len() + value.len());
    full.push_str(prefix);
    full.push_str(value);

    let mut line_bytes = 0usize;
    for ch in full.chars() {
        let len = ch.len_utf8();
        if line_bytes + len > 75 && line_bytes > 0 {
            out.push_str("\r\n ");
            line_bytes = 1;
        }
        out.push(ch);
        line_bytes += len;
    }
    out.push_str("\r\n");
}

fn clean_rrule(rule: &str) -> Option<&str> {
    if rule.is_empty() {
        return None;
    }
    let mut saw_freq = false;
    for (idx, part) in rule.split(';').enumerate() {
        let (name, value) = part.split_once('=')?;
        if name.is_empty()
            || value.is_empty()
            || !name.chars().all(|c| c.is_ascii_alphabetic())
            || !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, ',' | '.' | '+' | '-'))
        {
            return None;
        }
        if idx == 0 && name.eq_ignore_ascii_case("FREQ") {
            saw_freq = true;
        }
    }
    saw_freq.then_some(rule)
}

fn cal_address_value(email: &str) -> Option<&str> {
    let (local, domain) = email.split_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    let valid_char =
        |c: char| c.is_ascii_alphanumeric() || c == '@' || "!#$%&'*+-/=?^_`{|}~.".contains(c);
    if !email.chars().all(valid_char)
        || domain.starts_with('-')
        || domain.ends_with('-')
        || domain.contains("..")
    {
        return None;
    }
    Some(email)
}

fn build_attendee_line(prop: &str, att: &PayloadAttendee) -> Option<String> {
    let addr = cal_address_value(&att.email)?;
    let mut params = Vec::new();
    if !att.name.is_empty() && !att.name.contains('"') {
        let mut p = String::from("CN=");
        p.push_str(&param_value(&att.name));
        params.push(p);
    }
    if prop == "ORGANIZER" && !att.delegated_from.is_empty() {
        if let Some(sent_by) = cal_address_value(&att.delegated_from) {
            let mut p = String::from("SENT-BY=");
            let mut mailto = String::from("mailto:");
            mailto.push_str(sent_by);
            p.push_str(&param_value_quoted(&mailto));
            params.push(p);
        }
    }
    let role_param = match att.role.as_str() {
        "required" | "req-participant" => Some("REQ-PARTICIPANT"),
        "optional" | "opt-participant" => Some("OPT-PARTICIPANT"),
        "resource" | "non-participant" => Some("NON-PARTICIPANT"),
        "chair" => Some("CHAIR"),
        _ => None,
    };
    if let Some(r) = role_param {
        let mut p = String::from("ROLE=");
        p.push_str(r);
        params.push(p);
    }
    if !att.participation_status.is_empty() {
        let ps = match att.participation_status.as_str() {
            "accepted" => "ACCEPTED",
            "declined" => "DECLINED",
            "tentative" => "TENTATIVE",
            _ => "NEEDS-ACTION",
        };
        let mut p = String::from("PARTSTAT=");
        p.push_str(ps);
        params.push(p);
    }
    if att.expect_reply {
        params.push("RSVP=TRUE".to_owned());
    }
    let mut out = String::from(prop);
    if !params.is_empty() {
        out.push(';');
        out.push_str(&params.join(";"));
    }
    out.push_str(":mailto:");
    out.push_str(addr);
    Some(out)
}

fn push_rfc1123z(out: &mut String, t: DateTime<Utc>) {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let day = DAYS[t.weekday().num_days_from_sunday() as usize];
    let month = MONTHS[t.month0() as usize];
    let _ = write!(
        out,
        "{day}, {:02} {month} {:04} {:02}:{:02}:{:02} +0000",
        t.day(),
        t.year(),
        t.hour(),
        t.minute(),
        t.second()
    );
}

fn push_ical_date(out: &mut String, t: DateTime<FixedOffset>) {
    let _ = write!(out, "{:04}{:02}{:02}", t.year(), t.month(), t.day());
}

fn push_ical_local(out: &mut String, t: DateTime<FixedOffset>) {
    let _ = write!(
        out,
        "{:04}{:02}{:02}T{:02}{:02}{:02}",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
}

fn push_ical_utc(out: &mut String, t: DateTime<Utc>) {
    let _ = write!(
        out,
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
}

fn push_human_time(out: &mut String, t: DateTime<FixedOffset>, all_day: bool, tz: &str) {
    const DAYS: [&str; 7] = [
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
    ];
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let day = DAYS[t.weekday().num_days_from_sunday() as usize];
    let month = MONTHS[t.month0() as usize];
    let _ = write!(out, "{day}, {month} {}, {}", t.day(), t.year());
    if all_day {
        return;
    }
    let (pm, h12) = t.hour12();
    let ampm = if pm { "PM" } else { "AM" };
    let _ = write!(out, " at {h12}:{:02} {ampm}", t.minute());
    if !tz.is_empty() && tz != "UTC" {
        let _ = write!(out, " ({tz})");
    } else {
        out.push_str(" UTC");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thirteen_methods_match_registry_contract() {
        assert_eq!(METHODS.len(), 13);
        let mut mutators = Vec::new();
        let mut state_methods = Vec::new();
        for m in METHODS {
            assert_eq!(m.capability, CAPABILITY);
            assert_eq!(m.app, "calendar");
            assert_eq!(m.gate, Gate::Personal);
            assert!(m.account);
            if m.mutator {
                mutators.push(m.name);
            }
            if m.state {
                state_methods.push(m.name);
            }
        }
        assert_eq!(
            mutators,
            [
                "CalendarEvent/set",
                "CalendarEvent/import",
                "CalendarEvent/rsvp",
                "CalendarEvent/setOccurrence",
                "CalendarEvent/sendUpdate",
            ]
        );
        assert_eq!(state_methods, ["CalendarEvent/changes"]);
    }

    #[test]
    fn merge_set_results_overwrites_keys_and_handles_empty() {
        let merged = merge_set_results(
            Some(r#"{"accountId":"1","oldState":"4","newState":"5","created":{"c1":"10"}}"#),
            Some(r#"{"accountId":"1","oldState":"5","newState":"6","updated":{"10":null}}"#),
            None,
        );
        let parsed: Value = serde_json::from_str(&merged).unwrap();
        assert_eq!(parsed["oldState"], "5");
        assert_eq!(parsed["newState"], "6");
        assert_eq!(parsed["created"]["c1"], "10");
        assert!(parsed["updated"]["10"].is_null());
        assert_eq!(merge_set_results(None, None, None), "{}");
    }

    #[test]
    fn add_not_destroyed_populates_not_found() {
        let out = add_not_destroyed(
            r#"{"accountId":"1","destroyed":["5"]}"#,
            &["bad-id".to_owned()],
        );
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["notDestroyed"]["bad-id"]["type"], "notFound");
        assert_eq!(parsed["destroyed"][0], "5");
    }

    #[test]
    fn merge_resource_bookings_remaps_event_ids_to_client_keys() {
        let mut map = BTreeMap::new();
        map.insert("16000001".to_owned(), "k1".to_owned());
        let remapped =
            merge_resource_bookings(r#"{"16000001":{"status":"confirmed"}}"#, &map).unwrap();
        assert_eq!(remapped["k1"]["status"], "confirmed");
    }

    #[test]
    fn build_invite_mime_formats_request_and_cancel_with_recurrence_id() {
        let payload = r#"{
            "method":"CANCEL",
            "uid":"evt-1@setjoin.test",
            "title":"Weekly Sync\r\nBcc: evil@example.com",
            "description":"Notes; line1, line2",
            "location":"Room A",
            "start":"2026-11-22T10:00:00Z",
            "end":"2026-11-22T11:00:00Z",
            "recurrenceId":"2026-11-22T10:00:00-05:00",
            "rrule":"FREQ=WEEKLY;COUNT=3",
            "sequence":2,
            "status":"cancelled",
            "organizerEmail":"org@setjoin.test",
            "organizerName":"Org User",
            "attendees":[{"email":"guest@setjoin.test","name":"Guest, Team","role":"required","participationStatus":"accepted","expectReply":true}]
        }"#;
        let built = build_invite_mime(payload).unwrap().unwrap();
        assert_eq!(built.from, "org@setjoin.test");
        assert_eq!(built.recipients, vec!["guest@setjoin.test"]);
        assert!(built.mime.contains("METHOD:CANCEL\r\n"));
        assert!(built
            .mime
            .contains("Subject: Cancellation: Weekly SyncBcc: evil@example.com\r\n"));
        assert!(built.mime.contains("RECURRENCE-ID:20261122T150000Z\r\n"));
        assert!(built.mime.contains("RRULE:FREQ=WEEKLY;COUNT=3\r\n"));
        assert!(built
            .mime
            .contains("DESCRIPTION:Notes\\; line1\\, line2\r\n"));
        assert!(built.mime.contains("ATTENDEE;CN=\"Guest, Team\";ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED;RSVP=TRUE:mailto:guest@setjoin.test\r\n"));
    }

    #[test]
    fn build_counter_mime_targets_organizer_and_omits_role_for_attendee() {
        let payload = r#"{
            "uid":"evt-2@setjoin.test",
            "title":"Design Review",
            "start":"2026-11-23T14:00:00Z",
            "end":"2026-11-23T15:00:00Z",
            "sequence":1,
            "organizerEmail":"org@setjoin.test",
            "organizerName":"Org",
            "attendeeEmail":"att@setjoin.test",
            "attendeeName":"Att"
        }"#;
        let built = build_counter_mime(payload).unwrap();
        assert_eq!(built.from, "att@setjoin.test");
        assert_eq!(built.recipients, vec!["org@setjoin.test"]);
        assert!(built.mime.contains("METHOD:COUNTER\r\n"));
        assert!(built
            .mime
            .contains("Subject: Counter Proposal: Design Review\r\n"));
        assert!(built.mime.contains("DTSTART:20261123T140000Z\r\n"));
        assert!(built
            .mime
            .contains("ATTENDEE;CN=Att:mailto:att@setjoin.test\r\n"));
    }

    #[test]
    fn rrule_and_param_value_reject_crafted_inputs() {
        assert_eq!(
            clean_rrule("FREQ=DAILY;COUNT=2"),
            Some("FREQ=DAILY;COUNT=2")
        );
        assert_eq!(clean_rrule("COUNT=2;FREQ=DAILY"), None);
        assert_eq!(clean_rrule("FREQ=DAILY;BAD=a;b"), None);
        assert_eq!(param_value("a\\b;c"), "\"a\\\\b;c\"");
    }
}
