//! #371 Calendar/* except delegateList (frozen Go calendar.go:27-102, calendar_a3.go:39-178).

use super::args::{self, Kind};
use super::seam::{self, read_sql, write_sql, ScopedQuery, Sql, Type};
use super::{always, Answer, Cx, Gate, Method, MethodError, Reply};

const CAPABILITY: &str = "urn:ietf:params:jmap:calendars";
const APP: &str = "calendar";

const GET_SQL: Sql = read_sql!("SELECT jmap_calendar_get($1,$3::bigint[])::text");
const CHANGES_SQL: Sql = read_sql!("SELECT jmap_calendar_changes($1,$3)::text");
const SET_UPDATE_SQL: Sql = write_sql!("SELECT jmap_calendar_set_update($1,$4::text::jsonb)::text");
const SHARE_GET_SQL: Sql = read_sql!("SELECT jmap_calendar_share_get($1,$3)::text");
const SHARE_SET_SQL: Sql =
    write_sql!("SELECT jmap_calendar_share_set($1,$4,$5::text::jsonb,$6::text::jsonb)::text");

pub(super) const METHODS: &[Method] = &[
    Method {
        name: "Calendar/get",
        capability: CAPABILITY,
        app: APP,
        gate: Gate::Personal,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: get,
    },
    Method {
        name: "Calendar/changes",
        capability: CAPABILITY,
        app: APP,
        gate: Gate::Personal,
        account: true,
        mutator: false,
        state: true,
        ready: always,
        run: changes,
    },
    Method {
        name: "Calendar/set",
        capability: CAPABILITY,
        app: APP,
        gate: Gate::Personal,
        account: true,
        mutator: true,
        state: false,
        ready: always,
        run: set,
    },
    Method {
        name: "Calendar/getShared",
        capability: CAPABILITY,
        app: APP,
        gate: Gate::Personal,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: get_shared,
    },
    Method {
        name: "Calendar/shareGet",
        capability: CAPABILITY,
        app: APP,
        gate: Gate::Personal,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: share_get,
    },
    Method {
        name: "Calendar/shareSet",
        capability: CAPABILITY,
        app: APP,
        gate: Gate::Personal,
        account: true,
        mutator: true,
        state: false,
        ready: always,
        run: share_set,
    },
];

fn get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async {
        const FIELDS: &[(&str, Kind)] = &[
            ("accountId", Kind::Str),
            ("ids", Kind::Strings),
            ("properties", Kind::Strings),
        ];
        let args = args::decode(cx.args(), "", FIELDS)?;
        let scope = seam::resolve(cx, args.str("accountId")).await?;
        let (ids, bad) = seam::parse_id_list(args.strings("ids").unwrap_or(&[]));
        let raw = seam::read(cx, &scope, GET_SQL, &[(&ids, Type::INT8_ARRAY)]).await?;
        Ok(Answer {
            name: "Calendar/get",
            args: seam::not_found(&raw, &bad),
        })
    })
}

fn changes<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async {
        const FIELDS: &[(&str, Kind)] = &[("accountId", Kind::Str), ("sinceState", Kind::Str)];
        let args = args::decode(cx.args(), "", FIELDS)?;
        let scope = seam::resolve(cx, args.str("accountId")).await?;
        let since = args.str("sinceState");
        seam::since_state(since)?;
        let raw = seam::read(cx, &scope, CHANGES_SQL, &[(&since, Type::TEXT)]).await?;
        Ok(Answer {
            name: "Calendar/changes",
            args: raw,
        })
    })
}

fn set<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async {
        const FIELDS: &[(&str, Kind)] = &[("accountId", Kind::Str), ("update", Kind::Raw)];
        let args = args::decode(cx.args(), "", FIELDS)?;
        let scope = seam::resolve(cx, args.str("accountId")).await?;
        let Some(update) = args.raw("update").filter(|raw| {
            *raw != "null"
                && raw
                    .trim_start_matches([' ', '\t', '\n', '\r'])
                    .starts_with('{')
        }) else {
            return Ok(Answer {
                name: "Calendar/set",
                args: "null".to_owned(),
            });
        };
        let raw = seam::write(
            cx,
            &scope,
            "jmap_calendar_set_update",
            SET_UPDATE_SQL,
            &[(&update, Type::TEXT)],
        )
        .await?;
        Ok(Answer {
            name: "Calendar/set",
            args: raw,
        })
    })
}

fn get_shared<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async {
        const FIELDS: &[(&str, Kind)] = &[("accountId", Kind::Str), ("ownerEmail", Kind::Str)];
        let args = args::decode(cx.args(), "", FIELDS)?;
        let scope = seam::resolve(cx, args.str("accountId")).await?;
        let owner_email = args.str("ownerEmail");
        if owner_email.is_empty() {
            return Err(MethodError::new(
                "invalidArguments",
                "ownerEmail is required",
            ));
        }
        let raw = seam::query(cx, &scope, ScopedQuery::CalendarGetShared { owner_email }).await?;
        Ok(Answer {
            name: "Calendar/getShared",
            args: raw,
        })
    })
}

fn share_get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async {
        const FIELDS: &[(&str, Kind)] = &[("accountId", Kind::Str), ("calendarId", Kind::Str)];
        let args = args::decode(cx.args(), "", FIELDS)?;
        let scope = seam::resolve(cx, args.str("accountId")).await?;
        let Some(calendar_id) = super::parse_id(args.str("calendarId")) else {
            return Err(MethodError::new("invalidArguments", "invalid calendarId"));
        };
        let raw = seam::read(cx, &scope, SHARE_GET_SQL, &[(&calendar_id, Type::INT8)]).await?;
        Ok(Answer {
            name: "Calendar/shareGet",
            args: raw,
        })
    })
}

fn share_set<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async {
        const FIELDS: &[(&str, Kind)] = &[
            ("accountId", Kind::Str),
            ("calendarId", Kind::Str),
            ("grants", Kind::Raw),
            ("revokes", Kind::Raw),
        ];
        let args = args::decode(cx.args(), "", FIELDS)?;
        let scope = seam::resolve(cx, args.str("accountId")).await?;
        let Some(calendar_id) = super::parse_id(args.str("calendarId")) else {
            return Err(MethodError::new("invalidArguments", "invalid calendarId"));
        };
        let grants = args.raw("grants").unwrap_or("[]");
        let revokes = args.raw("revokes").unwrap_or("[]");
        let raw = seam::write(
            cx,
            &scope,
            "jmap_calendar_share_set",
            SHARE_SET_SQL,
            &[
                (&calendar_id, Type::INT8),
                (&grants, Type::TEXT),
                (&revokes, Type::TEXT),
            ],
        )
        .await?;
        Ok(Answer {
            name: "Calendar/shareSet",
            args: raw,
        })
    })
}
