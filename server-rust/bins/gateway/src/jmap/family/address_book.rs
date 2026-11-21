//! #375 AddressBook/* and ContactGroup/* (frozen Go contacts.go:18-85, contact_group.go).
use std::collections::BTreeMap;

use serde_json::value::RawValue;

use super::args::{self, Kind};
use super::seam::{
    not_found, parse_id_list, read, read_sql, resolve, set_batch, set_sql, since_state, write,
    write_sql, Cx, Type,
};
use super::{always, go_compact, parse_arg, Answer, Gate, Method, MethodError, Reply};

const CAPABILITY: &str = "urn:ietf:params:jmap:contacts";
const APP: &str = "contacts";

const fn method(
    name: &'static str,
    mutator: bool,
    state: bool,
    run: for<'a> fn(&'a Cx<'a>) -> Reply<'a>,
) -> Method {
    Method {
        name,
        capability: CAPABILITY,
        app: APP,
        gate: Gate::Personal,
        account: true,
        mutator,
        state,
        ready: always,
        run,
    }
}

pub(super) const METHODS: &[Method] = &[
    method("AddressBook/get", false, false, address_book_get),
    method("AddressBook/changes", false, true, address_book_changes),
    method("AddressBook/set", true, false, address_book_set),
    method("ContactGroup/get", false, false, contact_group_get),
    method("ContactGroup/query", false, false, contact_group_query),
    method("ContactGroup/set", true, false, contact_group_set),
    method("ContactGroup/expand", false, false, contact_group_expand),
];

fn address_book_get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("ids", Kind::Strings),
                ("properties", Kind::Strings),
            ],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let (ids, bad) = parse_id_list(args.strings("ids").unwrap_or_default());
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT jmap_addressbook_get($1,$3::bigint[])::text"),
            &[(&ids, Type::INT8_ARRAY)],
        )
        .await?;
        Ok(Answer {
            name: "AddressBook/get",
            args: not_found(&raw, &bad),
        })
    })
}

fn address_book_changes<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(
            cx.args(),
            "",
            &[("accountId", Kind::Str), ("sinceState", Kind::Str)],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let since = args.str("sinceState");
        since_state(since)?;
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT jmap_addressbook_changes($1,$3)::text"),
            &[(&since, Type::TEXT)],
        )
        .await?;
        Ok(Answer {
            name: "AddressBook/changes",
            args: raw,
        })
    })
}

fn address_book_set<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(
            cx.args(),
            "SetRequest",
            &[
                ("accountId", Kind::Str),
                ("create", Kind::Raw),
                ("update", Kind::Raw),
                ("destroy", Kind::Strings),
            ],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let raw = set_batch(
            cx,
            &scope,
            set_sql!("jmap_addressbook"),
            "addressbook.set",
            args.raw("create"),
            args.raw("update"),
            args.strings("destroy"),
        )
        .await?;
        Ok(Answer {
            name: "AddressBook/set",
            args: raw,
        })
    })
}

fn contact_group_get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(
            cx.args(),
            "",
            &[("accountId", Kind::Str), ("ids", Kind::Strings)],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let (ids, bad) = parse_id_list(args.strings("ids").unwrap_or_default());
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT jmap_contact_group_get($1,$3::bigint[])::text"),
            &[(&ids, Type::INT8_ARRAY)],
        )
        .await?;
        Ok(Answer {
            name: "ContactGroup/get",
            args: not_found(&raw, &bad),
        })
    })
}

fn contact_group_query<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(
            cx.args(),
            "",
            &[("accountId", Kind::Str), ("filter", Kind::Raw)],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let filter = args.raw("filter");
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT jmap_contact_group_query($1,$3::text::jsonb)::text"),
            &[(&filter, Type::TEXT)],
        )
        .await?;
        Ok(Answer {
            name: "ContactGroup/query",
            args: raw,
        })
    })
}

struct MembersPatch {
    group_id: String,
    add: String,
    remove: String,
}

fn raw_list_to_json(raw: Option<&str>) -> Option<String> {
    let Some(raw) = raw.filter(|text| *text != "null") else {
        return Some("[]".to_owned());
    };
    let items: Vec<Box<RawValue>> = serde_json::from_str(raw).ok()?;
    if items.is_empty() {
        return Some("[]".to_owned());
    }
    serde_json::to_string(&items).ok()
}

fn parse_members_patch(raw: &str) -> Option<MembersPatch> {
    let args = args::decode(
        raw,
        "",
        &[
            ("groupId", Kind::Str),
            ("add", Kind::Raw),
            ("remove", Kind::Raw),
        ],
    )
    .ok()?;
    let group_id = args.str("groupId");
    if group_id.is_empty() {
        return None;
    }
    let add = raw_list_to_json(args.raw("add"))?;
    let remove = raw_list_to_json(args.raw("remove"))?;
    Some(MembersPatch {
        group_id: group_id.to_owned(),
        add,
        remove,
    })
}

fn merge_members_result(set_result: &str, members_result: String) -> Result<String, MethodError> {
    let mut merged: BTreeMap<String, Box<RawValue>> =
        serde_json::from_str(set_result).unwrap_or_default();
    merged.insert(
        "members".to_owned(),
        RawValue::from_string(members_result).map_err(|_| MethodError::server_fail())?,
    );
    let encoded = serde_json::to_string(&merged).map_err(|_| MethodError::server_fail())?;
    go_compact(&encoded).ok_or_else(MethodError::server_fail)
}

fn contact_group_set<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("create", Kind::Raw),
                ("update", Kind::Raw),
                ("destroy", Kind::Strings),
                ("members", Kind::Raw),
            ],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let mut raw = set_batch(
            cx,
            &scope,
            set_sql!("jmap_contact_group"),
            "contact_group.set",
            args.raw("create"),
            args.raw("update"),
            args.strings("destroy"),
        )
        .await?;
        if let Some(members_raw) = args.raw("members").filter(|text| *text != "null") {
            if let Some(patch) = parse_members_patch(members_raw) {
                let group_id = parse_arg(&patch.group_id, "members.groupId")?;
                let members_result = write(
                    cx,
                    &scope,
                    "contact_group.members",
                    write_sql!(
                        "SELECT contact_group_members_set($1,$4,$5::text::jsonb,$6::text::jsonb)::text"
                    ),
                    &[
                        (&group_id, Type::INT8),
                        (&patch.add, Type::TEXT),
                        (&patch.remove, Type::TEXT),
                    ],
                )
                .await?;
                raw = merge_members_result(&raw, members_result)?;
            }
        }
        Ok(Answer {
            name: "ContactGroup/set",
            args: raw,
        })
    })
}

fn contact_group_expand<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(
            cx.args(),
            "",
            &[("accountId", Kind::Str), ("groupId", Kind::Str)],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let group_id = parse_arg(args.str("groupId"), "groupId")?;
        let list = read(
            cx,
            &scope,
            read_sql!("SELECT expand_contact_group($1,$3)::text"),
            &[(&group_id, Type::INT8)],
        )
        .await?;
        let mut out: BTreeMap<&str, Box<RawValue>> = BTreeMap::new();
        out.insert(
            "accountId",
            RawValue::from_string(crate::problem::go_string(args.str("accountId")))
                .map_err(|_| MethodError::server_fail())?,
        );
        out.insert(
            "list",
            RawValue::from_string(list).map_err(|_| MethodError::server_fail())?,
        );
        let encoded = serde_json::to_string(&out).map_err(|_| MethodError::server_fail())?;
        let raw = go_compact(&encoded).ok_or_else(MethodError::server_fail)?;
        Ok(Answer {
            name: "ContactGroup/expand",
            args: raw,
        })
    })
}
