//! #370 ContactCard/* (frozen Go contacts.go:86-330).
use super::args::{self, Kind};
use super::seam::{
    not_found, parse_id_list, read, read_sql, resolve, set_batch, set_sql, since_state, write,
    write_sql, Cx, Type,
};
use super::{always, parse_arg, Answer, Gate, Method, MethodError, Reply};

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
    method("ContactCard/get", false, false, contact_card_get),
    method("ContactCard/query", false, false, contact_card_query),
    method("ContactCard/changes", false, true, contact_card_changes),
    method("ContactCard/set", true, false, contact_card_set),
    method(
        "ContactCard/findDuplicates",
        false,
        false,
        contact_card_find_duplicates,
    ),
    method("ContactCard/merge", true, false, contact_card_merge),
    method(
        "ContactCard/galSearch",
        false,
        false,
        contact_card_gal_search,
    ),
    method(
        "ContactCard/directoryTree",
        false,
        false,
        contact_card_directory_tree,
    ),
    method(
        "ContactCard/directoryMembers",
        false,
        false,
        contact_card_directory_members,
    ),
    method(
        "ContactCard/directorySearch",
        false,
        false,
        contact_card_directory_search,
    ),
];

fn clamp_limit(raw: i64) -> i32 {
    if (1..=256).contains(&raw) {
        raw as i32
    } else {
        50
    }
}

fn contact_card_get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
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
            read_sql!("SELECT jmap_contact_get($1,$3::bigint[])::text"),
            &[(&ids, Type::INT8_ARRAY)],
        )
        .await?;
        Ok(Answer {
            name: "ContactCard/get",
            args: not_found(&raw, &bad),
        })
    })
}

fn contact_card_query<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(
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
        let scope = resolve(cx, args.str("accountId")).await?;
        let filter = args.raw("filter");
        let sort = args.raw("sort");
        let position =
            i32::try_from(args.int("position")).map_err(|_| MethodError::server_fail())?;
        let limit = clamp_limit(args.int("limit"));
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT jmap_contact_query($1,$3::text::jsonb,$4::text::jsonb,$5,$6)::text"),
            &[
                (&filter, Type::TEXT),
                (&sort, Type::TEXT),
                (&position, Type::INT4),
                (&limit, Type::INT4),
            ],
        )
        .await?;
        Ok(Answer {
            name: "ContactCard/query",
            args: raw,
        })
    })
}

fn contact_card_changes<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
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
            read_sql!("SELECT jmap_contact_changes($1,$3)::text"),
            &[(&since, Type::TEXT)],
        )
        .await?;
        Ok(Answer {
            name: "ContactCard/changes",
            args: raw,
        })
    })
}

fn contact_card_set<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
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
        // Mirrors frozen Go bug G1 (contacts.go:170): calls jmap_contactcard_set_*
        // (known missing -> SQLSTATE 42883 -> serverFail when any phase is present).
        let raw = set_batch(
            cx,
            &scope,
            set_sql!("jmap_contactcard"),
            "contact_card.set",
            args.raw("create"),
            args.raw("update"),
            args.strings("destroy"),
        )
        .await?;
        Ok(Answer {
            name: "ContactCard/set",
            args: raw,
        })
    })
}

fn contact_card_find_duplicates<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(cx.args(), "", &[("accountId", Kind::Str)])?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT contact_find_duplicates($1)::text"),
            &[],
        )
        .await?;
        Ok(Answer {
            name: "ContactCard/findDuplicates",
            args: raw,
        })
    })
}

fn contact_card_merge<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("keepId", Kind::Str),
                ("dropId", Kind::Str),
            ],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let keep_id = parse_arg(args.str("keepId"), "keepId")?;
        let drop_id = parse_arg(args.str("dropId"), "dropId")?;
        let raw = write(
            cx,
            &scope,
            "contact_card.merge",
            write_sql!("SELECT contact_merge($1,$4,$5)::text"),
            &[(&keep_id, Type::INT8), (&drop_id, Type::INT8)],
        )
        .await?;
        Ok(Answer {
            name: "ContactCard/merge",
            args: raw,
        })
    })
}

fn contact_card_gal_search<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("text", Kind::Str),
                ("limit", Kind::Int),
            ],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let text = args.str("text");
        let limit = clamp_limit(args.int("limit"));
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT gal_search($1,$3,$4)::text"),
            &[(&text, Type::TEXT), (&limit, Type::INT4)],
        )
        .await?;
        Ok(Answer {
            name: "ContactCard/galSearch",
            args: raw,
        })
    })
}

fn contact_card_directory_tree<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(cx.args(), "", &[("accountId", Kind::Str)])?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT directory_tree($1)::text"),
            &[],
        )
        .await?;
        Ok(Answer {
            name: "ContactCard/directoryTree",
            args: raw,
        })
    })
}

fn contact_card_directory_members<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("departmentId", Kind::Int64),
                ("offset", Kind::Int),
                ("limit", Kind::Int),
            ],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let department_id = args.int("departmentId");
        let offset = i32::try_from(args.int("offset")).map_err(|_| MethodError::server_fail())?;
        let limit = clamp_limit(args.int("limit"));
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT directory_members($1,$3,$4,$5)::text"),
            &[
                (&department_id, Type::INT8),
                (&offset, Type::INT4),
                (&limit, Type::INT4),
            ],
        )
        .await?;
        Ok(Answer {
            name: "ContactCard/directoryMembers",
            args: raw,
        })
    })
}

fn contact_card_directory_search<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("query", Kind::Str),
                ("limit", Kind::Int),
            ],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let query_text = args.str("query");
        let limit = clamp_limit(args.int("limit"));
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT directory_search($1,$3,$4)::text"),
            &[(&query_text, Type::TEXT), (&limit, Type::INT4)],
        )
        .await?;
        Ok(Answer {
            name: "ContactCard/directorySearch",
            args: raw,
        })
    })
}
