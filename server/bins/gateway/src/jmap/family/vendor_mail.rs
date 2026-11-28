//! #376 SavedSearch/*, QuickStep/* and EmailTemplate/* (frozen Go savedsearches.go, quicksteps.go, email_templates.go).
use std::collections::BTreeMap;

use serde_json::json;
use serde_json::value::RawValue;

use super::args::{self, Kind};
use super::seam::{query, read, read_sql, resolve, write, write_sql, ScopedQuery, Type};
use super::{always, go_map, parse_id, Answer, Cx, Gate, Handled, Method, MethodError, Reply};

const VENDOR_MAIL: &str = "urn:setjoin:params:jmap:mail";

const fn vendor_method(
    name: &'static str,
    mutator: bool,
    run: for<'a> fn(&'a Cx<'a>) -> Reply<'a>,
) -> Method {
    Method {
        name,
        capability: VENDOR_MAIL,
        app: "",
        gate: Gate::Personal,
        account: true,
        mutator,
        state: false,
        ready: always,
        run,
    }
}

pub(super) const METHODS: &[Method] = &[
    vendor_method("SavedSearch/list", false, saved_search_list),
    vendor_method("SavedSearch/set", true, saved_search_set),
    vendor_method("SavedSearch/delete", true, saved_search_delete),
    vendor_method("QuickStep/get", false, quick_step_get),
    vendor_method("QuickStep/set", true, quick_step_set),
    vendor_method("QuickStep/apply", true, quick_step_apply),
    vendor_method("EmailTemplate/list", false, email_template_list),
    vendor_method("EmailTemplate/set", true, email_template_set),
    vendor_method("EmailTemplate/delete", true, email_template_delete),
];

fn parse_arg(raw: &str, property: &str) -> Result<i64, MethodError> {
    parse_id(raw).ok_or_else(|| {
        let detail = match property {
            "id" => "invalid id",
            "messageId" => "invalid messageId",
            _ => "invalid argument",
        };
        MethodError::new("invalidArguments", detail)
    })
}

/// Marshal `{"accountId": "<id>", "<key>": <raw>}` with sorted outer keys,
/// preserving `raw` (a reducer's `json.RawMessage`) verbatim, compacted and
/// HTML-escaped as Go's `json.Marshal` + `json.Encoder`.
fn raw_map(account_id: i64, key: &str, raw: &str) -> Result<String, MethodError> {
    let mut map: BTreeMap<&str, Box<RawValue>> = BTreeMap::new();
    let account_json =
        serde_json::to_string(&account_id.to_string()).map_err(|_| MethodError::server_fail())?;
    let account_raw =
        RawValue::from_string(account_json).map_err(|_| MethodError::server_fail())?;
    let value_raw =
        RawValue::from_string(raw.to_owned()).map_err(|_| MethodError::server_fail())?;
    map.insert("accountId", account_raw);
    map.insert(key, value_raw);
    let json = serde_json::to_string(&map).map_err(|_| MethodError::server_fail())?;
    super::go_compact(&json).ok_or_else(MethodError::server_fail)
}

fn answer(name: &'static str, args: String) -> Handled {
    Ok(Answer { name, args })
}

fn saved_search_list<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(cx.args(), "", &[("accountId", Kind::Str)])?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let list = read(
            cx,
            &scope,
            read_sql!("SELECT saved_search_list($1)::text"),
            &[],
        )
        .await?;
        answer("SavedSearch/list", raw_map(scope.id(), "list", &list)?)
    })
}

fn saved_search_set<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("name", Kind::Str),
                ("query", Kind::Str),
            ],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let (name, query) = (args.str("name"), args.str("query"));
        let created = write(
            cx,
            &scope,
            "saved_search.set",
            write_sql!("SELECT saved_search_set($1,$4,$5)::text"),
            &[(&name, Type::TEXT), (&query, Type::TEXT)],
        )
        .await?;
        answer("SavedSearch/set", raw_map(scope.id(), "created", &created)?)
    })
}

fn saved_search_delete<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(
            cx.args(),
            "",
            &[("accountId", Kind::Str), ("id", Kind::Str)],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let id = parse_arg(args.str("id"), "id")?;
        let result = write(
            cx,
            &scope,
            "saved_search.delete",
            write_sql!("SELECT saved_search_delete($1,$4)::text"),
            &[(&id, Type::INT8)],
        )
        .await?;
        answer(
            "SavedSearch/delete",
            raw_map(scope.id(), "result", &result)?,
        )
    })
}

fn quick_step_get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(cx.args(), "", &[("accountId", Kind::Str)])?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let list = read(
            cx,
            &scope,
            read_sql!("SELECT quick_step_list($1)::text"),
            &[],
        )
        .await?;
        answer("QuickStep/get", raw_map(scope.id(), "list", &list)?)
    })
}

fn quick_step_set<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("id", Kind::Str),
                ("name", Kind::Str),
                ("icon", Kind::Str),
                ("actions", Kind::Raw),
                ("destroy", Kind::Bool),
            ],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let raw_id = args.str("id");
        if args.bool("destroy") {
            let id = parse_arg(raw_id, "id")?;
            let _ = write(
                cx,
                &scope,
                "quick_step.delete",
                write_sql!("SELECT quick_step_delete($1,$4)::text"),
                &[(&id, Type::INT8)],
            )
            .await?;
            return answer(
                "QuickStep/set",
                go_map(vec![
                    ("accountId", json!(scope.id().to_string())),
                    ("destroyed", json!(raw_id)),
                ]),
            );
        }
        let id = if raw_id.is_empty() {
            None
        } else {
            Some(parse_arg(raw_id, "id")?)
        };
        let (name, icon) = (args.str("name"), args.str("icon"));
        let actions = args.raw("actions").unwrap_or("[]");
        let new_id = write(
            cx,
            &scope,
            "quick_step.set",
            write_sql!("SELECT quick_step_set($1,$4,$5,$6,$7::text::jsonb)::text"),
            &[
                (&id, Type::INT8),
                (&name, Type::TEXT),
                (&icon, Type::TEXT),
                (&actions, Type::TEXT),
            ],
        )
        .await?;
        answer(
            "QuickStep/set",
            go_map(vec![
                ("accountId", json!(scope.id().to_string())),
                ("id", json!(new_id)),
            ]),
        )
    })
}

fn quick_step_apply<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("id", Kind::Str),
                ("messageId", Kind::Str),
            ],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let raw_id = args.str("id");
        let id = parse_arg(raw_id, "id")?;
        let message = parse_arg(args.str("messageId"), "messageId")?;
        let result = query(cx, &scope, ScopedQuery::QuickStepApply { id, message }).await?;
        if result == "null" {
            return Err(MethodError::new("notFound", "message not found"));
        }
        answer(
            "QuickStep/apply",
            go_map(vec![
                ("accountId", json!(scope.id().to_string())),
                ("applied", json!(raw_id)),
            ]),
        )
    })
}

fn email_template_list<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(cx.args(), "", &[("accountId", Kind::Str)])?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let list = read(
            cx,
            &scope,
            read_sql!("SELECT email_template_list($1)::text"),
            &[],
        )
        .await?;
        answer("EmailTemplate/list", raw_map(scope.id(), "list", &list)?)
    })
}

fn email_template_set<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("name", Kind::Str),
                ("subject", Kind::Str),
                ("bodyHtml", Kind::Str),
            ],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let (name, subject, body_html) =
            (args.str("name"), args.str("subject"), args.str("bodyHtml"));
        let created = write(
            cx,
            &scope,
            "email_template.set",
            write_sql!("SELECT email_template_set($1,$4,$5,$6)::text"),
            &[
                (&name, Type::TEXT),
                (&subject, Type::TEXT),
                (&body_html, Type::TEXT),
            ],
        )
        .await?;
        answer(
            "EmailTemplate/set",
            raw_map(scope.id(), "created", &created)?,
        )
    })
}

fn email_template_delete<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        let args = args::decode(
            cx.args(),
            "",
            &[("accountId", Kind::Str), ("id", Kind::Str)],
        )?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let id = parse_arg(args.str("id"), "id")?;
        let result = write(
            cx,
            &scope,
            "email_template.delete",
            write_sql!("SELECT email_template_delete($1,$4)::text"),
            &[(&id, Type::INT8)],
        )
        .await?;
        answer(
            "EmailTemplate/delete",
            raw_map(scope.id(), "result", &result)?,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_arg_matches_go_parse_id_and_detail() {
        assert_eq!(parse_arg("42", "id"), Ok(42));
        assert_eq!(parse_arg("+7", "id"), Ok(7));
        assert_eq!(parse_arg("05", "messageId"), Ok(5));
        for bad in ["", "0", "-1", "abc", "99999999999999999999"] {
            assert_eq!(
                parse_arg(bad, "id"),
                Err(MethodError::new("invalidArguments", "invalid id")),
                "{bad}"
            );
            assert_eq!(
                parse_arg(bad, "messageId"),
                Err(MethodError::new("invalidArguments", "invalid messageId")),
                "{bad}"
            );
        }
    }

    #[test]
    fn raw_map_preserves_inner_order_and_escapes_html() {
        let out = raw_map(
            12,
            "created",
            r#"{"id": "27000001", "name": "T", "subject": "S", "bodyHtml": "<p>a & b</p>"}"#,
        )
        .expect("raw_map");
        assert_eq!(
            out,
            r#"{"accountId":"12","created":{"id":"27000001","name":"T","subject":"S","bodyHtml":"\u003cp\u003ea \u0026 b\u003c/p\u003e"}}"#
        );
        assert_eq!(raw_map(12, "list", "{bad"), Err(MethodError::server_fail()));
    }

    #[test]
    fn methods_metadata_and_classify_gate_on_vendor_capability() {
        assert_eq!(METHODS.len(), 9);
        for method in METHODS {
            assert_eq!(method.capability, VENDOR_MAIL);
            assert_eq!(method.app, "");
            assert_eq!(method.gate, Gate::Personal);
            assert!(method.account);
            assert!(!method.state);
            let expected_mutator = !matches!(
                method.name,
                "SavedSearch/list" | "QuickStep/get" | "EmailTemplate/list"
            );
            assert_eq!(method.mutator, expected_mutator, "{}", method.name);
        }
        let ok = br#"{"using":["urn:setjoin:params:jmap:mail"],"methodCalls":[["QuickStep/get",{"accountId":"1"},"c1"]]}"#;
        assert!(crate::jmap::family::classify(ok, None).is_some());
        let core_only = br#"{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["QuickStep/get",{"accountId":"1"},"c1"]]}"#;
        assert!(crate::jmap::family::classify(core_only, None).is_none());
    }
}
