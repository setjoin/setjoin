//! #377 Reminder/get, Reminder/dismiss and Reminder/snooze (frozen Go reminder.go).

use super::args::{self, Kind};
use super::seam::{read, read_sql, resolve, write, write_sql, Type};
use super::{always, Answer, Cx, Gate, Method, MethodError, Reply};

const CAPABILITY: &str = "urn:setjoin:params:jmap:reminders";

pub(super) const METHODS: &[Method] = &[
    Method {
        name: "Reminder/get",
        capability: CAPABILITY,
        app: "",
        gate: Gate::Personal,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: get,
    },
    Method {
        name: "Reminder/dismiss",
        capability: CAPABILITY,
        app: "",
        gate: Gate::Personal,
        account: true,
        mutator: true,
        state: false,
        ready: always,
        run: dismiss,
    },
    Method {
        name: "Reminder/snooze",
        capability: CAPABILITY,
        app: "",
        gate: Gate::Personal,
        account: true,
        mutator: true,
        state: false,
        ready: always,
        run: snooze,
    },
];

fn clamp_limit(limit: i64) -> i32 {
    if limit <= 0 || limit > 500 {
        100
    } else {
        limit as i32
    }
}

fn get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        const FIELDS: &[(&str, Kind)] = &[("accountId", Kind::Str), ("limit", Kind::Int)];
        let args = args::decode(cx.args(), "", FIELDS)?;
        let limit = clamp_limit(args.int("limit"));
        let scope = resolve(cx, args.str("accountId")).await?;
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT reminders_get($1,$3)::text"),
            &[(&limit, Type::INT4)],
        )
        .await?;
        Ok(Answer {
            name: "Reminder/get",
            args: raw,
        })
    })
}

fn dismiss<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        const FIELDS: &[(&str, Kind)] = &[
            ("accountId", Kind::Str),
            ("reminderId", Kind::Str),
            ("all", Kind::Bool),
        ];
        let args = args::decode(cx.args(), "", FIELDS)?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let reminder_id = args.str("reminderId");
        let raw = if args.bool("all") || reminder_id.is_empty() {
            write(
                cx,
                &scope,
                "reminder.dismiss_all",
                write_sql!("SELECT reminder_dismiss_all($1)::text"),
                &[],
            )
            .await?
        } else {
            let rid = super::parse_id(reminder_id)
                .ok_or_else(|| MethodError::new("invalidArguments", "invalid reminderId"))?;
            write(
                cx,
                &scope,
                "reminder.dismiss",
                write_sql!("SELECT reminder_dismiss($1,$4)::text"),
                &[(&rid, Type::INT8)],
            )
            .await?
        };
        Ok(Answer {
            name: "Reminder/dismiss",
            args: raw,
        })
    })
}

fn snooze<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        const FIELDS: &[(&str, Kind)] = &[
            ("accountId", Kind::Str),
            ("reminderId", Kind::Str),
            ("until", Kind::Str),
        ];
        let args = args::decode(cx.args(), "", FIELDS)?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let rid = super::parse_id(args.str("reminderId"))
            .ok_or_else(|| MethodError::new("invalidArguments", "invalid reminderId"))?;
        let until = args.str("until");
        let raw = write(
            cx,
            &scope,
            "reminder.snooze",
            write_sql!("SELECT reminder_snooze($1,$4,$5::text::timestamptz)::text"),
            &[(&rid, Type::INT8), (&until, Type::TEXT)],
        )
        .await?;
        Ok(Answer {
            name: "Reminder/snooze",
            args: raw,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn methods_match_go_metadata() {
        assert_eq!(METHODS.len(), 3);
        assert_eq!(
            METHODS
                .iter()
                .map(|m| (m.name, m.capability, m.gate, m.account, m.mutator, m.state))
                .collect::<Vec<_>>(),
            vec![
                (
                    "Reminder/get",
                    CAPABILITY,
                    Gate::Personal,
                    true,
                    false,
                    false
                ),
                (
                    "Reminder/dismiss",
                    CAPABILITY,
                    Gate::Personal,
                    true,
                    true,
                    false
                ),
                (
                    "Reminder/snooze",
                    CAPABILITY,
                    Gate::Personal,
                    true,
                    true,
                    false
                ),
            ]
        );
    }

    #[test]
    fn limit_clamps_like_go() {
        assert_eq!(clamp_limit(0), 100);
        assert_eq!(clamp_limit(-5), 100);
        assert_eq!(clamp_limit(501), 100);
        assert_eq!(clamp_limit(10_000_000_000), 100);
        assert_eq!(clamp_limit(1), 1);
        assert_eq!(clamp_limit(500), 500);
        assert_eq!(clamp_limit(25), 25);
    }

    #[test]
    fn arg_decode_preserves_go_type_errors() {
        const GET: &[(&str, Kind)] = &[("accountId", Kind::Str), ("limit", Kind::Int)];
        let err = args::decode(r#"{"accountId":"1","limit":"bad"}"#, "", GET)
            .err()
            .expect("type error");
        assert_eq!(err.kind, "invalidArguments");
        assert_eq!(
            err.detail,
            "json: cannot unmarshal string into Go struct field .limit of type int"
        );

        const DISMISS: &[(&str, Kind)] = &[
            ("accountId", Kind::Str),
            ("reminderId", Kind::Str),
            ("all", Kind::Bool),
        ];
        let err = args::decode(r#"{"accountId":"1","all":"yes"}"#, "", DISMISS)
            .err()
            .expect("type error");
        assert_eq!(
            err.detail,
            "json: cannot unmarshal string into Go struct field .all of type bool"
        );
    }
}
