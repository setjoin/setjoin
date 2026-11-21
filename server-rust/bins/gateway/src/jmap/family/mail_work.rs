//! #374 MailWork/* family (frozen Go mail_work.go).

use std::collections::BTreeSet;

use chrono::{DateTime, NaiveDate, NaiveTime};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::args::{decode, Kind};
use super::seam::{ics, read, read_sql, resolve, since_state, write, write_sql, Type};
use super::{always, go_compact, Answer, Cx, Gate, Method, MethodError, Reply};

const MAIL_CAP: &str = "urn:ietf:params:jmap:mail";
const TOGGLE_WORK: &str = "feature.shared_mail_work";
const TOGGLE_NOTIFICATIONS: &str = "feature.shared_mail_notifications";
const TOGGLE_ANALYTICS: &str = "feature.shared_mail_analytics";
const TOGGLE_INTEGRATIONS: &str = "feature.shared_mail_integrations";

pub(super) const METHODS: &[Method] = &[
    Method {
        name: "MailWork/get",
        capability: MAIL_CAP,
        app: "",
        gate: Gate::Read,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: run_get,
    },
    Method {
        name: "MailWork/changes",
        capability: MAIL_CAP,
        app: "",
        gate: Gate::Read,
        account: true,
        mutator: false,
        state: true,
        ready: always,
        run: run_changes,
    },
    Method {
        name: "MailWork/set",
        capability: MAIL_CAP,
        app: "",
        gate: Gate::Collaborate,
        account: true,
        mutator: true,
        state: true,
        ready: always,
        run: run_set,
    },
    Method {
        name: "MailWork/action",
        capability: MAIL_CAP,
        app: "",
        gate: Gate::Collaborate,
        account: true,
        mutator: true,
        state: true,
        ready: always,
        run: run_action,
    },
    Method {
        name: "MailWorkCollaborators/get",
        capability: MAIL_CAP,
        app: "",
        gate: Gate::Read,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: run_collaborators_get,
    },
    Method {
        name: "MailWorkPolicy/get",
        capability: MAIL_CAP,
        app: "",
        gate: Gate::Read,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: run_policy_get,
    },
    Method {
        name: "MailWorkPolicy/set",
        capability: MAIL_CAP,
        app: "",
        gate: Gate::Collaborate,
        account: true,
        mutator: true,
        state: true,
        ready: always,
        run: run_policy_set,
    },
    Method {
        name: "MailWorkNotificationPreferences/get",
        capability: MAIL_CAP,
        app: "",
        gate: Gate::Read,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: run_notification_preferences_get,
    },
    Method {
        name: "MailWorkNotificationPreferences/set",
        capability: MAIL_CAP,
        app: "",
        gate: Gate::Collaborate,
        account: true,
        mutator: true,
        state: true,
        ready: always,
        run: run_notification_preferences_set,
    },
    Method {
        name: "MailWorkMetrics/get",
        capability: MAIL_CAP,
        app: "",
        gate: Gate::Read,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: run_metrics_get,
    },
];

fn disabled() -> MethodError {
    MethodError::new("serverUnavailable", "shared mail work is not enabled")
}

fn invalid(detail: &str) -> MethodError {
    MethodError::new("invalidArguments", detail)
}

async fn require_work(cx: &Cx<'_>) -> Result<(), MethodError> {
    if cx.toggle(TOGGLE_WORK).await == Some(true) {
        Ok(())
    } else {
        Err(disabled())
    }
}

async fn require_work_and(cx: &Cx<'_>, extra: &str) -> Result<(), MethodError> {
    require_work(cx).await?;
    if cx.toggle(extra).await == Some(true) {
        Ok(())
    } else {
        Err(disabled())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, MethodError> {
    let raw = serde_json::to_string(value).map_err(|_| MethodError::server_fail())?;
    let canonical = go_compact(&raw).ok_or_else(MethodError::server_fail)?;
    Ok(sha256_hex(canonical.as_bytes()))
}

fn parse_nonzero_uuid(raw: &str) -> Option<String> {
    let inner = match raw.len() {
        36 => raw,
        38 if raw.starts_with('{') && raw.ends_with('}') => &raw[1..37],
        45 if raw
            .get(..9)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("urn:uuid:")) =>
        {
            &raw[9..]
        }
        32 => {
            if !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            let lower = raw.to_ascii_lowercase();
            if lower.bytes().all(|b| b == b'0') {
                return None;
            }
            let mut formatted = String::with_capacity(36);
            formatted.push_str(&lower[0..8]);
            formatted.push('-');
            formatted.push_str(&lower[8..12]);
            formatted.push('-');
            formatted.push_str(&lower[12..16]);
            formatted.push('-');
            formatted.push_str(&lower[16..20]);
            formatted.push('-');
            formatted.push_str(&lower[20..32]);
            return Some(formatted);
        }
        _ => return None,
    };
    let bytes = inner.as_bytes();
    let dashes = [8usize, 13, 18, 23];
    let mut any_nonzero = false;
    for (i, b) in bytes.iter().enumerate() {
        if dashes.contains(&i) {
            if *b != b'-' {
                return None;
            }
        } else if !b.is_ascii_hexdigit() {
            return None;
        } else if *b != b'0' {
            any_nonzero = true;
        }
    }
    any_nonzero.then(|| inner.to_ascii_lowercase())
}

fn parse_non_negative_decimal(raw: &str) -> Option<i64> {
    raw.parse::<i64>().ok().filter(|v| *v >= 0)
}

fn parse_positive_decimal(raw: &str) -> Option<i64> {
    raw.parse::<i64>().ok().filter(|v| *v > 0)
}

fn parse_rfc3339(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    if bytes.len() < 20 || bytes[10] != b'T' || raw.contains('z') || raw.contains('t') {
        return None;
    }
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|dt| dt.to_rfc3339())
}

fn parse_hhmm(raw: &str) -> Option<NaiveTime> {
    let bytes = raw.as_bytes();
    if bytes.len() != 5
        || bytes[2] != b':'
        || !bytes[0].is_ascii_digit()
        || !bytes[1].is_ascii_digit()
        || !bytes[3].is_ascii_digit()
        || !bytes[4].is_ascii_digit()
    {
        return None;
    }
    NaiveTime::parse_from_str(raw, "%H:%M").ok()
}

fn parse_ymd(raw: &str) -> Option<NaiveDate> {
    let bytes = raw.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
    {
        return None;
    }
    NaiveDate::parse_from_str(raw, "%Y-%m-%d").ok()
}

fn valid_location(name: &str) -> bool {
    matches!(name, "" | "UTC" | "Local") || matches!(ics::load_location(name), ics::Zone::Tz(_))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkSetCanonical<'a> {
    account_id: &'a str,
    thread_id: &'a str,
    operation_id: &'a str,
    action: &'a str,
    expected_generation: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    assignee_user_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    due_at: Option<&'a str>,
    reason: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkActionCanonical<'a> {
    account_id: &'a str,
    thread_id: &'a str,
    operation_id: &'a str,
    expected_generation: &'a str,
    action_kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_id: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicySetCanonical<'a> {
    account_id: &'a str,
    operation_id: &'a str,
    expected_generation: &'a str,
    timezone: &'a str,
    weekday_mask: i64,
    workday_start: &'a str,
    workday_end: &'a str,
    holidays: Option<&'a [String]>,
    sla_minutes: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NotificationPreferencesSetCanonical<'a> {
    account_id: &'a str,
    operation_id: &'a str,
    category: &'a str,
    delivery: &'a str,
    timezone: &'a str,
    digest_hour: i64,
    expected_generation: &'a str,
}

fn run_get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async {
        require_work(cx).await?;
        const FIELDS: &[(&str, Kind)] = &[("accountId", Kind::Str), ("ids", Kind::Strings)];
        let args = decode(cx.args(), "", FIELDS)?;
        let ids = args.strings("ids");
        if ids.is_some_and(|list| list.len() > 256) {
            return Err(MethodError::new(
                "requestTooLarge",
                "too many ids requested",
            ));
        }
        let scope = resolve(cx, args.str("accountId")).await?;
        let ids: Option<Vec<String>> = ids.map(|list| list.to_vec());
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT mail_work_get($1,$2,$3)::text"),
            &[(&ids, Type::TEXT_ARRAY)],
        )
        .await?;
        Ok(Answer {
            name: "MailWork/get",
            args: raw,
        })
    })
}

fn run_changes<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async {
        require_work(cx).await?;
        const FIELDS: &[(&str, Kind)] = &[
            ("accountId", Kind::Str),
            ("sinceState", Kind::Str),
            ("maxChanges", Kind::Int),
        ];
        let args = decode(cx.args(), "", FIELDS)?;
        let since = args.str("sinceState");
        since_state(since)?;
        let raw_max = args.int("maxChanges");
        let max_changes: Option<i32> = if raw_max <= 0 {
            None
        } else {
            Some(i32::try_from(raw_max).map_err(|_| MethodError::server_fail())?)
        };
        let scope = resolve(cx, args.str("accountId")).await?;
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT mail_work_changes($1,$2,$3,$4)::text"),
            &[(&since, Type::TEXT), (&max_changes, Type::INT4)],
        )
        .await?;
        Ok(Answer {
            name: "MailWork/changes",
            args: raw,
        })
    })
}

fn run_set<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async {
        require_work(cx).await?;
        const FIELDS: &[(&str, Kind)] = &[
            ("accountId", Kind::Str),
            ("threadId", Kind::Str),
            ("operationId", Kind::Str),
            ("action", Kind::Str),
            ("expectedGeneration", Kind::Str),
            ("assigneeUserId", Kind::Str),
            ("status", Kind::Str),
            ("dueAt", Kind::Str),
            ("reason", Kind::Str),
        ];
        let args = decode(cx.args(), "", FIELDS)?;
        let operation_id = parse_nonzero_uuid(args.str("operationId"))
            .ok_or_else(|| invalid("operationId must be a non-zero UUID"))?;
        let expected = parse_non_negative_decimal(args.str("expectedGeneration"))
            .ok_or_else(|| invalid("expectedGeneration must be a non-negative decimal string"))?
            .to_string();
        let assignee = match args.opt_str("assigneeUserId") {
            Some(raw) => Some(
                parse_positive_decimal(raw)
                    .ok_or_else(|| invalid("assigneeUserId must be a positive decimal string"))?
                    .to_string(),
            ),
            None => None,
        };
        let due = match args.opt_str("dueAt") {
            Some(raw) => Some(parse_rfc3339(raw).ok_or_else(|| invalid("dueAt must be RFC3339"))?),
            None => None,
        };
        let scope = resolve(cx, args.str("accountId")).await?;
        let digest = canonical_digest(&WorkSetCanonical {
            account_id: args.str("accountId"),
            thread_id: args.str("threadId"),
            operation_id: args.str("operationId"),
            action: args.str("action"),
            expected_generation: args.str("expectedGeneration"),
            assignee_user_id: args.opt_str("assigneeUserId"),
            status: args.opt_str("status"),
            due_at: args.opt_str("dueAt"),
            reason: args.str("reason"),
        })?;
        let thread_id = args.str("threadId");
        let action = args.str("action");
        let status = args.opt_str("status");
        let reason = args.str("reason");
        let raw = write(
            cx,
            &scope,
            "mail_work.set",
            write_sql!(
                "SELECT mail_work_set($1,$2,$4,$5::text::uuid,$6,$7::text::bigint,$8::text::bigint,$9,$10::text::timestamptz,$11,$12)::text"
            ),
            &[
                (&thread_id, Type::TEXT),
                (&operation_id, Type::TEXT),
                (&action, Type::TEXT),
                (&expected, Type::TEXT),
                (&assignee, Type::TEXT),
                (&status, Type::TEXT),
                (&due, Type::TEXT),
                (&reason, Type::TEXT),
                (&digest, Type::TEXT),
            ],
        )
        .await?;
        Ok(Answer {
            name: "MailWork/set",
            args: raw,
        })
    })
}

fn run_action<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async {
        require_work_and(cx, TOGGLE_INTEGRATIONS).await?;
        const FIELDS: &[(&str, Kind)] = &[
            ("accountId", Kind::Str),
            ("threadId", Kind::Str),
            ("operationId", Kind::Str),
            ("expectedGeneration", Kind::Str),
            ("actionKind", Kind::Str),
            ("targetId", Kind::Str),
        ];
        let args = decode(cx.args(), "", FIELDS)?;
        let operation_id = parse_nonzero_uuid(args.str("operationId"))
            .ok_or_else(|| invalid("operationId must be a non-zero UUID"))?;
        let expected = parse_positive_decimal(args.str("expectedGeneration"))
            .ok_or_else(|| invalid("expectedGeneration must be a positive decimal string"))?
            .to_string();
        let action_kind = args.str("actionKind");
        if !matches!(action_kind, "task" | "chat" | "drive") {
            return Err(invalid("actionKind must be task, chat, or drive"));
        }
        let target = match args.opt_str("targetId") {
            Some(raw) => Some(
                parse_positive_decimal(raw)
                    .ok_or_else(|| invalid("targetId must be a positive decimal string"))?
                    .to_string(),
            ),
            None => None,
        };
        if (action_kind == "task" && target.is_some())
            || (action_kind != "task" && target.is_none())
        {
            return Err(invalid("targetId is required only for chat and drive"));
        }
        let scope = resolve(cx, args.str("accountId")).await?;
        let digest = canonical_digest(&WorkActionCanonical {
            account_id: args.str("accountId"),
            thread_id: args.str("threadId"),
            operation_id: args.str("operationId"),
            expected_generation: args.str("expectedGeneration"),
            action_kind,
            target_id: args.opt_str("targetId"),
        })?;
        let thread_id = args.str("threadId");
        let raw = write(
            cx,
            &scope,
            "mail_work.action",
            write_sql!(
                "SELECT mail_work_action_enqueue($1,$2,$4,$5::text::uuid,$6::text::bigint,$7,$8::text::bigint,$9)::text"
            ),
            &[
                (&thread_id, Type::TEXT),
                (&operation_id, Type::TEXT),
                (&expected, Type::TEXT),
                (&action_kind, Type::TEXT),
                (&target, Type::TEXT),
                (&digest, Type::TEXT),
            ],
        )
        .await?;
        Ok(Answer {
            name: "MailWork/action",
            args: raw,
        })
    })
}

fn run_collaborators_get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async {
        require_work(cx).await?;
        const FIELDS: &[(&str, Kind)] = &[
            ("accountId", Kind::Str),
            ("query", Kind::Str),
            ("limit", Kind::Int),
        ];
        let args = decode(cx.args(), "", FIELDS)?;
        let query = args.str("query");
        if query.len() > 128 {
            return Err(invalid("query is too long"));
        }
        let mut limit = args.int("limit");
        if limit == 0 {
            limit = 20;
        }
        if !(1..=50).contains(&limit) {
            return Err(invalid("limit must be between 1 and 50"));
        }
        let limit = limit as i32;
        let scope = resolve(cx, args.str("accountId")).await?;
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT mail_work_collaborators_get($1,$2,$3,$4)::text"),
            &[(&query, Type::TEXT), (&limit, Type::INT4)],
        )
        .await?;
        Ok(Answer {
            name: "MailWorkCollaborators/get",
            args: raw,
        })
    })
}

fn run_policy_get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async {
        require_work(cx).await?;
        const FIELDS: &[(&str, Kind)] = &[("accountId", Kind::Str)];
        let args = decode(cx.args(), "", FIELDS)?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT mail_work_sla_policy_get($1,$2)::text"),
            &[],
        )
        .await?;
        Ok(Answer {
            name: "MailWorkPolicy/get",
            args: raw,
        })
    })
}

fn run_policy_set<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async {
        require_work(cx).await?;
        const FIELDS: &[(&str, Kind)] = &[
            ("accountId", Kind::Str),
            ("operationId", Kind::Str),
            ("expectedGeneration", Kind::Str),
            ("timezone", Kind::Str),
            ("weekdayMask", Kind::Int),
            ("workdayStart", Kind::Str),
            ("workdayEnd", Kind::Str),
            ("holidays", Kind::Strings),
            ("slaMinutes", Kind::Int),
        ];
        let args = decode(cx.args(), "", FIELDS)?;
        let operation_id = parse_nonzero_uuid(args.str("operationId"))
            .ok_or_else(|| invalid("operationId must be a non-zero UUID"))?;
        let expected = parse_non_negative_decimal(args.str("expectedGeneration"))
            .ok_or_else(|| invalid("expectedGeneration must be a non-negative decimal string"))?
            .to_string();
        let timezone = args.str("timezone");
        let weekday_mask = args.int("weekdayMask");
        let sla_minutes = args.int("slaMinutes");
        let holidays = args.strings("holidays");
        if !valid_location(timezone)
            || !(1..=127).contains(&weekday_mask)
            || !(1..=525_600).contains(&sla_minutes)
            || holidays.is_some_and(|list| list.len() > 366)
        {
            return Err(invalid("invalid SLA policy bounds"));
        }
        let workday_start = args.str("workdayStart");
        let workday_end = args.str("workdayEnd");
        let (Some(start), Some(end)) = (parse_hhmm(workday_start), parse_hhmm(workday_end)) else {
            return Err(invalid(
                "workdayStart and workdayEnd must be HH:MM with start before end",
            ));
        };
        if start >= end {
            return Err(invalid(
                "workdayStart and workdayEnd must be HH:MM with start before end",
            ));
        }
        if let Some(list) = holidays {
            let mut seen = BTreeSet::new();
            for holiday in list {
                if parse_ymd(holiday).is_none() || !seen.insert(holiday.as_str()) {
                    return Err(invalid("holidays must contain unique YYYY-MM-DD values"));
                }
            }
        }
        let scope = resolve(cx, args.str("accountId")).await?;
        let digest = canonical_digest(&PolicySetCanonical {
            account_id: args.str("accountId"),
            operation_id: args.str("operationId"),
            expected_generation: args.str("expectedGeneration"),
            timezone,
            weekday_mask,
            workday_start,
            workday_end,
            holidays,
            sla_minutes,
        })?;
        let weekday_mask_i32 = weekday_mask as i32;
        let sla_minutes_i32 = sla_minutes as i32;
        let holidays_vec: Option<Vec<String>> = holidays.map(|list| list.to_vec());
        let raw = write(
            cx,
            &scope,
            "mail_work.policy_set",
            write_sql!(
                "SELECT mail_work_sla_policy_set($1,$2,$4::text::uuid,$5::text::bigint,$6,$7,$8::text::time,$9::text::time,$10::text[]::date[],$11,$12)::text"
            ),
            &[
                (&operation_id, Type::TEXT),
                (&expected, Type::TEXT),
                (&timezone, Type::TEXT),
                (&weekday_mask_i32, Type::INT4),
                (&workday_start, Type::TEXT),
                (&workday_end, Type::TEXT),
                (&holidays_vec, Type::TEXT_ARRAY),
                (&sla_minutes_i32, Type::INT4),
                (&digest, Type::TEXT),
            ],
        )
        .await?;
        Ok(Answer {
            name: "MailWorkPolicy/set",
            args: raw,
        })
    })
}

fn run_notification_preferences_get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async {
        require_work_and(cx, TOGGLE_NOTIFICATIONS).await?;
        const FIELDS: &[(&str, Kind)] = &[("accountId", Kind::Str)];
        let args = decode(cx.args(), "", FIELDS)?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT mail_work_notification_preferences_get($1,$2)::text"),
            &[],
        )
        .await?;
        Ok(Answer {
            name: "MailWorkNotificationPreferences/get",
            args: raw,
        })
    })
}

fn run_notification_preferences_set<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async {
        require_work_and(cx, TOGGLE_NOTIFICATIONS).await?;
        const FIELDS: &[(&str, Kind)] = &[
            ("accountId", Kind::Str),
            ("operationId", Kind::Str),
            ("category", Kind::Str),
            ("delivery", Kind::Str),
            ("timezone", Kind::Str),
            ("digestHour", Kind::Int),
            ("expectedGeneration", Kind::Str),
        ];
        let args = decode(cx.args(), "", FIELDS)?;
        let operation_id = parse_nonzero_uuid(args.str("operationId"))
            .ok_or_else(|| invalid("operationId must be a non-zero UUID"))?;
        let expected = parse_non_negative_decimal(args.str("expectedGeneration"))
            .ok_or_else(|| invalid("expectedGeneration must be a non-negative decimal string"))?
            .to_string();
        let scope = resolve(cx, args.str("accountId")).await?;
        let digest_hour = args.int("digestHour");
        let digest = canonical_digest(&NotificationPreferencesSetCanonical {
            account_id: args.str("accountId"),
            operation_id: args.str("operationId"),
            category: args.str("category"),
            delivery: args.str("delivery"),
            timezone: args.str("timezone"),
            digest_hour,
            expected_generation: args.str("expectedGeneration"),
        })?;
        let digest_hour_i32 = i32::try_from(digest_hour).map_err(|_| MethodError::server_fail())?;
        let category = args.str("category");
        let delivery = args.str("delivery");
        let timezone = args.str("timezone");
        let raw = write(
            cx,
            &scope,
            "mail_work.notification_preferences_set",
            write_sql!(
                "SELECT mail_work_notification_preferences_set($1,$2,$4::text::uuid,$5,$6,$7,$8,$9::text::bigint,$10)::text"
            ),
            &[
                (&operation_id, Type::TEXT),
                (&category, Type::TEXT),
                (&delivery, Type::TEXT),
                (&timezone, Type::TEXT),
                (&digest_hour_i32, Type::INT4),
                (&expected, Type::TEXT),
                (&digest, Type::TEXT),
            ],
        )
        .await?;
        Ok(Answer {
            name: "MailWorkNotificationPreferences/set",
            args: raw,
        })
    })
}

fn run_metrics_get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async {
        require_work_and(cx, TOGGLE_ANALYTICS).await?;
        const FIELDS: &[(&str, Kind)] = &[
            ("accountId", Kind::Str),
            ("from", Kind::Str),
            ("to", Kind::Str),
            ("policyVersion", Kind::Int),
        ];
        let args = decode(cx.args(), "", FIELDS)?;
        let from = parse_ymd(args.str("from")).ok_or_else(|| invalid("from must be YYYY-MM-DD"))?;
        let to = parse_ymd(args.str("to"))
            .ok_or_else(|| invalid("to must be YYYY-MM-DD, on or after from, within 366 days"))?;
        if to < from || (to - from).num_days() > 366 {
            return Err(invalid(
                "to must be YYYY-MM-DD, on or after from, within 366 days",
            ));
        }
        let mut policy_version = args.int("policyVersion");
        if policy_version == 0 {
            policy_version = 1;
        }
        if policy_version < 1 {
            return Err(invalid("policyVersion must be positive"));
        }
        let policy_version_i32 =
            i32::try_from(policy_version).map_err(|_| MethodError::server_fail())?;
        let scope = resolve(cx, args.str("accountId")).await?;
        let from_str = from.format("%Y-%m-%d").to_string();
        let to_str = to.format("%Y-%m-%d").to_string();
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT mail_work_metrics_get($1,$2,$3::text::date,$4::text::date,$5)::text"),
            &[
                (&from_str, Type::TEXT),
                (&to_str, Type::TEXT),
                (&policy_version_i32, Type::INT4),
            ],
        )
        .await?;
        Ok(Answer {
            name: "MailWorkMetrics/get",
            args: raw,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_metadata_covers_all_ten_mail_work_methods() {
        assert_eq!(METHODS.len(), 10);
        for method in METHODS {
            assert_eq!(method.capability, MAIL_CAP);
            assert_eq!(method.app, "");
            assert!(method.account);
        }
        let state_methods: Vec<&str> = METHODS
            .iter()
            .filter(|method| method.state)
            .map(|method| method.name)
            .collect();
        assert_eq!(
            state_methods,
            vec![
                "MailWork/changes",
                "MailWork/set",
                "MailWork/action",
                "MailWorkPolicy/set",
                "MailWorkNotificationPreferences/set",
            ]
        );
        let mutator_methods: Vec<&str> = METHODS
            .iter()
            .filter(|method| method.mutator)
            .map(|method| method.name)
            .collect();
        assert_eq!(
            mutator_methods,
            vec![
                "MailWork/set",
                "MailWork/action",
                "MailWorkPolicy/set",
                "MailWorkNotificationPreferences/set",
            ]
        );
    }

    #[test]
    fn uuid_parser_mirrors_go_uuid_parse() {
        assert_eq!(
            parse_nonzero_uuid("00000000-0000-4000-8000-000000000007").as_deref(),
            Some("00000000-0000-4000-8000-000000000007")
        );
        assert_eq!(
            parse_nonzero_uuid("{00000000-0000-4000-8000-00000000000A}").as_deref(),
            Some("00000000-0000-4000-8000-00000000000a")
        );
        assert_eq!(
            parse_nonzero_uuid("urn:uuid:00000000000040008000000000000007"),
            None
        );
        assert_eq!(
            parse_nonzero_uuid("URN:UUID:00000000-0000-4000-8000-000000000007").as_deref(),
            Some("00000000-0000-4000-8000-000000000007")
        );
        assert_eq!(
            parse_nonzero_uuid("00000000000040008000000000000007").as_deref(),
            Some("00000000-0000-4000-8000-000000000007")
        );
        assert_eq!(
            parse_nonzero_uuid("00000000-0000-0000-0000-000000000000"),
            None
        );
        assert_eq!(parse_nonzero_uuid("not-a-uuid"), None);
    }

    #[test]
    fn date_time_and_decimal_parsers_match_go() {
        assert_eq!(parse_non_negative_decimal("0"), Some(0));
        assert_eq!(parse_non_negative_decimal("-1"), None);
        assert_eq!(parse_positive_decimal("0"), None);
        assert_eq!(parse_positive_decimal("1"), Some(1));
        assert!(parse_rfc3339("2026-10-01T09:00:00Z").is_some());
        assert!(parse_rfc3339("2026-10-01t09:00:00Z").is_none());
        assert!(parse_rfc3339("2026-10-01 09:00:00Z").is_none());
        assert!(parse_hhmm("09:00").is_some());
        assert!(parse_hhmm("9:00").is_none());
        assert!(parse_hhmm("24:00").is_none());
        assert!(parse_ymd("2026-10-01").is_some());
        assert!(parse_ymd("2026-1-1").is_none());
        assert!(valid_location("UTC"));
        assert!(valid_location(""));
        assert!(valid_location("Local"));
        assert!(!valid_location("Not/AZone"));
        assert!(!valid_location("../UTC"));
    }

    #[test]
    fn canonical_digests_match_go_json_marshal_order_and_escaping() {
        let digest_work_set = canonical_digest(&WorkSetCanonical {
            account_id: "7",
            thread_id: "t<1>",
            operation_id: "00000000-0000-4000-8000-000000000007",
            action: "claim",
            expected_generation: "0",
            assignee_user_id: None,
            status: None,
            due_at: None,
            reason: "a&b",
        })
        .expect("digest");
        let expected_work_set = sha256_hex(
            br#"{"accountId":"7","threadId":"t\u003c1\u003e","operationId":"00000000-0000-4000-8000-000000000007","action":"claim","expectedGeneration":"0","reason":"a\u0026b"}"#,
        );
        assert_eq!(digest_work_set, expected_work_set);

        let digest_policy = canonical_digest(&PolicySetCanonical {
            account_id: "7",
            operation_id: "00000000-0000-4000-8000-000000000007",
            expected_generation: "0",
            timezone: "UTC",
            weekday_mask: 62,
            workday_start: "09:00",
            workday_end: "17:00",
            holidays: None,
            sla_minutes: 480,
        })
        .expect("digest");
        let expected_policy = sha256_hex(
            br#"{"accountId":"7","operationId":"00000000-0000-4000-8000-000000000007","expectedGeneration":"0","timezone":"UTC","weekdayMask":62,"workdayStart":"09:00","workdayEnd":"17:00","holidays":null,"slaMinutes":480}"#,
        );
        assert_eq!(digest_policy, expected_policy);
    }
}
