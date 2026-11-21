//! #372 MailDraft/* and MailComment/* (frozen Go mail_draft.go, mail_comment.go).

use serde::Serialize;
use serde_json::{value::RawValue, Value};
use sha2::{Digest as _, Sha256};

use super::args::{decode, Kind};
use super::seam::{read, read_sql, resolve, write, write_sql, Type};
use super::{always, Answer, Cx, Gate, Handled, Method, MethodError, Reply};

const DRAFT_TOGGLE: &str = "feature.shared_mail_drafts";
const DRAFT_DISABLED: &str = "shared mail drafts are not enabled";
const COMMENT_TOGGLE: &str = "feature.shared_mail_comments";
const COMMENT_DISABLED: &str = "shared mail comments are not enabled";

pub(super) const METHODS: &[Method] = &[
    Method {
        name: "MailDraft/get",
        capability: "urn:ietf:params:jmap:mail",
        app: "",
        gate: Gate::Read,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: get,
    },
    Method {
        name: "MailDraft/open",
        capability: "urn:ietf:params:jmap:mail",
        app: "",
        gate: Gate::Collaborate,
        account: true,
        mutator: true,
        state: false,
        ready: always,
        run: open,
    },
    Method {
        name: "MailDraft/lease",
        capability: "urn:ietf:params:jmap:mail",
        app: "",
        gate: Gate::Collaborate,
        account: true,
        mutator: true,
        state: true,
        ready: always,
        run: lease,
    },
    Method {
        name: "MailDraft/save",
        capability: "urn:ietf:params:jmap:mail",
        app: "",
        gate: Gate::Collaborate,
        account: true,
        mutator: true,
        state: true,
        ready: always,
        run: save,
    },
    Method {
        name: "MailDraft/replace",
        capability: "urn:ietf:params:jmap:mail",
        app: "",
        gate: Gate::Collaborate,
        account: true,
        mutator: true,
        state: true,
        ready: always,
        run: replace,
    },
    Method {
        name: "MailComment/get",
        capability: "urn:ietf:params:jmap:mail",
        app: "",
        gate: Gate::Read,
        account: true,
        mutator: false,
        state: false,
        ready: always,
        run: comment_get,
    },
    Method {
        name: "MailComment/set",
        capability: "urn:ietf:params:jmap:mail",
        app: "",
        gate: Gate::Collaborate,
        account: true,
        mutator: true,
        state: true,
        ready: always,
        run: comment_set,
    },
];

async fn require_toggle(cx: &Cx<'_>, key: &str, disabled: &str) -> Result<(), MethodError> {
    match cx.toggle(key).await {
        Some(true) => Ok(()),
        Some(false) => Err(MethodError::new("serverUnavailable", disabled)),
        None => Err(MethodError::server_fail()),
    }
}

fn parse_uuid(raw: &str) -> Option<String> {
    if !raw.is_ascii() {
        return None;
    }
    let hex: String = match raw.len() {
        32 => raw.to_ascii_lowercase(),
        36 => {
            let bytes = raw.as_bytes();
            if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
                return None;
            }
            let mut out = String::with_capacity(32);
            out.push_str(&raw[..8]);
            out.push_str(&raw[9..13]);
            out.push_str(&raw[14..18]);
            out.push_str(&raw[19..23]);
            out.push_str(&raw[24..]);
            out.to_ascii_lowercase()
        }
        38 if raw.starts_with('{') && raw.ends_with('}') => return parse_uuid(&raw[1..37]),
        45 if raw
            .get(..9)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("urn:uuid:")) =>
        {
            return parse_uuid(&raw[9..]);
        }
        _ => return None,
    };
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    if hex.bytes().all(|b| b == b'0') {
        return None;
    }
    let mut canonical = String::with_capacity(36);
    canonical.push_str(&hex[..8]);
    canonical.push('-');
    canonical.push_str(&hex[8..12]);
    canonical.push('-');
    canonical.push_str(&hex[12..16]);
    canonical.push('-');
    canonical.push_str(&hex[16..20]);
    canonical.push('-');
    canonical.push_str(&hex[20..]);
    Some(canonical)
}

fn parse_positive_i64(raw: &str) -> Option<i64> {
    raw.parse::<i64>().ok().filter(|&value| value > 0)
}

fn parse_non_negative_i64(raw: &str) -> Option<i64> {
    raw.parse::<i64>().ok().filter(|&value| value >= 0)
}

fn parse_rfc3339(raw: &str) -> Option<String> {
    if !raw.is_ascii() || raw.len() < 20 || raw.as_bytes()[10] != b'T' || raw.ends_with('z') {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|dt| dt.to_rfc3339())
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let sum = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in sum {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn request_digest<T: Serialize>(value: &T) -> Result<String, MethodError> {
    let raw = serde_json::to_string(value).map_err(|_| MethodError::server_fail())?;
    let compacted = super::go_compact(&raw).ok_or_else(MethodError::server_fail)?;
    Ok(sha256_hex(compacted.as_bytes()))
}

#[derive(Serialize)]
struct OpenDigest<'a> {
    #[serde(rename = "accountId")]
    account_id: &'a str,
    #[serde(rename = "operationId")]
    operation_id: &'a str,
    #[serde(rename = "messageId")]
    message_id: &'a str,
    #[serde(rename = "receivedAt")]
    received_at: &'a str,
    #[serde(rename = "finalSenderAddress")]
    final_sender_address: &'a str,
}

#[derive(Serialize)]
struct LeaseDigest<'a> {
    #[serde(rename = "accountId")]
    account_id: &'a str,
    #[serde(rename = "operationId")]
    operation_id: &'a str,
    id: &'a str,
    action: &'a str,
    #[serde(rename = "expectedEpoch")]
    expected_epoch: &'a str,
    #[serde(rename = "targetUserId", skip_serializing_if = "Option::is_none")]
    target_user_id: Option<&'a str>,
    reason: &'a str,
}

#[derive(Serialize)]
struct SaveDigest<'a> {
    #[serde(rename = "accountId")]
    account_id: &'a str,
    #[serde(rename = "operationId")]
    operation_id: &'a str,
    id: &'a str,
    #[serde(rename = "expectedEpoch")]
    expected_epoch: &'a str,
    #[serde(rename = "baseRevision")]
    base_revision: &'a str,
    #[serde(rename = "messageId")]
    message_id: &'a str,
    #[serde(rename = "receivedAt")]
    received_at: &'a str,
    #[serde(rename = "contentDigest")]
    content_digest: &'a str,
    #[serde(rename = "attachmentDigest")]
    attachment_digest: &'a str,
}

#[derive(Serialize)]
struct ReplaceDigest<'a> {
    #[serde(rename = "accountId")]
    account_id: &'a str,
    #[serde(rename = "operationId")]
    operation_id: &'a str,
    id: &'a str,
    #[serde(rename = "expectedEpoch")]
    expected_epoch: &'a str,
    #[serde(rename = "baseRevision")]
    base_revision: &'a str,
    draft: &'a RawValue,
}

#[derive(Serialize)]
struct CommentSetDigest<'a> {
    #[serde(rename = "accountId")]
    account_id: &'a str,
    #[serde(rename = "threadId")]
    thread_id: &'a str,
    #[serde(rename = "operationId")]
    operation_id: &'a str,
    #[serde(rename = "expectedGeneration")]
    expected_generation: &'a str,
    body: &'a str,
    #[serde(rename = "mentionUserIds", skip_serializing_if = "<[_]>::is_empty")]
    mention_user_ids: &'a [String],
    #[serde(rename = "replacesCommentId", skip_serializing_if = "Option::is_none")]
    replaces_comment_id: Option<&'a str>,
    #[serde(rename = "handoffUserId", skip_serializing_if = "Option::is_none")]
    handoff_user_id: Option<&'a str>,
}

fn get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        require_toggle(cx, DRAFT_TOGGLE, DRAFT_DISABLED).await?;
        let args = decode(
            cx.args(),
            "",
            &[("accountId", Kind::Str), ("ids", Kind::Strings)],
        )
        .map_err(|_| MethodError::new("invalidArguments", "invalid shared draft query"))?;
        let ids_arg = match args.strings("ids") {
            None => None,
            Some(raw_ids) => {
                if raw_ids.len() > 256 {
                    return Err(MethodError::new(
                        "invalidArguments",
                        "invalid shared draft query",
                    ));
                }
                let mut parsed = Vec::with_capacity(raw_ids.len());
                for raw in raw_ids {
                    let Some(id) = parse_uuid(raw) else {
                        return Err(MethodError::new(
                            "invalidArguments",
                            "ids must contain non-zero UUIDs",
                        ));
                    };
                    parsed.push(id);
                }
                Some(parsed)
            }
        };
        let scope = resolve(cx, args.str("accountId")).await?;
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT mail_draft_get($1,$2,$3::text[]::uuid[])::text"),
            &[(&ids_arg, Type::TEXT_ARRAY)],
        )
        .await?;
        Ok(Answer {
            name: "MailDraft/get",
            args: raw,
        })
    })
}

fn open<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        require_toggle(cx, DRAFT_TOGGLE, DRAFT_DISABLED).await?;
        let args = decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("operationId", Kind::Str),
                ("messageId", Kind::Str),
                ("receivedAt", Kind::Str),
                ("finalSenderAddress", Kind::Str),
            ],
        )?;
        let (Some(op), Some(message_id), Some(received_at)) = (
            parse_uuid(args.str("operationId")),
            parse_positive_i64(args.str("messageId")),
            parse_rfc3339(args.str("receivedAt")),
        ) else {
            return Err(MethodError::new(
                "invalidArguments",
                "operationId, messageId and receivedAt are required",
            ));
        };
        let account_raw = args.str("accountId");
        let final_sender = args.str("finalSenderAddress");
        let scope = resolve(cx, account_raw).await?;
        let digest = request_digest(&OpenDigest {
            account_id: account_raw,
            operation_id: args.str("operationId"),
            message_id: args.str("messageId"),
            received_at: args.str("receivedAt"),
            final_sender_address: final_sender,
        })?;
        let raw = write(
            cx,
            &scope,
            "mail_draft.open",
            write_sql!(
                "SELECT mail_draft_session_open($1,$2,$4::text::uuid,$5,$6::text::timestamptz,$7,$8)::text"
            ),
            &[
                (&op, Type::TEXT),
                (&message_id, Type::INT8),
                (&received_at, Type::TEXT),
                (&final_sender, Type::TEXT),
                (&digest, Type::TEXT),
            ],
        )
        .await?;
        Ok(Answer {
            name: "MailDraft/open",
            args: raw,
        })
    })
}

fn lease<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        require_toggle(cx, DRAFT_TOGGLE, DRAFT_DISABLED).await?;
        let args = decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("operationId", Kind::Str),
                ("id", Kind::Str),
                ("action", Kind::Str),
                ("expectedEpoch", Kind::Str),
                ("targetUserId", Kind::Str),
                ("reason", Kind::Str),
            ],
        )?;
        let (Some(op), Some(id), Some(epoch)) = (
            parse_uuid(args.str("operationId")),
            parse_uuid(args.str("id")),
            parse_positive_i64(args.str("expectedEpoch")),
        ) else {
            return Err(MethodError::new(
                "invalidArguments",
                "invalid shared draft lease tuple",
            ));
        };
        let target_raw = args.opt_str("targetUserId");
        let target = match target_raw {
            None => None,
            Some(raw) => {
                let Some(value) = parse_positive_i64(raw) else {
                    return Err(MethodError::new(
                        "invalidArguments",
                        "targetUserId must be a positive decimal string",
                    ));
                };
                Some(value)
            }
        };
        let account_raw = args.str("accountId");
        let action = args.str("action");
        let reason = args.str("reason");
        let scope = resolve(cx, account_raw).await?;
        let digest = request_digest(&LeaseDigest {
            account_id: account_raw,
            operation_id: args.str("operationId"),
            id: args.str("id"),
            action,
            expected_epoch: args.str("expectedEpoch"),
            target_user_id: target_raw,
            reason,
        })?;
        let raw = write(
            cx,
            &scope,
            "mail_draft.lease",
            write_sql!(
                "SELECT mail_draft_lease_action($1,$2,$4::text::uuid,$5::text::uuid,$6,$7,$8,$9,$10)::text"
            ),
            &[
                (&op, Type::TEXT),
                (&id, Type::TEXT),
                (&action, Type::TEXT),
                (&epoch, Type::INT8),
                (&target, Type::INT8),
                (&reason, Type::TEXT),
                (&digest, Type::TEXT),
            ],
        )
        .await?;
        Ok(Answer {
            name: "MailDraft/lease",
            args: raw,
        })
    })
}

fn save<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        require_toggle(cx, DRAFT_TOGGLE, DRAFT_DISABLED).await?;
        let args = decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("operationId", Kind::Str),
                ("id", Kind::Str),
                ("expectedEpoch", Kind::Str),
                ("baseRevision", Kind::Str),
                ("messageId", Kind::Str),
                ("receivedAt", Kind::Str),
                ("contentDigest", Kind::Str),
                ("attachmentDigest", Kind::Str),
            ],
        )?;
        let content_digest = args.str("contentDigest");
        let attachment_digest = args.str("attachmentDigest");
        let (Some(op), Some(id), Some(epoch), Some(revision), Some(message_id), Some(received_at)) = (
            parse_uuid(args.str("operationId")),
            parse_uuid(args.str("id")),
            parse_positive_i64(args.str("expectedEpoch")),
            parse_positive_i64(args.str("baseRevision")),
            parse_positive_i64(args.str("messageId")),
            parse_rfc3339(args.str("receivedAt")),
        ) else {
            return Err(MethodError::new(
                "invalidArguments",
                "invalid shared draft revision tuple",
            ));
        };
        if content_digest.len() != 64 || attachment_digest.len() != 64 {
            return Err(MethodError::new(
                "invalidArguments",
                "invalid shared draft revision tuple",
            ));
        }
        let account_raw = args.str("accountId");
        let scope = resolve(cx, account_raw).await?;
        let digest = request_digest(&SaveDigest {
            account_id: account_raw,
            operation_id: args.str("operationId"),
            id: args.str("id"),
            expected_epoch: args.str("expectedEpoch"),
            base_revision: args.str("baseRevision"),
            message_id: args.str("messageId"),
            received_at: args.str("receivedAt"),
            content_digest,
            attachment_digest,
        })?;
        let raw = write(
            cx,
            &scope,
            "mail_draft.save",
            write_sql!(
                "SELECT mail_draft_revision_accept($1,$2,$4::text::uuid,$5::text::uuid,$6,$7,$8,$9::text::timestamptz,$10,$11,$12)::text"
            ),
            &[
                (&op, Type::TEXT),
                (&id, Type::TEXT),
                (&epoch, Type::INT8),
                (&revision, Type::INT8),
                (&message_id, Type::INT8),
                (&received_at, Type::TEXT),
                (&content_digest, Type::TEXT),
                (&attachment_digest, Type::TEXT),
                (&digest, Type::TEXT),
            ],
        )
        .await?;
        Ok(Answer {
            name: "MailDraft/save",
            args: raw,
        })
    })
}

fn replace<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        require_toggle(cx, DRAFT_TOGGLE, DRAFT_DISABLED).await?;
        let args = decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("operationId", Kind::Str),
                ("id", Kind::Str),
                ("expectedEpoch", Kind::Str),
                ("baseRevision", Kind::Str),
                ("draft", Kind::Raw),
            ],
        )
        .map_err(|_| MethodError::new("invalidArguments", "invalid shared draft replacement"))?;
        let Some(draft_raw) = args
            .raw("draft")
            .filter(|raw| !raw.is_empty() && raw.len() <= (1 << 20))
        else {
            return Err(MethodError::new(
                "invalidArguments",
                "invalid shared draft replacement",
            ));
        };
        let (Some(op), Some(id), Some(epoch), Some(revision)) = (
            parse_uuid(args.str("operationId")),
            parse_uuid(args.str("id")),
            parse_positive_i64(args.str("expectedEpoch")),
            parse_positive_i64(args.str("baseRevision")),
        ) else {
            return Err(MethodError::new(
                "invalidArguments",
                "invalid shared draft replacement tuple",
            ));
        };
        if !matches!(
            serde_json::from_str::<Value>(draft_raw),
            Ok(Value::Object(_))
        ) {
            return Err(MethodError::new(
                "invalidArguments",
                "draft must be an object",
            ));
        }
        let account_raw = args.str("accountId");
        let scope = resolve(cx, account_raw).await?;
        let draft_raw_value =
            serde_json::from_str::<&RawValue>(draft_raw).map_err(|_| MethodError::server_fail())?;
        let digest = request_digest(&ReplaceDigest {
            account_id: account_raw,
            operation_id: args.str("operationId"),
            id: args.str("id"),
            expected_epoch: args.str("expectedEpoch"),
            base_revision: args.str("baseRevision"),
            draft: draft_raw_value,
        })?;
        let draft_json = super::go_compact(draft_raw).ok_or_else(MethodError::server_fail)?;
        let raw = write(
            cx,
            &scope,
            "mail_draft.replace",
            write_sql!(
                "SELECT mail_draft_replace($1,$2,$4::text::uuid,$5::text::uuid,$6,$7,$8::text::jsonb,$9)::text"
            ),
            &[
                (&op, Type::TEXT),
                (&id, Type::TEXT),
                (&epoch, Type::INT8),
                (&revision, Type::INT8),
                (&draft_json, Type::TEXT),
                (&digest, Type::TEXT),
            ],
        )
        .await?;
        Ok(Answer {
            name: "MailDraft/replace",
            args: raw,
        })
    })
}

fn comment_get<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        require_toggle(cx, COMMENT_TOGGLE, COMMENT_DISABLED).await?;
        let args = decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("threadId", Kind::Str),
                ("before", Kind::Str),
                ("limit", Kind::Int),
            ],
        )?;
        let limit: i32 = match args.int("limit") {
            0 => 100,
            value if (1..=100).contains(&value) => value as i32,
            _ => {
                return Err(MethodError::new("invalidArguments", "limit must be 1..100"));
            }
        };
        let before = match args.opt_str("before") {
            None => None,
            Some(raw) => {
                let Some(ts) = parse_rfc3339(raw) else {
                    return Err(MethodError::new(
                        "invalidArguments",
                        "before must be RFC3339",
                    ));
                };
                Some(ts)
            }
        };
        let thread_id = args.str("threadId");
        let scope = resolve(cx, args.str("accountId")).await?;
        let raw = read(
            cx,
            &scope,
            read_sql!("SELECT mail_comment_get($1,$2,$3,$4::text::timestamptz,$5)::text"),
            &[
                (&thread_id, Type::TEXT),
                (&before, Type::TEXT),
                (&limit, Type::INT4),
            ],
        )
        .await?;
        Ok(Answer {
            name: "MailComment/get",
            args: raw,
        })
    })
}

fn comment_set<'a>(cx: &'a Cx<'a>) -> Reply<'a> {
    Box::pin(async move {
        require_toggle(cx, COMMENT_TOGGLE, COMMENT_DISABLED).await?;
        let args = decode(
            cx.args(),
            "",
            &[
                ("accountId", Kind::Str),
                ("threadId", Kind::Str),
                ("operationId", Kind::Str),
                ("expectedGeneration", Kind::Str),
                ("body", Kind::Str),
                ("mentionUserIds", Kind::Strings),
                ("replacesCommentId", Kind::Str),
                ("handoffUserId", Kind::Str),
            ],
        )?;
        let Some(op) = parse_uuid(args.str("operationId")) else {
            return Err(MethodError::new(
                "invalidArguments",
                "operationId must be a non-zero UUID",
            ));
        };
        let Some(expected) = parse_non_negative_i64(args.str("expectedGeneration")) else {
            return Err(MethodError::new(
                "invalidArguments",
                "expectedGeneration must be a non-negative decimal string",
            ));
        };
        let mention_raw = args.strings("mentionUserIds").unwrap_or(&[]);
        if mention_raw.len() > 50 {
            return Err(MethodError::new("requestTooLarge", "too many mentions"));
        }
        let mut mentions = Vec::with_capacity(mention_raw.len());
        for raw in mention_raw {
            let Some(id) = parse_positive_i64(raw) else {
                return Err(MethodError::new(
                    "invalidArguments",
                    "mention user ids must be positive decimal strings",
                ));
            };
            mentions.push(id);
        }
        let replaces_raw = args.opt_str("replacesCommentId");
        let replaces = match replaces_raw {
            None => None,
            Some(raw) => {
                let Some(id) = parse_uuid(raw) else {
                    return Err(MethodError::new(
                        "invalidArguments",
                        "replacesCommentId must be a non-zero UUID",
                    ));
                };
                Some(id)
            }
        };
        let handoff_raw = args.opt_str("handoffUserId");
        let handoff = match handoff_raw {
            None => None,
            Some(raw) => {
                let Some(id) = parse_positive_i64(raw) else {
                    return Err(MethodError::new(
                        "invalidArguments",
                        "handoffUserId must be a positive decimal string",
                    ));
                };
                Some(id)
            }
        };
        let account_raw = args.str("accountId");
        let thread_id = args.str("threadId");
        let body = args.str("body");
        let scope = resolve(cx, account_raw).await?;
        let digest = request_digest(&CommentSetDigest {
            account_id: account_raw,
            thread_id,
            operation_id: args.str("operationId"),
            expected_generation: args.str("expectedGeneration"),
            body,
            mention_user_ids: mention_raw,
            replaces_comment_id: replaces_raw,
            handoff_user_id: handoff_raw,
        })?;
        let raw = write(
            cx,
            &scope,
            "mail_comment.set",
            write_sql!(
                "SELECT mail_comment_set($1,$2,$4,$5::text::uuid,$6,$7,$8,$9::text::uuid,$10,$11)::text"
            ),
            &[
                (&thread_id, Type::TEXT),
                (&op, Type::TEXT),
                (&expected, Type::INT8),
                (&body, Type::TEXT),
                (&mentions, Type::INT8_ARRAY),
                (&replaces, Type::TEXT),
                (&handoff, Type::INT8),
                (&digest, Type::TEXT),
            ],
        )
        .await?;
        Ok(Answer {
            name: "MailComment/set",
            args: raw,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn methods_cover_all_seven_draft_and_comment_routes() {
        assert_eq!(METHODS.len(), 7);
        let names: Vec<&str> = METHODS.iter().map(|method| method.name).collect();
        assert_eq!(
            names,
            [
                "MailDraft/get",
                "MailDraft/open",
                "MailDraft/lease",
                "MailDraft/save",
                "MailDraft/replace",
                "MailComment/get",
                "MailComment/set",
            ]
        );
        for method in METHODS {
            assert_eq!(method.capability, "urn:ietf:params:jmap:mail");
            assert_eq!(method.app, "");
            assert!(method.account);
        }
    }

    #[test]
    fn uuid_parser_matches_google_uuid_and_rejects_nil() {
        assert_eq!(
            parse_uuid("11111111-1111-4111-8111-111111111111"),
            Some("11111111-1111-4111-8111-111111111111".to_owned())
        );
        assert_eq!(
            parse_uuid("11111111111141118111111111111111"),
            Some("11111111-1111-4111-8111-111111111111".to_owned())
        );
        assert_eq!(
            parse_uuid("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"),
            Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_owned())
        );
        assert_eq!(
            parse_uuid("urn:uuid:11111111-1111-4111-8111-111111111111"),
            Some("11111111-1111-4111-8111-111111111111".to_owned())
        );
        assert_eq!(parse_uuid("00000000-0000-0000-0000-000000000000"), None);
        assert_eq!(parse_uuid("00000000000000000000000000000000"), None);
        assert_eq!(parse_uuid(""), None);
        assert_eq!(parse_uuid("not-a-uuid"), None);
        assert_eq!(parse_uuid("11111111-1111-4111-8111-11111111111g"), None);
    }

    #[test]
    fn integer_and_timestamp_parsers_match_go() {
        assert_eq!(parse_positive_i64("1"), Some(1));
        assert_eq!(parse_positive_i64("+5"), Some(5));
        assert_eq!(parse_positive_i64("0"), None);
        assert_eq!(parse_positive_i64("-1"), None);
        assert_eq!(parse_positive_i64(" 1"), None);
        assert_eq!(parse_non_negative_i64("0"), Some(0));
        assert_eq!(parse_non_negative_i64("-1"), None);

        assert!(parse_rfc3339("2026-11-01T00:00:00Z").is_some());
        assert!(parse_rfc3339("2026-11-01T00:00:00.123456Z").is_some());
        assert!(parse_rfc3339("2026-11-01T00:00:00+08:00").is_some());
        assert_eq!(parse_rfc3339("2026-11-01 00:00:00Z"), None);
        assert_eq!(parse_rfc3339("2026-11-01t00:00:00z"), None);
        assert_eq!(parse_rfc3339("not-a-time"), None);
    }

    #[test]
    fn request_digest_mirrors_go_struct_marshaling() {
        let open = request_digest(&OpenDigest {
            account_id: "100",
            operation_id: "11111111-1111-4111-8111-111111111111",
            message_id: "42",
            received_at: "2026-11-01T00:00:00Z",
            final_sender_address: "a@b.test",
        })
        .expect("open digest");
        assert_eq!(
            open,
            sha256_hex(
                br#"{"accountId":"100","operationId":"11111111-1111-4111-8111-111111111111","messageId":"42","receivedAt":"2026-11-01T00:00:00Z","finalSenderAddress":"a@b.test"}"#
            )
        );

        let lease = request_digest(&LeaseDigest {
            account_id: "100",
            operation_id: "11111111-1111-4111-8111-111111111111",
            id: "22222222-2222-4222-8222-222222222222",
            action: "renew",
            expected_epoch: "1",
            target_user_id: None,
            reason: "keep <lock>",
        })
        .expect("lease digest");
        assert_eq!(
            lease,
            sha256_hex(
                br#"{"accountId":"100","operationId":"11111111-1111-4111-8111-111111111111","id":"22222222-2222-4222-8222-222222222222","action":"renew","expectedEpoch":"1","reason":"keep \u003clock\u003e"}"#
            )
        );

        let comment_empty_mentions = request_digest(&CommentSetDigest {
            account_id: "100",
            thread_id: "thr-1",
            operation_id: "11111111-1111-4111-8111-111111111111",
            expected_generation: "0",
            body: "note & check",
            mention_user_ids: &[],
            replaces_comment_id: None,
            handoff_user_id: None,
        })
        .expect("comment digest");
        assert_eq!(
            comment_empty_mentions,
            sha256_hex(
                br#"{"accountId":"100","threadId":"thr-1","operationId":"11111111-1111-4111-8111-111111111111","expectedGeneration":"0","body":"note \u0026 check"}"#
            )
        );
    }
}
