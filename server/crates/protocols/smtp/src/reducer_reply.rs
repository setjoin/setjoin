//! Frozen Go reducererr.Classify + SMTPReply. Diagnostics remain private.
use setjoin_pg::StatementFailure;
pub const TEMPORARY: &str = "451 4.3.0 Temporary failure, please try again later\r\n";
pub fn project(error: &StatementFailure) -> &'static str {
    let kind = error
        .hint
        .as_deref()
        .and_then(|h| serde_json::from_str::<serde_json::Value>(h).ok())
        .and_then(|v| {
            v.as_object()
                .and_then(|o| o.iter().rev().find(|(k, _)| k.eq_ignore_ascii_case("type")))
                .and_then(|(_, v)| v.as_str())
                .map(str::to_owned)
        });
    match (error.sqlstate.as_deref(), kind.as_deref()) {
        (Some("BZ001"), kind) if kind != Some("over_quota") => return TEMPORARY,
        (Some("BZ081"), Some("bad_outcome")) | (Some("BZ099"), Some("last_global")) => {
            return TEMPORARY
        }
        _ => {}
    }
    match error.sqlstate.as_deref() {
        Some("BZ001" | "BZ009" | "BZ148") => "552 5.2.2 Mailbox full\r\n",
        Some("BZ004" | "BZ196") => "552 5.2.2 Sending quota exceeded\r\n",
        Some(
            "BZ002" | "BZ003" | "BZ005" | "BZ015" | "BZ045" | "BZ052" | "BZ061" | "BZ065" | "BZ066"
            | "BZ069" | "BZ071" | "BZ107" | "BZ116" | "BZ140" | "BZ161" | "BZ163" | "BZ164"
            | "BZ166" | "BZ167" | "BZ171" | "BZ173" | "BZ175" | "BZ176" | "BZ186" | "BZ187"
            | "BZ194" | "BZ199" | "BZ203" | "BZ204" | "BZ211" | "BZ213" | "BZ215" | "BZ216"
            | "BZ219" | "BZ217" | "BZ218" | "BZ223" | "BZ220" | "BZ236" | "BZ239" | "BZ244"
            | "BZ250" | "BZ253" | "BZ258" | "BZ273" | "BZ277" | "BZ284" | "BZ307" | "BZ308"
            | "BZ311" | "BZ314" | "BZ323",
        ) => "550 5.7.1 Message rejected by policy\r\n",
        Some(
            "BZ007" | "BZ019" | "BZ020" | "BZ021" | "BZ030" | "BZ033" | "BZ038" | "BZ042" | "BZ049"
            | "BZ051" | "BZ053" | "BZ060" | "BZ074" | "BZ084" | "BZ086" | "BZ091" | "BZ099"
            | "BZ101" | "BZ103" | "BZ112" | "BZ113" | "BZ114" | "BZ118" | "BZ121" | "BZ081"
            | "BZ125" | "BZ130" | "BZ132" | "BZ134" | "BZ139" | "BZ169" | "BZ170" | "BZ185"
            | "BZ268" | "BZ270" | "BZ272" | "BZ300" | "BZ302" | "BZ310" | "BZ317" | "BZ321",
        ) => "550 5.1.1 Recipient address rejected: no such user\r\n",
        _ => TEMPORARY,
    }
}

/// Submission's `classifyReducerReply` adapter: a recognized class keeps its
/// reply, but an unrecognized (non-BZ or unmapped) error is the generic
/// `554 5.3.0 Failed to send message`, never the inbound transient default.
pub fn submission(error: &StatementFailure) -> String {
    let reply = project(error);
    let transient = reply == TEMPORARY;
    let recognized_transient = error.sqlstate.as_deref() == Some("BZ008");
    if transient && !recognized_transient {
        "554 5.3.0 Failed to send message\r\n".into()
    } else {
        reply.into()
    }
}
