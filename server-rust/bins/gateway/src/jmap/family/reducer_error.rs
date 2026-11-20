//! Go `mapReducerErr` (mailserver/internal/jmap/reducer_error.go:50) over
//! `shared/reducererr`: `Classify` (projection.go:82), `JMAPError`
//! (projection.go:149) and `Detail` (detail.go). An unclassified failure is
//! `serverFail` / `database error`, exactly Go's default arm.
use serde_json::Value;
use setjoin_pg::StatementFailure;

use super::MethodError;

/// Go's `ReplyClass`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    Unknown,
    OverQuota,
    SendQuota,
    Forbidden,
    NotFound,
    AccountNotFound,
    CannotCalc,
    Transient,
    InvalidArguments,
    Conflict,
    StateMismatch,
    Unprocessable,
}

use Class::{
    AccountNotFound, CannotCalc, Conflict, Forbidden, InvalidArguments, NotFound, OverQuota,
    SendQuota, StateMismatch, Transient, Unprocessable,
};

/// Frozen `codeClass` (shared/reducererr/reducererr.go:75-465), Go row order,
/// `Err*` constants resolved (reducererr.go:40-74).
const CODE_CLASS: &[(&str, Class)] = &[
    ("BZ001", OverQuota),
    ("BZ009", OverQuota),
    ("BZ004", SendQuota),
    ("BZ002", Forbidden),
    ("BZ003", Forbidden),
    ("BZ005", Forbidden),
    ("BZ015", Forbidden),
    ("BZ045", Forbidden),
    ("BZ052", Forbidden),
    ("BZ061", Forbidden),
    ("BZ065", Forbidden),
    ("BZ066", Forbidden),
    ("BZ069", Forbidden),
    ("BZ071", Forbidden),
    ("BZ107", Forbidden),
    ("BZ116", Forbidden),
    ("BZ006", AccountNotFound),
    ("BZ007", NotFound),
    ("BZ019", NotFound),
    ("BZ020", NotFound),
    ("BZ021", NotFound),
    ("BZ030", NotFound),
    ("BZ033", NotFound),
    ("BZ038", NotFound),
    ("BZ042", NotFound),
    ("BZ049", NotFound),
    ("BZ051", NotFound),
    ("BZ053", NotFound),
    ("BZ060", NotFound),
    ("BZ074", NotFound),
    ("BZ084", NotFound),
    ("BZ086", NotFound),
    ("BZ091", NotFound),
    ("BZ099", NotFound),
    ("BZ101", NotFound),
    ("BZ103", NotFound),
    ("BZ112", NotFound),
    ("BZ113", NotFound),
    ("BZ114", NotFound),
    ("BZ118", NotFound),
    ("BZ121", NotFound),
    ("BZ081", NotFound),
    ("BZ125", NotFound),
    ("BZ130", NotFound),
    ("BZ132", NotFound),
    ("BZ134", NotFound),
    ("BZ040", InvalidArguments),
    ("BZ041", InvalidArguments),
    ("BZ043", InvalidArguments),
    ("BZ085", InvalidArguments),
    ("BZ104", InvalidArguments),
    ("BZ031", InvalidArguments),
    ("BZ036", InvalidArguments),
    ("BZ037", InvalidArguments),
    ("BZ039", InvalidArguments),
    ("BZ044", InvalidArguments),
    ("BZ046", InvalidArguments),
    ("BZ047", InvalidArguments),
    ("BZ119", InvalidArguments),
    ("BZ050", InvalidArguments),
    ("BZ055", InvalidArguments),
    ("BZ056", InvalidArguments),
    ("BZ057", InvalidArguments),
    ("BZ070", InvalidArguments),
    ("BZ072", InvalidArguments),
    ("BZ076", InvalidArguments),
    ("BZ078", InvalidArguments),
    ("BZ082", InvalidArguments),
    ("BZ094", InvalidArguments),
    ("BZ097", InvalidArguments),
    ("BZ098", InvalidArguments),
    ("BZ105", InvalidArguments),
    ("BZ115", InvalidArguments),
    ("BZ117", InvalidArguments),
    ("BZ120", InvalidArguments),
    ("BZ122", InvalidArguments),
    ("BZ123", InvalidArguments),
    ("BZ124", InvalidArguments),
    ("BZ126", InvalidArguments),
    ("BZ131", InvalidArguments),
    ("BZ133", InvalidArguments),
    ("BZ135", InvalidArguments),
    ("BZ022", Conflict),
    ("BZ048", Conflict),
    ("BZ054", Conflict),
    ("BZ062", Conflict),
    ("BZ063", Conflict),
    ("BZ064", Conflict),
    ("BZ075", Conflict),
    ("BZ077", Conflict),
    ("BZ080", Conflict),
    ("BZ087", Conflict),
    ("BZ093", Conflict),
    ("BZ095", Conflict),
    ("BZ100", Conflict),
    ("BZ102", Conflict),
    ("BZ106", Conflict),
    ("BZ108", Conflict),
    ("BZ110", Conflict),
    ("BZ111", Conflict),
    ("BZ136", Conflict),
    ("BZ137", Conflict),
    ("BZ088", Unprocessable),
    ("BZ090", Unprocessable),
    ("BZ092", Unprocessable),
    ("BZ109", Unprocessable),
    ("BZ139", NotFound),
    ("BZ140", Forbidden),
    ("BZ141", Unprocessable),
    ("BZ142", Conflict),
    ("BZ143", Conflict),
    ("BZ144", Unprocessable),
    ("BZ145", Conflict),
    ("BZ146", Conflict),
    ("BZ147", Conflict),
    ("BZ148", OverQuota),
    ("BZ149", Conflict),
    ("BZ150", Conflict),
    ("BZ160", InvalidArguments),
    ("BZ161", Forbidden),
    ("BZ162", Unprocessable),
    ("BZ163", Forbidden),
    ("BZ164", Forbidden),
    ("BZ165", Unprocessable),
    ("BZ166", Forbidden),
    ("BZ167", Forbidden),
    ("BZ168", Unprocessable),
    ("BZ169", NotFound),
    ("BZ170", NotFound),
    ("BZ171", Forbidden),
    ("BZ172", InvalidArguments),
    ("BZ173", Forbidden),
    ("BZ175", Forbidden),
    ("BZ178", Unprocessable),
    ("BZ176", Forbidden),
    ("BZ177", Unprocessable),
    ("BZ179", Unprocessable),
    ("BZ185", NotFound),
    ("BZ186", Forbidden),
    ("BZ187", Forbidden),
    ("BZ188", Unprocessable),
    ("BZ189", Unprocessable),
    ("BZ190", Conflict),
    ("BZ191", Unprocessable),
    ("BZ192", Conflict),
    ("BZ193", Conflict),
    ("BZ194", Forbidden),
    ("BZ195", Unprocessable),
    ("BZ196", SendQuota),
    ("BZ197", Unprocessable),
    ("BZ198", Conflict),
    ("BZ199", Forbidden),
    ("BZ200", Conflict),
    ("BZ201", Unprocessable),
    ("BZ202", Conflict),
    ("BZ203", Forbidden),
    ("BZ204", Forbidden),
    ("BZ206", Unprocessable),
    ("BZ205", Conflict),
    ("BZ207", InvalidArguments),
    ("BZ208", Conflict),
    ("BZ209", Unprocessable),
    ("BZ210", Unprocessable),
    ("BZ211", Forbidden),
    ("BZ212", Unprocessable),
    ("BZ213", Forbidden),
    ("BZ215", Forbidden),
    ("BZ216", Forbidden),
    ("BZ219", Forbidden),
    ("BZ221", Conflict),
    ("BZ217", Forbidden),
    ("BZ218", Forbidden),
    ("BZ222", InvalidArguments),
    ("BZ223", Forbidden),
    ("BZ220", Forbidden),
    ("BZ224", Unprocessable),
    ("BZ225", Conflict),
    ("BZ226", Conflict),
    ("BZ227", Conflict),
    ("BZ228", InvalidArguments),
    ("BZ229", Conflict),
    ("BZ230", Conflict),
    ("BZ231", Unprocessable),
    ("BZ232", Conflict),
    ("BZ233", Conflict),
    ("BZ234", Conflict),
    ("BZ235", Conflict),
    ("BZ236", Forbidden),
    ("BZ237", Conflict),
    ("BZ238", Conflict),
    ("BZ239", Forbidden),
    ("BZ240", Conflict),
    ("BZ241", InvalidArguments),
    ("BZ242", Conflict),
    ("BZ243", Conflict),
    ("BZ244", Forbidden),
    ("BZ245", Unprocessable),
    ("BZ246", Conflict),
    ("BZ247", Conflict),
    ("BZ248", Conflict),
    ("BZ249", Conflict),
    ("BZ250", Forbidden),
    ("BZ251", InvalidArguments),
    ("BZ252", InvalidArguments),
    ("BZ253", Forbidden),
    ("BZ254", Conflict),
    ("BZ255", Conflict),
    ("BZ256", Conflict),
    ("BZ257", InvalidArguments),
    ("BZ258", Forbidden),
    ("BZ259", Conflict),
    ("BZ260", Conflict),
    ("BZ261", InvalidArguments),
    ("BZ262", Conflict),
    ("BZ263", Conflict),
    ("BZ264", Conflict),
    ("BZ265", InvalidArguments),
    ("BZ266", Conflict),
    ("BZ267", Conflict),
    ("BZ268", NotFound),
    ("BZ269", InvalidArguments),
    ("BZ285", InvalidArguments),
    ("BZ270", NotFound),
    ("BZ271", InvalidArguments),
    ("BZ272", NotFound),
    ("BZ273", Forbidden),
    ("BZ274", Conflict),
    ("BZ275", Conflict),
    ("BZ276", Unprocessable),
    ("BZ277", Forbidden),
    ("BZ278", Conflict),
    ("BZ279", Conflict),
    ("BZ280", Conflict),
    ("BZ281", Unprocessable),
    ("BZ282", Conflict),
    ("BZ283", Unprocessable),
    ("BZ284", Forbidden),
    ("BZ300", NotFound),
    ("BZ301", InvalidArguments),
    ("BZ302", NotFound),
    ("BZ303", StateMismatch),
    ("BZ304", StateMismatch),
    ("BZ305", Conflict),
    ("BZ306", Conflict),
    ("BZ307", Forbidden),
    ("BZ308", Forbidden),
    ("BZ309", StateMismatch),
    ("BZ310", NotFound),
    ("BZ311", Forbidden),
    ("BZ312", Conflict),
    ("BZ313", Conflict),
    ("BZ314", Forbidden),
    ("BZ315", Conflict),
    ("BZ316", InvalidArguments),
    ("BZ317", NotFound),
    ("BZ318", Conflict),
    ("BZ319", Conflict),
    ("BZ320", Unprocessable),
    ("BZ321", NotFound),
    ("BZ322", InvalidArguments),
    ("BZ323", Forbidden),
    ("BZ324", StateMismatch),
    ("BZ325", Conflict),
    ("BZ326", StateMismatch),
    ("BZ327", Conflict),
    ("BZ328", Conflict),
    ("BZ329", StateMismatch),
    ("BZ011", CannotCalc),
    ("BZ008", Transient),
];

/// `detailPass` with `passMessage` (detail.go).
const PASS_MESSAGE: &[&str] = &[
    "BZ040", "BZ041", "BZ043", "BZ060", "BZ061", "BZ062", "BZ063", "BZ069", "BZ064", "BZ065",
    "BZ066", "BZ100", "BZ104", "BZ105", "BZ106", "BZ107", "BZ108", "BZ109", "BZ110", "BZ115",
    "BZ116", "BZ117", "BZ122", "BZ123", "BZ124", "BZ126", "BZ131", "BZ133",
];

/// `detailPass` with `passHint` (detail.go).
const PASS_HINT: &[&str] = &[
    "BZ080", "BZ081", "BZ082", "BZ085", "BZ086", "BZ087", "BZ088", "BZ090", "BZ091", "BZ092",
    "BZ093", "BZ094", "BZ095", "BZ097", "BZ098", "BZ102",
];

/// `detailFixed` (detail.go), constants resolved.
const FIXED: &[(&str, &str)] = &[
    ("BZ001", "over quota"),
    ("BZ009", "over quota"),
    ("BZ004", "sending quota exceeded"),
    ("BZ002", "access denied"),
    ("BZ003", "not authorized to send from this address"),
    ("BZ005", "message blocked by policy"),
    ("BZ006", "accountId does not match an existing account"),
    ("BZ007", "recipient not found"),
    ("BZ011", "client must resync (sinceState too old)"),
    ("BZ038", "reminder not found"),
    ("BZ039", "snooze time must be in the future"),
    ("BZ042", "quick step not found"),
    ("BZ045", "contact group not owned by caller"),
];

/// Go `ParseReducerError` for the dual-use codes: the HINT `type` slug, the
/// code when the HINT is empty or has no type, `None` when the HINT is not a
/// well-typed `ReducerError` object (Go then treats the error as unknown).
fn slug(failure: &StatementFailure, code: &str) -> Option<String> {
    let hint = match failure.hint.as_deref() {
        None | Some("") => return Some(code.to_owned()),
        Some(hint) => hint,
    };
    let object = match serde_json::from_str::<Value>(hint).ok()? {
        Value::Null => return Some(code.to_owned()),
        Value::Object(object) => object,
        _ => return None,
    };
    let fold = crate::guests_input::fold;
    let mut kind = String::new();
    for (key, value) in &object {
        let key = fold(key);
        let is = |name: &str| key == fold(name);
        if is("type") || is("from_addr") || is("reason") || is("remediation") {
            match value {
                Value::Null => {}
                Value::String(text) => {
                    if is("type") {
                        kind = text.clone();
                    }
                }
                _ => return None,
            }
        } else if is("mailbox_id") || is("user_id") || is("domain_id") || is("policy_id") {
            match value {
                Value::Null => {}
                Value::Number(number) if number.as_i64().is_some() => {}
                _ => return None,
            }
        }
    }
    Some(if kind.is_empty() {
        code.to_owned()
    } else {
        kind
    })
}

/// Go `Classify` (projection.go:82).
pub(crate) fn classify(failure: &StatementFailure) -> Class {
    let Some(code) = failure.sqlstate.as_deref() else {
        return Class::Unknown;
    };
    let slug_is = |expected: &str| slug(failure, code).as_deref() == Some(expected);
    match code {
        "BZ001" => {
            if slug_is("over_quota") {
                OverQuota
            } else {
                Class::Unknown
            }
        }
        "BZ081" => {
            if slug_is("bad_outcome") {
                InvalidArguments
            } else {
                NotFound
            }
        }
        "BZ099" => {
            if slug_is("last_global") {
                Conflict
            } else {
                NotFound
            }
        }
        _ => CODE_CLASS
            .iter()
            .find(|(candidate, _)| *candidate == code)
            .map_or(Class::Unknown, |(_, class)| *class),
    }
}

/// Go `ReplyClass.JMAPError` (projection.go:149).
fn jmap_type(class: Class) -> Option<&'static str> {
    match class {
        OverQuota | SendQuota => Some("overQuota"),
        Forbidden => Some("forbidden"),
        NotFound => Some("notFound"),
        AccountNotFound => Some("accountNotFound"),
        CannotCalc => Some("cannotCalculateChanges"),
        InvalidArguments => Some("invalidArguments"),
        StateMismatch => Some("stateMismatch"),
        Class::Unknown | Transient | Conflict | Unprocessable => None,
    }
}

/// Go `ReplyClass.detailFallback` (detail.go).
fn fallback(class: Class) -> &'static str {
    match class {
        OverQuota | SendQuota => "overQuota",
        Forbidden => "forbidden",
        NotFound => "notFound",
        AccountNotFound => "accountNotFound",
        CannotCalc => "cannotCalculateChanges",
        InvalidArguments => "invalidArguments",
        Conflict => "conflict",
        StateMismatch => "stateMismatch",
        Unprocessable => "unprocessable",
        Class::Unknown | Transient => "request failed",
    }
}

/// Go `Detail` (detail.go).
fn detail(failure: &StatementFailure, class: Class) -> String {
    if matches!(class, Class::Unknown | Transient) {
        return "request failed".to_owned();
    }
    let code = failure.sqlstate.as_deref().unwrap_or("");
    if code == "BZ081" && class == InvalidArguments {
        return fallback(class).to_owned();
    }
    if code == "BZ099" {
        return if class == Conflict && !failure.message.is_empty() {
            failure.message.clone()
        } else {
            "policy not found".to_owned()
        };
    }
    let hint_mode = PASS_HINT.contains(&code);
    if hint_mode || PASS_MESSAGE.contains(&code) {
        if hint_mode {
            if let Some(hint) = failure.hint.as_deref().filter(|hint| !hint.is_empty()) {
                return hint.to_owned();
            }
        }
        if !failure.message.is_empty() {
            return failure.message.clone();
        }
    }
    if let Some((_, fixed)) = FIXED.iter().find(|(candidate, _)| *candidate == code) {
        return (*fixed).to_owned();
    }
    fallback(class).to_owned()
}

/// Go `mapReducerErr`.
pub(crate) fn project(failure: &StatementFailure) -> MethodError {
    let class = classify(failure);
    match jmap_type(class) {
        Some(kind) => MethodError::new(kind, &detail(failure, class)),
        None => MethodError::server_fail(),
    }
}

/// Go `calendarA3Error` (calendar_a3.go:30): any BZ001 is `forbidden`.
pub(crate) fn project_calendar(failure: &StatementFailure) -> MethodError {
    if failure.sqlstate.as_deref() == Some("BZ001") {
        MethodError::new("forbidden", "not authorized for this calendar")
    } else {
        project(failure)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use regex::Regex;

    use super::*;

    // Drift tests against frozen Go; delete with Go (#142).
    const REDUCERERR: &str = include_str!("../../../../../../shared/reducererr/reducererr.go");
    const DETAIL: &str = include_str!("../../../../../../shared/reducererr/detail.go");
    const PROJECTION: &str = include_str!("../../../../../../shared/reducererr/projection.go");

    const ALL: [Class; 12] = [
        Class::Unknown,
        OverQuota,
        SendQuota,
        Forbidden,
        NotFound,
        AccountNotFound,
        CannotCalc,
        Transient,
        InvalidArguments,
        Conflict,
        StateMismatch,
        Unprocessable,
    ];

    fn failure(code: Option<&str>, message: &str, hint: Option<&str>) -> StatementFailure {
        StatementFailure {
            sqlstate: code.map(str::to_owned),
            message: message.to_owned(),
            hint: hint.map(str::to_owned),
        }
    }

    fn block<'a>(source: &'a str, header: &str) -> &'a str {
        let start = source
            .find(header)
            .unwrap_or_else(|| panic!("{header} not found"));
        let body = &source[start + header.len()..];
        &body[..body.find("\n}").expect("block end")]
    }

    fn constants() -> BTreeMap<String, String> {
        Regex::new(r#"(?m)^\s*(Err[A-Za-z0-9]+)\s*=\s*"(BZ[0-9]+)""#)
            .expect("constant pattern")
            .captures_iter(REDUCERERR)
            .map(|c| (c[1].to_owned(), c[2].to_owned()))
            .collect()
    }

    fn code(raw: &str, constants: &BTreeMap<String, String>) -> String {
        if raw.starts_with('"') {
            raw.trim_matches('"').to_owned()
        } else {
            constants
                .get(raw)
                .unwrap_or_else(|| panic!("unknown constant {raw}"))
                .clone()
        }
    }

    /// `case ClassX, ClassY:` / `default:` followed by `return "…"` in one switch.
    fn switch_returns(source: &str, header: &str) -> (BTreeMap<String, String>, String) {
        let mut map = BTreeMap::new();
        let mut default = String::new();
        let mut current: Vec<String> = Vec::new();
        for line in block(source, header).lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("case ") {
                current = rest
                    .trim_end_matches(':')
                    .split(',')
                    .map(|name| name.trim().trim_start_matches("Class").to_owned())
                    .collect();
            } else if line.starts_with("default") {
                current = vec!["<default>".to_owned()];
            } else if let Some(rest) = line.strip_prefix("return \"") {
                let value = rest.split('"').next().unwrap_or("").to_owned();
                for name in &current {
                    if name == "<default>" {
                        default = value.clone();
                    } else {
                        map.insert(name.clone(), value.clone());
                    }
                }
            }
        }
        (map, default)
    }

    #[test]
    fn code_class_matches_frozen_go() {
        let constants = constants();
        let rows = Regex::new(r#"(?m)^\s*(Err[A-Za-z0-9]+|"BZ[0-9]+")\s*:\s*Class([A-Za-z]+),"#)
            .expect("row pattern");
        let go: BTreeMap<String, String> = rows
            .captures_iter(block(REDUCERERR, "var codeClass = map[string]ReplyClass{"))
            .map(|c| (code(&c[1], &constants), c[2].to_owned()))
            .collect();
        let rust: BTreeMap<String, String> = CODE_CLASS
            .iter()
            .map(|(code, class)| ((*code).to_owned(), format!("{class:?}")))
            .collect();
        assert_eq!(CODE_CLASS.len(), rust.len(), "duplicate code in CODE_CLASS");
        assert_eq!(rust, go);
    }

    #[test]
    fn detail_tables_match_frozen_go() {
        let constants = constants();
        let pass = Regex::new(r#""(BZ[0-9]+)":\s*pass(Message|Hint)"#).expect("pass pattern");
        let mut message = BTreeSet::new();
        let mut hint = BTreeSet::new();
        for c in pass.captures_iter(block(DETAIL, "var detailPass = map[string]passMode{")) {
            if &c[2] == "Message" {
                message.insert(c[1].to_owned());
            } else {
                hint.insert(c[1].to_owned());
            }
        }
        let rust_message: BTreeSet<String> = PASS_MESSAGE.iter().map(|c| (*c).to_owned()).collect();
        let rust_hint: BTreeSet<String> = PASS_HINT.iter().map(|c| (*c).to_owned()).collect();
        assert_eq!(rust_message, message);
        assert_eq!(rust_hint, hint);
        let fixed = Regex::new(r#"(?m)^\s*(Err[A-Za-z0-9]+|"BZ[0-9]+")\s*:\s*"([^"]*)""#)
            .expect("fixed pattern");
        let go: BTreeMap<String, String> = fixed
            .captures_iter(block(DETAIL, "var detailFixed = map[string]string{"))
            .map(|c| (code(&c[1], &constants), c[2].to_owned()))
            .collect();
        let rust: BTreeMap<String, String> = FIXED
            .iter()
            .map(|(code, text)| ((*code).to_owned(), (*text).to_owned()))
            .collect();
        assert_eq!(rust, go);
        for code in ["BZ114", "BZ121", "BZ125"] {
            assert!(
                !PASS_MESSAGE.contains(&code) && !PASS_HINT.contains(&code),
                "{code} must stay off the pass lists (no ownership oracle)"
            );
        }
        let (fallbacks, default) =
            switch_returns(DETAIL, "func (c ReplyClass) detailFallback() string {");
        for class in ALL {
            let name = format!("{class:?}");
            let expected = fallbacks
                .get(&name)
                .cloned()
                .unwrap_or_else(|| default.clone());
            assert_eq!(fallback(class), expected, "{name}");
        }
    }

    #[test]
    fn jmap_projection_matches_frozen_go() {
        let (types, default) =
            switch_returns(PROJECTION, "func (c ReplyClass) JMAPError() string {");
        for class in ALL {
            let name = format!("{class:?}");
            let expected = types.get(&name).cloned().unwrap_or_else(|| default.clone());
            assert_eq!(jmap_type(class).unwrap_or(""), expected, "{name}");
        }
    }

    #[test]
    fn projections_follow_go() {
        let cases = [
            (
                failure(Some("BZ038"), "Reminder not found", None),
                ("notFound", "reminder not found"),
            ),
            (
                failure(Some("BZ039"), "x", None),
                ("invalidArguments", "snooze time must be in the future"),
            ),
            (
                failure(Some("22007"), "bad time", None),
                ("serverFail", "database error"),
            ),
            (
                failure(None, "pool", None),
                ("serverFail", "database error"),
            ),
            (
                failure(Some("BZ001"), "x", Some(r#"{"type":"acl_forbidden"}"#)),
                ("serverFail", "database error"),
            ),
            (
                failure(Some("BZ001"), "x", Some(r#"{"type":"over_quota"}"#)),
                ("overQuota", "over quota"),
            ),
            (
                failure(Some("BZ001"), "x", Some("{")),
                ("serverFail", "database error"),
            ),
            (
                failure(Some("BZ040"), "name is required", None),
                ("invalidArguments", "name is required"),
            ),
            (
                failure(Some("BZ080"), "message", Some("actionable hint")),
                ("serverFail", "database error"),
            ),
            (
                failure(Some("BZ081"), "x", Some(r#"{"type":"bad_outcome"}"#)),
                ("invalidArguments", "invalidArguments"),
            ),
            // Go detailPass[BZ081] = passHint: no hint falls through to the message.
            (failure(Some("BZ081"), "x", None), ("notFound", "x")),
            (
                failure(Some("BZ099"), "last", Some(r#"{"type":"last_global"}"#)),
                ("serverFail", "database error"),
            ),
            (
                failure(Some("BZ099"), "x", None),
                ("notFound", "policy not found"),
            ),
            (
                failure(Some("BZ006"), "x", None),
                (
                    "accountNotFound",
                    "accountId does not match an existing account",
                ),
            ),
            (
                failure(Some("BZ011"), "x", None),
                (
                    "cannotCalculateChanges",
                    "client must resync (sinceState too old)",
                ),
            ),
            (
                failure(Some("BZ114"), "owner leak", None),
                ("notFound", "notFound"),
            ),
            (
                failure(Some("BZ008"), "x", None),
                ("serverFail", "database error"),
            ),
            (
                failure(Some("BZ303"), "x", None),
                ("stateMismatch", "stateMismatch"),
            ),
        ];
        for (input, (kind, text)) in cases {
            assert_eq!(project(&input), MethodError::new(kind, text), "{input:?}");
        }
        assert!(project(&failure(Some("BZ038"), "x", None))
            .json()
            .contains("\"status\":500"));
        assert_eq!(
            project_calendar(&failure(Some("BZ001"), "x", None)),
            MethodError::new("forbidden", "not authorized for this calendar")
        );
        assert_eq!(
            project_calendar(&failure(Some("BZ002"), "x", None)),
            MethodError::new("forbidden", "access denied")
        );
    }
}
