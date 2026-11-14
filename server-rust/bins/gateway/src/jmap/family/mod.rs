//! Per-family native JMAP methods (#369-#377): frozen Go `registerMethods`
//! rows (pinned by mailserver/internal/jmap/testdata/methods.golden) and their
//! Rust handlers. Each family owns one stub file exporting `METHODS`; a listed,
//! ready method is claimed for every well-formed single call, which also makes
//! `ws_request::needs_go` false for it, and is then answered here in Go's
//! `dispatchInvocation` order. Database and identity access exists only
//! through [`seam`], which `seam::tests::family_files_use_only_the_seam` guards.
// The scaffold ships every helper before the family PRs (#369-#377) use them.
#![allow(dead_code, unused_imports, unused_macros)]

use std::future::Future;
use std::pin::Pin;

use serde_json::value::RawValue;
use serde_json::Value;

pub(crate) mod args;
pub(crate) mod reducer_error;
pub(crate) mod seam;

mod address_book;
mod calendar;
mod calendar_delegate;
mod calendar_event;
mod contact_card;
mod continuity;
mod mail_draft;
mod mail_work;
mod reminder;
mod task;
mod task_list;
mod vendor_mail;

pub(crate) use crate::jmap::get::parse_id;
pub use seam::ContinuitySigner;
pub(crate) use seam::Cx;

/// Every family's registry rows. Names are unique across families.
const REGISTRY: &[&[Method]] = &[
    address_book::METHODS,
    calendar::METHODS,
    calendar_delegate::METHODS,
    calendar_event::METHODS,
    contact_card::METHODS,
    continuity::METHODS,
    mail_draft::METHODS,
    mail_work::METHODS,
    reminder::METHODS,
    task::METHODS,
    task_list::METHODS,
    vendor_mail::METHODS,
];

/// The family files, in REGISTRY order; the source guard scans exactly these.
pub(crate) const FAMILY_FILES: &[&str] = &[
    "address_book.rs",
    "calendar.rs",
    "calendar_delegate.rs",
    "calendar_event.rs",
    "contact_card.rs",
    "continuity.rs",
    "mail_draft.rs",
    "mail_work.rs",
    "reminder.rs",
    "task.rs",
    "task_list.rs",
    "vendor_mail.rs",
];

/// Largest argument object claimed (Go and ws_request's per-call limit).
const MAX_ARGS: usize = 2_000_000;

/// Go's `gateClass` for a delegated (shared-mailbox) `accountId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Gate {
    /// `reg`: primary account only.
    Personal,
    Read,
    Mutate,
    Submit,
    Collaborate,
}

impl Gate {
    /// Go's `gateClass.allows` (handler.go:242).
    pub(crate) fn allows(self, grants: &[String]) -> bool {
        grants.iter().any(|grant| match self {
            Gate::Personal => false,
            Gate::Read => matches!(
                grant.as_str(),
                "read" | "send_as" | "send_on_behalf" | "full_access"
            ),
            Gate::Mutate => grant == "full_access",
            Gate::Submit | Gate::Collaborate => {
                matches!(grant.as_str(), "send_as" | "send_on_behalf" | "full_access")
            }
        })
    }

    /// methods.golden's gate column.
    pub(crate) fn word(self) -> &'static str {
        match self {
            Gate::Personal => "personal",
            Gate::Read => "read",
            Gate::Mutate => "mutate",
            Gate::Submit => "submit",
            Gate::Collaborate => "collaborate",
        }
    }
}

/// A method response: Go's `(name, json.RawMessage)`.
pub(crate) struct Answer {
    pub name: &'static str,
    /// Raw JSON, compacted on output like Go's `json.RawMessage`.
    pub args: String,
}

/// Go's `jmap.Error`: the error type without its URN prefix, plus the detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MethodError {
    pub kind: String,
    pub detail: String,
}

impl MethodError {
    pub(crate) fn new(kind: &str, detail: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            detail: detail.to_owned(),
        }
    }

    /// Go's default `mapReducerErr` arm.
    pub(crate) fn server_fail() -> Self {
        Self::new("serverFail", "database error")
    }

    /// Go's `Error.MarshalJSON`.
    pub(crate) fn json(&self) -> String {
        crate::problem::jmap(error_status(&self.kind), &self.kind, &self.detail)
    }
}

pub(crate) type Handled = Result<Answer, MethodError>;
pub(crate) type Reply<'a> = Pin<Box<dyn Future<Output = Handled> + Send + 'a>>;

/// One frozen Go registry row with its Rust handler.
pub(crate) struct Method {
    pub name: &'static str,
    pub capability: &'static str,
    /// Go's registry `app` (entitlement gate); "" for none.
    pub app: &'static str,
    pub gate: Gate,
    /// Go calls `parseAccountID` (false: user-keyed worker handlers, task_lists.go:16-18).
    pub account: bool,
    /// Writes, bumps state or notifies (adequacy: repeat + row goldens).
    pub mutator: bool,
    /// Takes sinceState/ifInState/lease/revision (adequacy: state-mismatch).
    pub state: bool,
    /// Byte-independent readiness; `false` leaves the method to Go on both transports.
    pub ready: fn(Ready) -> bool,
    pub run: for<'a> fn(&'a Cx<'a>) -> Reply<'a>,
}

/// What readiness may depend on: never an executor, credential or key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Ready {
    /// The continuity signer and boot epoch are loaded.
    pub continuity: bool,
}

impl Ready {
    fn of(services: Option<&crate::jmap::JmapServices>) -> Self {
        Self {
            continuity: services
                .is_some_and(|s| s.continuity_signer.is_some() && s.continuity_boot.is_some()),
        }
    }
}

pub(crate) fn always(_: Ready) -> bool {
    true
}

/// A single call to a registered family method.
pub(crate) struct Request {
    pub method: &'static Method,
    pub args: String,
    pub client_id: String,
}

fn registered() -> impl Iterator<Item = &'static Method> {
    REGISTRY.iter().flat_map(|family| family.iter())
}

pub(crate) fn find(name: &str) -> Option<&'static Method> {
    registered().find(|method| method.name == name)
}

/// `Some` only for `{"using":[..],"methodCalls":[[name,args,id]]}` naming a
/// registered, ready family method whose capability `using` declares, with
/// args that are JSON (`null`, an object without result references, or any
/// other value `serve` rejects) of at most 2 MB and depth 128. Go resolves
/// `#key` references before dispatch (resultref.go:41-81), so those stay Go's.
pub(crate) fn classify(
    body: &[u8],
    services: Option<&crate::jmap::JmapServices>,
) -> Option<Request> {
    classify_with(body, services, find)
}

fn classify_with(
    body: &[u8],
    services: Option<&crate::jmap::JmapServices>,
    find: impl Fn(&str) -> Option<&'static Method>,
) -> Option<Request> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        using: Vec<String>,
        #[serde(rename = "methodCalls")]
        calls: Vec<(String, Box<RawValue>, String)>,
    }
    let body: Body = serde_json::from_slice(body).ok()?;
    let [(name, args, client_id)] = body.calls.as_slice() else {
        return None;
    };
    let method = find(name.as_str())?;
    if !body.using.iter().any(|c| c == method.capability) || !(method.ready)(Ready::of(services)) {
        return None;
    }
    let raw = args.get();
    if raw.len() > MAX_ARGS {
        return None;
    }
    if let Value::Object(map) = serde_json::from_str::<Value>(raw).ok()? {
        if map.keys().any(|key| key.starts_with('#')) {
            return None;
        }
    }
    Some(Request {
        method,
        args: raw.to_owned(),
        client_id: client_id.clone(),
    })
}

/// Go's `errorStatus` (handler.go:125).
pub(crate) fn error_status(kind: &str) -> u16 {
    match kind {
        "invalidArguments"
        | "invalidPatch"
        | "invalidProperties"
        | "notJSON"
        | "notRequest"
        | "unknownMethod"
        | "unknownCapability"
        | "invalidResultReference" => 400,
        "accountNotFound"
        | "accountNotSupportedByMethod"
        | "anchorNotFound"
        | "blobNotFound"
        | "calendarEventNotFound"
        | "emailNotFound"
        | "mailboxNotFound"
        | "stateMismatch"
        | "singleton"
        | "cannotCalculateChanges"
        | "requestTooLarge" => 400,
        "accountReadOnly" => 403,
        "tooLarge" => 413,
        "rateLimit" => 429,
        _ => 500,
    }
}

/// Go's `json.RawMessage` output: compacted, HTML-escaped strings.
pub(crate) fn go_compact(raw: &str) -> Option<String> {
    crate::jmap::reply::go_compact(raw)
}

/// Go's `json.Marshal(map[string]any)`: sorted keys, HTML-escaped strings.
pub(crate) fn go_map(entries: Vec<(&str, Value)>) -> String {
    let map: std::collections::BTreeMap<&str, Value> = entries.into_iter().collect();
    go_compact(&serde_json::to_string(&map).expect("map JSON")).expect("map JSON")
}

/// Go's `dispatchInvocation` (handler.go:1527) and the HTTP envelope.
pub(super) async fn serve(cx: &Cx<'_>, client_id: &str, session: &str) -> String {
    let method = cx.method();
    let handled = if !matches!(
        serde_json::from_str::<Value>(cx.args()),
        Ok(Value::Object(_) | Value::Null)
    ) {
        Err(MethodError::new(
            "invalidArguments",
            "args must be a JSON object",
        ))
    } else if !method.app.is_empty() && !cx.app_allowed().await {
        Err(MethodError::new(
            "forbidden",
            "access to this app is not permitted",
        ))
    } else {
        (method.run)(cx).await
    };
    let (name, args) = match handled {
        Ok(answer) => match go_compact(&answer.args) {
            Some(args) => (answer.name, args),
            None => ("error", MethodError::server_fail().json()),
        },
        Err(error) => ("error", error.json()),
    };
    format!(
        "{{\"sessionState\":{},\"methodResponses\":[[{},{},{}]]}}\n",
        crate::problem::go_string(session),
        crate::problem::go_string(name),
        args,
        crate::problem::go_string(client_id)
    )
}

/// Every non-stub registry row must be covered by exactly the fragments'
/// commands, with the same gate/app/account/mutator/state (adequacy input).
fn check_fragments(registered: &[&Method], fragments: &[(String, Value)]) -> Result<(), String> {
    use std::collections::{BTreeMap, BTreeSet};
    let by_name: BTreeMap<&str, &Method> = registered.iter().map(|m| (m.name, *m)).collect();
    let mut commands: BTreeSet<String> = BTreeSet::new();
    let mut mutators: BTreeSet<String> = BTreeSet::new();
    let mut suited: BTreeSet<String> = BTreeSet::new();
    for (file, fragment) in fragments {
        let inventory = fragment
            .pointer("/inventory/0")
            .ok_or_else(|| format!("{file}: missing inventory"))?;
        for (field, into) in [
            ("oracle_commands", &mut commands),
            ("oracle_mutators", &mut mutators),
        ] {
            let names = inventory
                .get(field)
                .and_then(Value::as_array)
                .ok_or_else(|| format!("{file}: missing {field}"))?;
            for name in names {
                let name = name
                    .as_str()
                    .ok_or_else(|| format!("{file}: {field} entry is not a string"))?;
                if !into.insert(name.to_owned()) {
                    return Err(format!("{file}: {name} declared twice in {field}"));
                }
            }
        }
        let suites = fragment
            .get("routes")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{file}: missing routes"))?;
        for suite in suites {
            let command = suite
                .get("command")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{file}: suite without command"))?;
            let method = by_name
                .get(command)
                .ok_or_else(|| format!("{file}: {command} is not registered"))?;
            suited.insert(command.to_owned());
            let expected = [
                ("gate", Value::from(method.gate.word())),
                ("app", Value::from(method.app)),
                ("account", Value::from(method.account)),
                ("mutator", Value::from(method.mutator)),
                ("state", Value::from(method.state)),
            ];
            for (field, value) in expected {
                if suite.get(field) != Some(&value) {
                    return Err(format!(
                        "{file}: {command} {field} differs from the registry"
                    ));
                }
            }
        }
    }
    let names: BTreeSet<String> = registered.iter().map(|m| m.name.to_owned()).collect();
    let writers: BTreeSet<String> = registered
        .iter()
        .filter(|m| m.mutator)
        .map(|m| m.name.to_owned())
        .collect();
    if commands != names {
        return Err(format!(
            "fragment commands {commands:?} != registered {names:?}"
        ));
    }
    if suited != names {
        return Err(format!(
            "fragment suites {suited:?} != registered {names:?}"
        ));
    }
    if mutators != writers {
        return Err(format!(
            "fragment mutators {mutators:?} != registered mutators {writers:?}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use serde_json::json;
    use setjoin_contracts::ids::{ActorId, Generation, MailboxId};
    use setjoin_pg::{MailboxAuthContext, ScopedExecutor};

    use super::*;

    const GOLDEN: &str =
        include_str!("../../../../../../mailserver/internal/jmap/testdata/methods.golden");
    const INVENTORY: &str = include_str!("../../../route-inventory.json");

    fn run_answer<'a>(_: &'a Cx<'a>) -> Reply<'a> {
        Box::pin(async {
            Ok(Answer {
                name: "Test/get",
                args: "{\"a\": 1}".into(),
            })
        })
    }

    fn never(_: Ready) -> bool {
        false
    }

    static TESTS: [Method; 3] = [
        Method {
            name: "Test/get",
            capability: "urn:test",
            app: "",
            gate: Gate::Personal,
            account: true,
            mutator: false,
            state: false,
            ready: always,
            run: run_answer,
        },
        Method {
            name: "Test/notReady",
            capability: "urn:test",
            app: "",
            gate: Gate::Personal,
            account: true,
            mutator: false,
            state: false,
            ready: never,
            run: run_answer,
        },
        Method {
            name: "Test/set",
            capability: "urn:test",
            app: "tests",
            gate: Gate::Read,
            account: true,
            mutator: true,
            state: true,
            ready: always,
            run: run_answer,
        },
    ];

    fn test_find(name: &str) -> Option<&'static Method> {
        TESTS.iter().find(|method| method.name == name)
    }

    fn body(using: &str, name: &str, args: &str) -> Vec<u8> {
        format!(r#"{{"using":["{using}"],"methodCalls":[["{name}",{args},"c1"]]}}"#).into_bytes()
    }

    #[test]
    fn classify_claims_only_registered_ready_single_calls() {
        assert!(classify_with(&body("urn:test", "Test/get", "{}"), None, test_find).is_some());
        assert!(classify_with(&body("urn:test", "Test/get", "null"), None, test_find).is_some());
        assert!(classify_with(&body("urn:test", "Test/get", "[1]"), None, test_find).is_some());
        assert!(classify_with(&body("urn:other", "Test/get", "{}"), None, test_find).is_none());
        assert!(classify_with(&body("urn:test", "Test/notReady", "{}"), None, test_find).is_none());
        assert!(classify_with(&body("urn:test", "Test/none", "{}"), None, test_find).is_none());
        let two =
            br#"{"using":["urn:test"],"methodCalls":[["Test/get",{},"a"],["Test/get",{},"b"]]}"#;
        assert!(classify_with(two, None, test_find).is_none());
        let extra =
            br#"{"using":["urn:test"],"methodCalls":[["Test/get",{},"a"]],"createdIds":{}}"#;
        assert!(classify_with(extra, None, test_find).is_none());
    }

    #[test]
    fn classify_leaves_references_large_and_deep_args_to_go() {
        let reference = r##"{"#ids":{"resultOf":"a","name":"Test/get","path":"/ids"}}"##;
        assert!(classify_with(&body("urn:test", "Test/get", reference), None, test_find).is_none());
        let large = format!(r#"{{"x":"{}"}}"#, "a".repeat(MAX_ARGS));
        assert!(classify_with(&body("urn:test", "Test/get", &large), None, test_find).is_none());
        let deep = format!(r#"{{"x":{}{}}}"#, "[".repeat(200), "]".repeat(200));
        assert!(classify_with(&body("urn:test", "Test/get", &deep), None, test_find).is_none());
    }

    #[test]
    fn gates_follow_go() {
        let grants = |g: &[&str]| g.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(!Gate::Personal.allows(&grants(&["full_access"])));
        assert!(Gate::Read.allows(&grants(&["read"])));
        assert!(!Gate::Read.allows(&grants(&["manage_calendar"])));
        assert!(Gate::Mutate.allows(&grants(&["full_access"])));
        assert!(!Gate::Mutate.allows(&grants(&["send_as"])));
        assert!(Gate::Collaborate.allows(&grants(&["send_on_behalf"])));
        assert!(!Gate::Submit.allows(&grants(&["read"])));
        assert_eq!(error_status("notFound"), 500);
        assert_eq!(error_status("forbidden"), 500);
        assert_eq!(error_status("accountNotFound"), 400);
        assert_eq!(error_status("invalidArguments"), 400);
    }

    #[test]
    fn go_map_sorts_and_escapes() {
        assert_eq!(
            go_map(vec![("b", json!("<")), ("a", json!(1))]),
            r#"{"a":1,"b":"<"}"#
        );
    }

    #[tokio::test]
    async fn serve_answers_go_shapes_without_a_database() {
        let exec = ScopedExecutor::from_dsn("host=127.0.0.1 port=1 user=x dbname=x", 1)
            .expect("lazy pool");
        let auth = MailboxAuthContext::from_authenticated_session(
            ActorId::new(1).expect("actor"),
            MailboxId::new(2).expect("mailbox"),
            Generation(1),
        );
        let cx = Cx::new(&exec, None, &auth, 1, 2, &TESTS[0], "[1]");
        assert_eq!(
            serve(&cx, "c1", "s").await,
            "{\"sessionState\":\"s\",\"methodResponses\":[[\"error\",{\"type\":\"urn:ietf:params:jmap:error:invalidArguments\",\"status\":400,\"detail\":\"args must be a JSON object\"},\"c1\"]]}\n"
        );
        let cx = Cx::new(&exec, None, &auth, 1, 2, &TESTS[0], "null");
        assert_eq!(
            serve(&cx, "c1", "s").await,
            "{\"sessionState\":\"s\",\"methodResponses\":[[\"Test/get\",{\"a\":1},\"c1\"]]}\n"
        );
    }

    #[test]
    fn registry_matches_frozen_go() {
        // Delete with Go (#142).
        let golden: BTreeMap<&str, Vec<&str>> = GOLDEN
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let fields: Vec<&str> = line.split('\t').collect();
                assert_eq!(fields.len(), 4, "methods.golden row {line:?}");
                (fields[0], fields)
            })
            .collect();
        assert!(golden.contains_key("Reminder/get"));
        let inventory: Value = serde_json::from_str(INVENTORY).expect("route inventory");
        let native: BTreeSet<&str> = inventory["routes"]
            .as_array()
            .expect("routes")
            .iter()
            .filter(|route| route["method"] == "POST" && route["path"] == "/jmap")
            .flat_map(|route| route["oracle_commands"].as_array().into_iter().flatten())
            .filter_map(Value::as_str)
            .collect();
        let mut seen = BTreeSet::new();
        for method in registered() {
            assert!(seen.insert(method.name), "{} registered twice", method.name);
            let row = golden
                .get(method.name)
                .unwrap_or_else(|| panic!("{} is not in methods.golden", method.name));
            assert_eq!(
                (method.capability, method.app, method.gate.word()),
                (row[1], row[2], row[3]),
                "{}",
                method.name
            );
            assert_eq!(
                crate::jmap::ws_request::metadata(method.name),
                Some(method.capability),
                "{}",
                method.name
            );
            assert!(
                !native.contains(method.name),
                "{} is already claimed by an older classifier",
                method.name
            );
            assert_eq!(
                method.account,
                !seam::WORKER_TASK_METHODS.contains(&method.name),
                "{} account flag",
                method.name
            );
        }
    }

    #[test]
    fn fragments_cover_registry() {
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/conformance/route-catalog.d");
        let mut fragments: Vec<(String, Value)> = Vec::new();
        // A missing directory is an empty set (A2 creates it).
        if let Ok(entries) = std::fs::read_dir(&directory) {
            for entry in entries {
                let path = entry.expect("fragment entry").path();
                let name = path
                    .file_name()
                    .expect("fragment name")
                    .to_string_lossy()
                    .into_owned();
                if name.starts_with("jmap-") && name.ends_with(".json") {
                    let text = std::fs::read_to_string(&path).expect("fragment text");
                    fragments.push((name, serde_json::from_str(&text).expect("fragment JSON")));
                }
            }
        }
        fragments.sort_by(|a, b| a.0.cmp(&b.0));
        let registered: Vec<&Method> = registered().collect();
        check_fragments(&registered, &fragments).unwrap();
    }

    fn fragment(commands: &[&str], mutators: &[&str], suite: Value) -> (String, Value) {
        (
            "jmap-1.json".into(),
            json!({"version": 1,
                "inventory": [{"listener": "gateway", "method": "POST", "path": "/jmap", "family": "F18",
                    "oracle_commands": commands, "oracle_mutators": mutators}],
                "routes": [suite]}),
        )
    }

    #[test]
    fn a_declared_command_without_a_suite_is_rejected() {
        let set = &TESTS[2];
        let good = json!({"command": "Test/set", "gate": "read", "app": "tests",
            "account": true, "mutator": true, "state": true});
        let (name, mut fragment) = fragment(&["Test/set"], &["Test/set"], good);
        fragment["routes"] = json!([]);
        let error = check_fragments(&[set], &[(name, fragment)]).unwrap_err();
        assert!(error.contains("fragment suites"), "{error}");
    }

    #[test]
    fn fragment_check_rejects_drift() {
        let set = &TESTS[2];
        let good = json!({"command": "Test/set", "gate": "read", "app": "tests",
            "account": true, "mutator": true, "state": true});
        assert!(check_fragments(&[], &[]).is_ok());
        assert!(check_fragments(
            &[set],
            &[fragment(&["Test/set"], &["Test/set"], good.clone())]
        )
        .is_ok());
        assert!(check_fragments(&[set], &[]).is_err(), "unlisted method");
        assert!(
            check_fragments(&[set], &[fragment(&["Test/set"], &[], good.clone())]).is_err(),
            "mutator missing"
        );
        let mut wrong_gate = good.clone();
        wrong_gate["gate"] = json!("personal");
        assert!(check_fragments(
            &[set],
            &[fragment(&["Test/set"], &["Test/set"], wrong_gate)]
        )
        .is_err());
        let mut wrong_account = good.clone();
        wrong_account["account"] = json!(false);
        assert!(check_fragments(
            &[set],
            &[fragment(&["Test/set"], &["Test/set"], wrong_account)]
        )
        .is_err());
        assert!(
            check_fragments(
                &[set],
                &[
                    fragment(&["Test/set"], &["Test/set"], good.clone()),
                    fragment(&["Test/set"], &["Test/set"], good)
                ]
            )
            .is_err(),
            "declared twice"
        );
    }
}
