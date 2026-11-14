//! The only database and identity seam family handlers get (#369-#377).
//!
//! [`Cx`], [`Scope`] and [`ContinuitySigner`] keep their fields private to
//! this module tree, and family files are not inside it. Scoped SQL is
//! `&'static str` checked by `call::owner_bound`; `$1` always comes from a
//! [`Scope`] that only [`resolve`] (Go `parseAccountID`) creates. Worker
//! (BYPASSRLS) statements are a closed table in `call.rs`: family code passes
//! a variant and its non-identity params, never SQL, and `$1` is the verified
//! user. `tests::family_files_use_only_the_seam` enforces the rest.
use setjoin_pg::{MailboxAuthContext, ScopedExecutor};

use super::Method;

/// A scoped write statement: Go's reducer call plus the receipt guard ($2 actor, $3 operation).
macro_rules! write_sql {
    ($sql:literal) => {
        concat!($sql, " WHERE $2::bigint>0 AND $3::text<>''")
    };
}

/// Go `dispatchSet` statements for reducer prefix `$p` (handler.go:1754).
macro_rules! set_sql {
    ($p:literal) => {
        $crate::jmap::family::seam::SetSql::new(
            concat!("SELECT ", $p, "_set_create($1,$2::text::jsonb)::text"),
            concat!("SELECT ", $p, "_set_update($1,$2::text::jsonb)::text"),
            concat!("SELECT ", $p, "_set_destroy($1,$2::bigint[])::text"),
        )
    };
}

pub(crate) use set_sql;
pub(crate) use write_sql;

mod account;
mod call;

pub(crate) use account::resolve;
pub(crate) use call::{
    not_found, parse_id_list, query, read, set_batch, since_state, worker_read, worker_write,
    write, ScopedQuery, SetSql, WorkerRead, WorkerWrite,
};
pub(crate) use setjoin_pg::{Param, Type};

/// The user-keyed worker methods without `parseAccountID` (task_lists.go:16-18).
pub(crate) const WORKER_TASK_METHODS: &[&str] = &[
    "TaskAssigned/get",
    "TaskAssigned/setStatus",
    "TaskList/get",
    "TaskList/set",
    "TaskList/taskSet",
    "TaskList/tasks",
    "TaskListMember/set",
];

/// Every Go `h.workerPool` family handler (task_lists.go, calendar_a3.go:197).
/// Changing this list or the statement table requires a Fable plan review.
pub(crate) const WORKER_METHODS: &[&str] = &[
    "Calendar/delegateList",
    "TaskAssigned/get",
    "TaskAssigned/setStatus",
    "TaskList/get",
    "TaskList/set",
    "TaskList/taskSet",
    "TaskList/tasks",
    "TaskListMember/set",
];

/// Go's `continuity.Service` signer (`CONTINUITY_SIGNING_KEY_FILE`/`_ID`).
pub struct ContinuitySigner {
    key_id: String,
    key: ring::signature::Ed25519KeyPair,
}

impl ContinuitySigner {
    pub fn new(key_id: String, key: ring::signature::Ed25519KeyPair) -> Self {
        Self { key_id, key }
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key.sign(message).as_ref().to_vec()
    }

    pub(crate) fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        use ring::signature::KeyPair;
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            self.key.public_key().as_ref(),
        )
        .verify(message, signature)
        .is_ok()
    }
}

/// Everything a handler may use; built only from the verified request.
pub(crate) struct Cx<'a> {
    exec: &'a ScopedExecutor,
    services: Option<&'a crate::jmap::JmapServices>,
    primary: &'a MailboxAuthContext,
    user: i64,
    mailbox: i64,
    method: &'static Method,
    args: &'a str,
}

impl<'a> Cx<'a> {
    pub(in crate::jmap) fn new(
        exec: &'a ScopedExecutor,
        services: Option<&'a crate::jmap::JmapServices>,
        primary: &'a MailboxAuthContext,
        user: i64,
        mailbox: i64,
        method: &'static Method,
        args: &'a str,
    ) -> Self {
        Self {
            exec,
            services,
            primary,
            user,
            mailbox,
            method,
            args,
        }
    }

    /// The call's arguments exactly as sent.
    pub(crate) fn args(&self) -> &'a str {
        self.args
    }

    pub(crate) fn method(&self) -> &'static Method {
        self.method
    }

    /// Go `h.continuity` (signer and boot epoch); `None` when the key did not load.
    pub(crate) fn continuity(&self) -> Option<(&'a ContinuitySigner, &'a str)> {
        let services = self.services?;
        Some((
            services.continuity_signer.as_deref()?,
            services.continuity_boot.as_deref()?,
        ))
    }

    /// Go `toggles.IsEnabled`; `None` when the registry state is unreadable.
    pub(crate) async fn toggle(&self, key: &str) -> Option<bool> {
        crate::jmap::gates::toggle_state(self.exec, key).await
    }

    pub(in crate::jmap::family) async fn app_allowed(&self) -> bool {
        account::app_allowed(self).await
    }
}

/// The account a call runs against; only [`resolve`] creates one.
pub(crate) struct Scope {
    mailbox: i64,
    auth: MailboxAuthContext,
    delegated: bool,
}

impl Scope {
    pub(crate) fn id(&self) -> i64 {
        self.mailbox
    }

    pub(crate) fn delegated(&self) -> bool {
        self.delegated
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use regex::Regex;

    use super::{WORKER_METHODS, WORKER_TASK_METHODS};

    const GOLDEN: &str =
        include_str!("../../../../../../../mailserver/internal/jmap/testdata/methods.golden");

    /// Substrings no scanned file may contain once its exact exceptions are removed.
    const FORBIDDEN: &[&str] = &[
        "setjoin_pg",
        "setjoin_db",
        "tokio_postgres",
        "MailboxAuthContext",
        "from_authenticated",
        "ScopedExecutor",
        "read_scoped",
        "read_user_scoped",
        "protocol_",
        "JmapServices",
        "JmapCommands",
        ".exec",
        ".services",
        ".worker",
        "SetSql",
        "unsafe",
        "include!",
        "include_str!",
        "include_bytes!",
        "#[path",
        "#[link",
        "extern crate",
        "env!(",
        "asm!(",
        "::std::",
        "std::env",
        "std::fs",
        "std::process",
        "std::net",
        "std::os",
        "std::io",
        "std::ffi",
        "tokio::",
        "Command::new",
        "super::super",
    ];
    /// `crate::` may only continue with these.
    const CRATE_PATHS: &[&str] = &["jmap::family", "problem::", "guests_input::"];
    /// Allowed `use` path prefixes (whole segments).
    const USE_PREFIXES: &[&str] = &[
        "std::collections",
        "std::fmt",
        "std::future",
        "std::pin",
        "std::cmp",
        "std::str",
        "std::iter",
        "std::borrow",
        "std::convert",
        "std::ops",
        "std::sync::Arc",
        "std::sync::OnceLock",
        "serde",
        "serde_json",
        "base64",
        "sha2",
        "chrono",
        "regex",
        "super",
        "self",
        "crate::jmap::family",
        "crate::problem",
        "crate::guests_input",
    ];
    const WORKER_TOKENS: &[&str] = &["worker_read", "worker_write", "WorkerRead", "WorkerWrite"];
    const WORKER_FILES: &[&str] = &["calendar_delegate.rs", "task_list.rs"];
    /// The reviewed core files next to the stubs.
    const CORE_FILES: &[&str] = &["args.rs", "mod.rs", "reducer_error.rs"];
    /// Narrow, exact exceptions for the core files (types and test-only harness use).
    const MOD_EXCEPTIONS: &[&str] = &[
        "pub(crate) use crate::jmap::get::parse_id;",
        "pub use seam::ContinuitySigner;",
        "pub(crate) use seam::Cx;",
        "crate::jmap::JmapServices",
        "crate::jmap::reply::go_compact",
        "crate::jmap::ws_request::metadata",
        "use setjoin_contracts::ids::{ActorId, Generation, MailboxId};",
        "use setjoin_pg::{MailboxAuthContext, ScopedExecutor};",
        "ScopedExecutor::from_dsn(",
        "MailboxAuthContext::from_authenticated_session(",
        "include_str!(",
        "std::fs::read_dir",
        "std::fs::read_to_string",
        "env!(\"CARGO_MANIFEST_DIR\")",
    ];
    const REDUCER_ERROR_EXCEPTIONS: &[&str] = &[
        "use setjoin_pg::StatementFailure;",
        "use Class::{",
        "include_str!(",
    ];

    fn exceptions(name: &str) -> &'static [&'static str] {
        match name {
            "mod.rs" => MOD_EXCEPTIONS,
            "reducer_error.rs" => REDUCER_ERROR_EXCEPTIONS,
            _ => &[],
        }
    }

    /// Every path a `use` declaration names, braces expanded, aliases and `self` dropped.
    fn use_paths(text: &str) -> Vec<String> {
        let declaration =
            Regex::new(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+([^;]+);").expect("use pattern");
        let alias = Regex::new(r"\s+as\s+[A-Za-z_][A-Za-z0-9_]*").expect("alias pattern");
        let mut paths = Vec::new();
        for captures in declaration.captures_iter(text) {
            let tree: String = alias
                .replace_all(&captures[1], "")
                .chars()
                .filter(|ch| !ch.is_whitespace())
                .collect();
            expand("", &tree, &mut paths);
        }
        paths
    }

    fn expand(prefix: &str, tree: &str, out: &mut Vec<String>) {
        match tree.find('{') {
            Some(open) if tree.ends_with('}') => {
                let base = format!("{prefix}{}", &tree[..open]);
                let inner = &tree[open + 1..tree.len() - 1];
                let (mut depth, mut start) = (0usize, 0usize);
                for (index, ch) in inner.char_indices() {
                    match ch {
                        '{' => depth += 1,
                        '}' => depth = depth.saturating_sub(1),
                        ',' if depth == 0 => {
                            expand(&base, &inner[start..index], out);
                            start = index + 1;
                        }
                        _ => {}
                    }
                }
                expand(&base, &inner[start..], out);
            }
            _ if tree.is_empty() => {}
            _ => {
                let path = format!("{prefix}{tree}");
                out.push(path.trim_end_matches("::self").to_owned());
            }
        }
    }

    fn use_allowed(path: &str) -> bool {
        if path.ends_with('*') {
            return path == "super::*";
        }
        if path.starts_with("::") || path.starts_with("super::super") {
            return false;
        }
        USE_PREFIXES
            .iter()
            .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}::")))
    }

    /// Every rule a scanned file breaks (empty when it only uses the seam).
    fn violations(name: &str, source: &str) -> Vec<String> {
        let mut text = source.to_owned();
        for exception in exceptions(name) {
            text = text.replace(exception, "");
        }
        let mut found = Vec::new();
        for token in FORBIDDEN {
            if text.contains(token) {
                found.push(format!("{name}: {token}"));
            }
        }
        let mut rest = text.as_str();
        while let Some(at) = rest.find("crate::") {
            rest = &rest[at + "crate::".len()..];
            if !CRATE_PATHS.iter().any(|allowed| rest.starts_with(allowed)) {
                found.push(format!(
                    "{name}: crate::{}",
                    rest.chars().take(40).collect::<String>()
                ));
            }
        }
        for path in use_paths(&text) {
            if !use_allowed(&path) {
                found.push(format!("{name}: use {path}"));
            }
        }
        if !WORKER_FILES.contains(&name) {
            for token in WORKER_TOKENS {
                if text.contains(token) {
                    found.push(format!("{name}: {token}"));
                }
            }
        }
        found
    }

    #[test]
    fn family_files_use_only_the_seam() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/jmap/family");
        let mut scanned: Vec<(String, String)> = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(directory) = stack.pop() {
            for entry in std::fs::read_dir(&directory).expect("family directory") {
                let path = entry.expect("family entry").path();
                let relative = path
                    .strip_prefix(&root)
                    .expect("inside family")
                    .to_string_lossy()
                    .replace('\\', "/");
                if relative == "seam" {
                    continue;
                }
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("family file");
                scanned.push((relative, text));
            }
        }
        scanned.sort();
        let names: BTreeSet<&str> = scanned.iter().map(|(name, _)| name.as_str()).collect();
        let expected: BTreeSet<&str> = super::super::FAMILY_FILES
            .iter()
            .chain(CORE_FILES.iter())
            .copied()
            .collect();
        assert_eq!(
            names, expected,
            "family/ may hold exactly the stub and core files"
        );
        for (name, text) in &scanned {
            let found = violations(name, text);
            assert!(found.is_empty(), "{found:#?}");
        }
    }

    #[test]
    fn the_guard_rejects_each_escape() {
        for fixture in [
            "use std::{env, process::Command};",
            "use std as s;",
            "use ::std::env::var;",
            "use std::*;",
            "use std::os::unix::process::CommandExt;",
            "pub(crate) use crate::jmap::reply::response;",
            "use crate::workers::Workers;",
            "use setjoin_pg::Type;",
            "use tokio::process::Command;",
            "use super::super::Cx;",
            "use serde_json as json; use json::Value; use crate::jmap::JmapServices;",
            "fn f() { let _ = std::env::var(\"DB_WORKER_DSN\"); }",
            "fn f() -> &'static str { env!(\"DB_DSN\") }",
            "fn f() { let _ = crate::jmap::random(); }",
            "include!(\"other.rs\");",
            "#[path = \"x.rs\"]\nmod x;",
            "extern crate std as s;",
            "fn f(cx: &Cx<'_>) { let _ = &cx.exec; }",
            "unsafe fn f() {}",
            "const S: SetSql = SetSql::new(\"\", \"\", \"\");",
            "fn f() { super::seam::worker_read(); }",
            "fn f() { let _ = tokio::fs::read(\"x\"); }",
        ] {
            assert!(!violations("reminder.rs", fixture).is_empty(), "{fixture}");
        }
        for clean in [
            "use super::Method;",
            "use super::seam::{read, resolve, write, write_sql, Type};",
            "use std::collections::{BTreeMap, BTreeSet};",
            "use serde_json::{json, Value};",
            "use std::fmt::{self, Write};",
            "pub(super) const METHODS: &[super::Method] = &[];",
            "fn f() -> String { crate::problem::go_string(\"x\") }",
        ] {
            let found = violations("reminder.rs", clean);
            assert!(found.is_empty(), "{clean}: {found:?}");
        }
        assert!(violations("task_list.rs", "fn f() { super::seam::worker_read(); }").is_empty());
        assert!(
            !violations("mod.rs", "use std::{env, process::Command};").is_empty(),
            "core files are scanned too"
        );
        assert!(!violations("args.rs", "fn f() { let _ = std::fs::read(\"x\"); }").is_empty());
    }

    #[test]
    fn worker_methods_live_only_in_the_worker_files() {
        let in_worker_files: Vec<&str> = super::super::task_list::METHODS
            .iter()
            .chain(super::super::calendar_delegate::METHODS.iter())
            .map(|method| method.name)
            .collect();
        for name in &in_worker_files {
            assert!(
                WORKER_METHODS.contains(name),
                "{name} is not a worker method"
            );
        }
        for method in super::super::registered() {
            if WORKER_METHODS.contains(&method.name) {
                assert!(
                    in_worker_files.contains(&method.name),
                    "{} must live in task_list.rs or calendar_delegate.rs",
                    method.name
                );
            }
        }
        let mut sorted = WORKER_METHODS.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, WORKER_METHODS, "WORKER_METHODS stays sorted");
        for name in WORKER_TASK_METHODS {
            assert!(WORKER_METHODS.contains(name), "{name}");
        }
        for name in WORKER_METHODS {
            assert!(
                GOLDEN
                    .lines()
                    .any(|line| line.starts_with(&format!("{name}\t"))),
                "{name} is not in methods.golden"
            );
        }
    }
}
