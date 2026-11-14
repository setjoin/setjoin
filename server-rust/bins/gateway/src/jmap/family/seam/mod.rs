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
    not_found, parse_id_list, read, set_batch, since_state, worker_read, worker_write, write,
    SetSql, WorkerRead, WorkerWrite,
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
    use super::{WORKER_METHODS, WORKER_TASK_METHODS};

    const GOLDEN: &str =
        include_str!("../../../../../../../mailserver/internal/jmap/testdata/methods.golden");

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
        "std::env",
        "std::fs",
        "std::process",
        "std::net",
        "super::super",
    ];
    const WORKER_TOKENS: &[&str] = &["worker_read", "worker_write", "WorkerRead", "WorkerWrite"];
    const WORKER_FILES: &[&str] = &["calendar_delegate.rs", "task_list.rs"];

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
                if matches!(relative.as_str(), "mod.rs" | "args.rs" | "reducer_error.rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("family file");
                scanned.push((relative, text));
            }
        }
        scanned.sort();
        let names: Vec<&str> = scanned.iter().map(|(name, _)| name.as_str()).collect();
        let mut expected = super::super::FAMILY_FILES.to_vec();
        expected.sort_unstable();
        assert_eq!(
            names, expected,
            "family/ may hold exactly the registered stub files"
        );
        for (name, text) in &scanned {
            for token in FORBIDDEN {
                assert!(
                    !text.contains(token),
                    "{name} uses {token}; go through family::seam"
                );
            }
            let mut rest = text.as_str();
            while let Some(at) = rest.find("crate::jmap::") {
                rest = &rest[at + "crate::jmap::".len()..];
                assert!(
                    rest.starts_with("family"),
                    "{name} reaches crate::jmap outside family"
                );
            }
            if !WORKER_FILES.contains(&name.as_str()) {
                for token in WORKER_TOKENS {
                    assert!(!text.contains(token), "{name} may not use {token}");
                }
            }
        }
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
