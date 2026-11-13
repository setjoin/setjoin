//! Which database (if any) a conformance run uses. Mirrors the Go rule in
//! `shared/testsupport/pool.go`: no DSN skips with a greppable line, unless
//! `REQUIRE_DB` is non-empty, in which case a missing database is a failure.

/// The skip marker printed when no database is configured. Greppable in CI logs.
pub const SKIP_MARKER: &str = "CONFORMANCE-SKIP";

#[derive(Debug, PartialEq, Eq)]
pub enum DbGate {
    /// Run against these connections. `dsn` is the owner connection for
    /// fixtures and observation; `direct` is used only for LISTEN; `app`
    /// (`DB_APP_DSN`, the constrained `setjoin_app` credential) runs the
    /// command under test when set, else the owner connection does.
    Run {
        dsn: String,
        direct: String,
        app: Option<String>,
    },
    /// No database and none required: the case must be reported as skipped.
    Skip,
    /// No database but `REQUIRE_DB` is set: the case must fail.
    Missing,
}

/// Resolve the gate from an environment lookup. `TEST_DB_DSN` wins over
/// `DB_DSN`; `DB_DIRECT_DSN` (LISTEN/NOTIFY connection) defaults to the DSN.
pub fn resolve(env: impl Fn(&str) -> Option<String>) -> DbGate {
    let non_empty = |key: &str| env(key).filter(|v| !v.is_empty());
    match non_empty("TEST_DB_DSN").or_else(|| non_empty("DB_DSN")) {
        Some(dsn) => {
            let direct = non_empty("DB_DIRECT_DSN").unwrap_or_else(|| dsn.clone());
            let app = non_empty("DB_APP_DSN");
            DbGate::Run { dsn, direct, app }
        }
        None if non_empty("REQUIRE_DB").is_some() => DbGate::Missing,
        None => DbGate::Skip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |key| owned.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    }

    #[test]
    fn no_dsn_skips() {
        assert_eq!(resolve(env(&[])), DbGate::Skip);
    }

    #[test]
    fn no_dsn_with_require_db_is_missing() {
        assert_eq!(resolve(env(&[("REQUIRE_DB", "1")])), DbGate::Missing);
    }

    #[test]
    fn test_db_dsn_wins_and_direct_defaults_to_it() {
        let gate = resolve(env(&[("DB_DSN", "a"), ("TEST_DB_DSN", "b")]));
        assert_eq!(
            gate,
            DbGate::Run {
                dsn: "b".into(),
                direct: "b".into(),
                app: None,
            }
        );
    }

    #[test]
    fn direct_dsn_is_used_for_listen_when_set() {
        let gate = resolve(env(&[("DB_DSN", "pool"), ("DB_DIRECT_DSN", "direct")]));
        assert_eq!(
            gate,
            DbGate::Run {
                dsn: "pool".into(),
                direct: "direct".into(),
                app: None,
            }
        );
    }

    #[test]
    fn app_dsn_runs_the_command_when_set() {
        let gate = resolve(env(&[("DB_DSN", "owner"), ("DB_APP_DSN", "app")]));
        assert_eq!(
            gate,
            DbGate::Run {
                dsn: "owner".into(),
                direct: "owner".into(),
                app: Some("app".into()),
            }
        );
    }

    #[test]
    fn empty_values_count_as_unset() {
        assert_eq!(
            resolve(env(&[("DB_DSN", ""), ("REQUIRE_DB", "")])),
            DbGate::Skip
        );
    }
}
