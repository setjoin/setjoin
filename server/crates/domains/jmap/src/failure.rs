//! How a reducer failure is answered (JMAP1, #315).
//!
//! Go's `mapReducerErr` turns a reducer error into a JMAP method error:
//! `BZ006` is `accountNotFound`, `BZ011` `cannotCalculateChanges`, `BZ002`
//! `forbidden`, any other unclassified error `serverFail` with the detail
//! `database error`. Rust answers exactly those the database itself reported
//! deterministically (a data, integrity, syntax or `RAISE` SQLSTATE: Go's
//! identical call fails identically). Everything else (timeouts, pool and
//! transport faults, serialization failures, BZ codes this family does not
//! raise) forwards to Go, which answers its own way; a rolled-back command
//! wrote nothing, so forwarding it cannot double an effect.
use setjoin_pg::StatementFailure;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// `BZ006`: detail `accountId does not match an existing account`.
    AccountNotFound,
    /// `BZ011`: detail `client must resync (sinceState too old)`.
    CannotCalculateChanges,
    /// `BZ002`: detail `access denied`.
    Forbidden,
    /// Detail `database error`.
    ServerFail,
    /// Not Rust's to answer.
    Forward,
}

pub fn classify(failure: &StatementFailure) -> Failure {
    match failure.sqlstate.as_deref() {
        Some("BZ006") => Failure::AccountNotFound,
        Some("BZ011") => Failure::CannotCalculateChanges,
        Some("BZ002") => Failure::Forbidden,
        Some(s)
            if s.starts_with("22")
                || s.starts_with("23")
                || s.starts_with("42")
                || s == "P0001" =>
        {
            Failure::ServerFail
        }
        _ => Failure::Forward,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(state: Option<&str>) -> StatementFailure {
        StatementFailure {
            sqlstate: state.map(str::to_owned),
            message: String::new(),
            hint: None,
        }
    }

    #[test]
    fn only_deterministic_database_answers_are_rust_s_to_give() {
        assert_eq!(classify(&f(Some("BZ006"))), Failure::AccountNotFound);
        assert_eq!(classify(&f(Some("BZ011"))), Failure::CannotCalculateChanges);
        assert_eq!(classify(&f(Some("BZ002"))), Failure::Forbidden);
        for s in ["22007", "22P02", "23505", "42883", "P0001"] {
            assert_eq!(classify(&f(Some(s))), Failure::ServerFail, "{s}");
        }
        for s in [
            Some("57014"),
            Some("40001"),
            Some("08006"),
            Some("BZ019"),
            Some("53300"),
            None,
        ] {
            assert_eq!(classify(&f(s)), Failure::Forward, "{s:?}");
        }
    }
}
