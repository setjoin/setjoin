//! Test-only bug restoration for the owner-approved security fixes (2026-11-05,
//! #492/#493/#500/#488). Absent from every ordinary build: with the
//! `oracle-mutants` feature, `SETJOIN_SMTP_MUTANT=<id>` re-enables one frozen-Go
//! defect so `scripts/test-smtp-secfix-mutants.py` can prove the secure-behaviour
//! test rejects it.
#[cfg(feature = "oracle-mutants")]
pub(crate) fn on(id: &str) -> bool {
    std::env::var("SETJOIN_SMTP_MUTANT").is_ok_and(|v| v == id)
}
#[cfg(not(feature = "oracle-mutants"))]
#[inline(always)]
pub(crate) fn on(_: &str) -> bool {
    false
}
