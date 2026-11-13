//! Test-only bug restoration for the owner-approved OIDC provider security fixes
//! (2026-11-05, #523). Absent from every ordinary build: with the
//! `oracle-mutants` feature, `SETJOIN_SECFIX7_MUTANT=<id>` re-enables one
//! frozen-Go defect so `scripts/test-secfix7-mutants.py` can prove the
//! secure-behaviour test rejects it.
#[cfg(feature = "oracle-mutants")]
pub fn on(id: &str) -> bool {
    ["SETJOIN_SECFIX7_MUTANT", "SETJOIN_SECFIX8_MUTANT", "SETJOIN_SECFIX10_MUTANT", "SETJOIN_SAMLACS_MUTANT", "SETJOIN_SECFIX13_MUTANT", "SETJOIN_OIDCLAX_MUTANT"]
        .iter()
        .any(|name| std::env::var(name).is_ok_and(|v| v == id))
}
#[cfg(not(feature = "oracle-mutants"))]
#[inline(always)]
pub fn on(_: &str) -> bool {
    false
}
