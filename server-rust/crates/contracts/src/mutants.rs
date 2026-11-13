//! Test-only bug restoration for the owner-approved security fixes of
//! 2026-11-05 (#484 #487 #490 #495 #499 #503 #504 #491). Absent from every
//! ordinary build: with the `oracle-mutants` feature, `SETJOIN_SECFIX3_MUTANT=<id>`
//! re-enables one frozen-Go defect so `scripts/test-secfix3-mutants.py` can prove
//! the secure-behaviour test rejects it.
#[cfg(feature = "oracle-mutants")]
pub fn on(id: &str) -> bool {
    std::env::var("SETJOIN_SECFIX3_MUTANT").is_ok_and(|v| v == id)
}
#[cfg(not(feature = "oracle-mutants"))]
#[inline(always)]
pub fn on(_: &str) -> bool {
    false
}
