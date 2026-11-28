//! Consolidated integration test suite `suite_misc` (preserves exact submodule test coverage).

#[path = "email_list_reducer.rs"]
mod email_list_reducer;
#[path = "email_list_rust.rs"]
mod email_list_rust;
#[path = "golden_contract.rs"]
mod golden_contract;
#[path = "mark_read_reducer.rs"]
mod mark_read_reducer;
#[path = "mark_read_rust.rs"]
mod mark_read_rust;
#[path = "oracle_discriminates.rs"]
mod oracle_discriminates;
#[path = "shared_vectors.rs"]
mod shared_vectors;
