//! Database-backed parity oracles for commands moving to Rust authority
//! (ARCH-026). Not runtime code: nothing here is linked into a gateway.
pub mod db_gate;
pub mod dns_fake;
pub mod email_list;
pub mod fixture;
pub mod golden;
pub mod harness;
pub mod ldap_fake;
pub mod mark_read;
pub mod ports;
pub mod reducer;
pub mod reducer_list;

pub mod shared_vectors;
