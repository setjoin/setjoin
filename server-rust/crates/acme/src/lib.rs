//! Managed ACME certificate lifecycle (ARCH-028 port of frozen Go's `internal/acme` managed loop).
//!
//! Issuance and renewal happen only in [`Manager::run`]; serving never issues. The cache layout
//! is shared with Go (see [`cache`]), so either process can serve what the other issued.
mod challenge;
pub mod dns;
mod client;
pub use challenge::{PendingAlpn, TlsAlpnStore};
pub mod cache;
pub mod inspect;
pub mod keys;
mod manager;

pub use manager::{
    normalize, not_after, Challenge, Config, Http01Store, Manager, TickOutcome, HTTP01_PREFIX,
};
