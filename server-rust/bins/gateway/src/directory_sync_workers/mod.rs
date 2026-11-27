//! Background AD/LDAP/Catalog directory-sync workers (moved out of
//! `crates/domains/directory-sync` so domain crates remain strictly free of
//! `WorkerDatabase` / `WorkerConnection` per Wave 1.8 #546d).

pub mod ad_runtime;
pub mod catalog;
pub mod ldap_engine;
pub mod ldap_normalized;
pub mod ldap_runtime;

pub use ad_runtime::{AdRuntime, AdWorker};
pub use catalog::{Decode, Entry, IdentitySourceRuntime, ProbeFailure, Snapshot, SourceConfig};
pub use ldap_engine::{Worker, DEFAULT_ABSENCE_SWEEP_HOURS};
pub use ldap_runtime::{load_env_codec, LdapRuntime, Loaded};
pub use setjoin_directory_sync::ldap::{
    admit_filter, atoi_lenient, build_sync_filter, is_secret_key, parse_bool, PreviewRow,
    SyncResult,
};

pub(crate) fn log_warn_ad(message: &str) {
    eprintln!("setjoin-gateway: ad-sync: {message}");
}

pub(crate) fn log_warn_ldap(message: &str) {
    eprintln!("setjoin-gateway: ldap-sync: {message}");
}
