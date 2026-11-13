//! AD sync runtime (#381): wire client, normalized engine connector, worker
//! state and the route bodies of `admin.ADHandler`.
//!
//! Go's handler-built worker always runs the generation-fenced identity-source
//! pipeline (`SetIdentitySourceStore` binds `legacy:ad` to every worker), so the
//! legacy `ad/sync.go` upsert path is unreachable through the handler and is not
//! ported; the cursor is the source row's committed `{"usn":"<n>"}`.
pub mod client;
pub mod runtime;
pub use client::{AdClient, AdUser, ClientConfig, NameServerResolver, SrvResolver, SystemResolver};
pub use runtime::{AdRuntime, AdWorker};

pub(crate) fn log_warn(message: &str) {
    eprintln!("setjoin-gateway: ad-sync: {message}");
}
