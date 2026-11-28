use std::sync::atomic::{AtomicBool, Ordering};

/// `feature.federation` as the components read it (Go: `flags.IsEnabled`).
/// Production supplies the platform feature snapshot; the default is OFF.
pub trait Flags: Send + Sync {
    fn federation_enabled(&self) -> bool;
}

impl Flags for AtomicBool {
    fn federation_enabled(&self) -> bool {
        self.load(Ordering::Relaxed)
    }
}
