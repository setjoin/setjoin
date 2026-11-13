//! Business feature toggles for native JMAP Email extensions.

/// Go's `toggle.FeatureFlags.IsEnabled` for a key whose registry default is
/// OFF, from the database row Go's cache mirrors: `Some(true)` when the row is
/// enabled, `Some(false)` when it is absent or off, `None` (forward to Go) on a
/// read error or an unusable registry state. Process-environment overrides are
/// Go's alone and are not visible here.
pub async fn toggle_state(exec: &setjoin_pg::ScopedExecutor, key: &str) -> Option<bool> {
    let rows = tokio::time::timeout(
        super::PRECHECK_TIMEOUT,
        exec.read(
            "SELECT s.mode::text, ft.enabled FROM feature_toggle_registry_state s \
             LEFT JOIN feature_toggles ft ON ft.key = $1 WHERE s.singleton",
            &[(&key, setjoin_pg::Type::TEXT)],
        ),
    )
    .await
    .ok()?
    .ok()?;
    let row = rows.first()?;
    matches!(
        row.get::<_, Option<String>>(0).as_deref(),
        Some("observe" | "enforce")
    )
    .then(|| row.get::<_, Option<bool>>(1) == Some(true))
}

/// `feature.stale_nudges`, the gate of `Email/nudges` and `Email/nudgeDismiss`.
pub const NUDGES_FLAG: &str = "feature.stale_nudges";
