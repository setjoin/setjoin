use std::fs;
use std::path::PathBuf;

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap()
        .to_path_buf()
}

fn source(relative: &str) -> String {
    fs::read_to_string(repository_root().join(relative)).unwrap()
}

#[test]
fn adapters_do_not_reintroduce_parallel_vault_or_offline_state() {
    let tauri = source("clients/desktop/src-tauri/src/bridge.rs");
    let napi = source("clients/rust/native-shared/native_impl.rs");
    let composition = source("clients/desktop/src-tauri/src/lib.rs");

    for removed in [
        "VaultState",
        "OfflineState",
        "fn engine(",
        "fn unlocked_core(",
    ] {
        assert!(!tauri.contains(removed), "Tauri reintroduced {removed}");
        assert!(!napi.contains(removed), "N-API reintroduced {removed}");
    }
    for removed in ["static VAULT", "static OFFLINE"] {
        assert!(!napi.contains(removed), "N-API reintroduced {removed}");
    }
    assert!(tauri.contains("Mutex<CapabilitySession>"));
    assert!(napi.contains("Mutex<CapabilitySession>"));
    assert_eq!(
        composition
            .matches("manage(bridge::CapabilityState::default())")
            .count(),
        1
    );
}
