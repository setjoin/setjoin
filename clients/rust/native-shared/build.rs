//! Host test-lane link setup (D-CLIENTS-RUST-OHOS-NATIVE-002).
//!
//! `native-shared` is an rlib-only crate whose purpose is executing the shared
//! implementation's unit tests on the build host. The test executable links
//! napi-rs runtime objects that reference Node-API symbols which exist only in
//! the embedding runtime (Electron / ArkTS ArkWeb). The tests never CALL into
//! the JS runtime — they construct and drop plain `napi::Error`/`Buffer`
//! values — so those symbols are never dereferenced here, exactly as the
//! production cdylibs rely on dynamic lookup inside their host processes.
//! `napi_build::setup()` covers cdylib targets via `rustc-cdylib-link-arg`;
//! the unit-test executable needs the equivalent passed for executables.

fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    match os.as_str() {
        // ld: leave Node-API symbols unresolved; they resolve at load time in
        // the embedding runtime, never in this test binary.
        "macos" => println!("cargo:rustc-link-arg=-Wl,-undefined,dynamic_lookup"),
        "linux" => println!("cargo:rustc-link-arg=-Wl,--unresolved-symbols=ignore-all"),
        _ => {}
    }
}
