#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// The app logic lives in lib.rs (a cdylib/staticlib for mobile — see
// Cargo.toml's [lib] block); this stays a thin binary entry for desktop.
fn main() {
    setjoin_desktop::run();
}
