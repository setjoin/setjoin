// Tauri 2 mobile requires the app to be built as a library (cdylib on
// Android for JNI, staticlib on iOS for the Xcode "Build Rust Code" phase),
// with a `run()` entry point annotated `tauri::mobile_entry_point`. `main.rs`
// stays a thin binary wrapper so desktop builds are unaffected. See
// `Cargo.toml`'s `[lib]` block (crate-type = staticlib/cdylib/rlib).
mod bridge;
mod bridge_js;
mod mam;
mod mam_lifecycle;
mod mam_lifecycle_owner;

// C2 cfg(mobile) — target-checked post-init: platform screenshot-block glue,
// compiled only for the mobile targets. Desktop uses mam's no-op fallback.
#[cfg(target_os = "android")]
mod mam_android;
#[cfg(target_os = "ios")]
mod mam_ios;
// C2 cfg(mobile) — target-checked post-init: APNs/FCM push register + upload.
#[cfg(any(target_os = "ios", target_os = "android"))]
mod push;

use std::sync::Arc;

use tauri::{generate_handler, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder, WindowEvent};

// One shell-owned command list expands both the production Tauri dispatcher
// and the test-visible projection. Platform cfg attributes stay on the list
// items so both consumers see the same target-specific surface.
macro_rules! with_native_commands {
    ($consumer:ident) => {
        $consumer![
            bridge::vault_unlock,
            bridge::vault_is_unlocked,
            bridge::vault_list_totp,
            bridge::vault_generate_totp,
            bridge::notify,
            bridge::pick_file,
            bridge::open_external,
            bridge::secure_store_get,
            bridge::secure_store_set,
            bridge::secure_store_remove,
            bridge::db_open,
            bridge::db_is_open,
            bridge::db_exec,
            bridge::db_query,
            bridge::db_wipe,
            bridge::recovery_blob_write_begin,
            bridge::recovery_blob_write_chunk,
            bridge::recovery_blob_write_commit,
            bridge::recovery_blob_write_abort,
            bridge::recovery_blob_read_open,
            bridge::recovery_blob_read_chunk,
            bridge::recovery_blob_read_close,
            bridge::recovery_blob_ref,
            bridge::recovery_blob_unref,
            mam::mam_enroll,
            mam::mam_checkin,
            mam::mam_get_policy,
            mam::mam_is_wiped,
            mam::device_proof,
            mam::mam_set_surface_route,
            #[cfg(any(target_os = "ios", target_os = "android"))]
            bridge::biometric_unlock,
            #[cfg(any(target_os = "ios", target_os = "android"))]
            bridge::biometric_status,
            #[cfg(any(target_os = "ios", target_os = "android"))]
            bridge::share,
            #[cfg(any(target_os = "ios", target_os = "android"))]
            bridge::push_register,
            #[cfg(feature = "mobile-e2e-probe")]
            bridge::e2e_probe_report,
        ]
    };
}

#[cfg(test)]
macro_rules! project_command_names {
    ($( $(#[$meta:meta])* $command:path ),* $(,)?) => {
        &[
            $(
                $(#[$meta])*
                stringify!($command),
            )*
        ]
    };
}

#[cfg(test)]
pub(crate) const REGISTERED_NATIVE_COMMANDS: &[&str] = with_native_commands!(project_command_names);

#[cfg_attr(
    any(target_os = "ios", target_os = "android"),
    tauri::mobile_entry_point
)]
pub fn run() {
    #[allow(unused_mut)]
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_deep_link::init());

    // C2 cfg(mobile) — target-checked post-init: biometric + native share
    // plugins, registered only on the mobile targets. Desktop never links them.
    #[cfg(any(target_os = "ios", target_os = "android"))]
    {
        builder = builder
            .plugin(tauri_plugin_biometric::init())
            .plugin(tauri_plugin_share::init());
    }

    builder
        // One native capability generation: guard + lazy offline engine.
        .manage(bridge::CapabilityState::default())
        // MAM device-trust lifecycle state (last-seen policy version).
        .manage(mam::MamState::default())
        .invoke_handler(with_native_commands!(generate_handler))
        .setup(|app| {
            let owner_app = app.handle().clone();
            app.manage(mam_lifecycle_owner::MamLifecycleOwner::new(
                mam_lifecycle_owner::DEFAULT_MAM_ROLLOUT_MODE,
                Arc::new(move |done| {
                    let checkin_app = owner_app.clone();
                    tauri::async_runtime::spawn(async move {
                        let vault = checkin_app.state::<bridge::CapabilityState>();
                        let mam_state = checkin_app.state::<mam::MamState>();
                        if let Err(error) =
                            mam::mam_checkin(checkin_app.clone(), vault, mam_state).await
                        {
                            eprintln!("mam lifecycle check-in failed: {error}");
                        }
                        done();
                    });
                }),
            ));

            // Build the main window in Rust so the bridge init script runs
            // before the webmail loads (defining window.setjoinNative ahead of
            // first paint). The window is no longer declared in tauri.conf.json.
            #[allow(unused_mut)]
            let mut window_builder = WebviewWindowBuilder::new(app, "main", WebviewUrl::default())
                .title("SetJoin")
                .initialization_script(crate::bridge_js::bridge_init_js());

            // Queue B #6 mobile-runtime e2e harness only — a second init
            // script that self-drives the offline-core round trip and reports
            // the result to disk. Never present in a shipped build.
            #[cfg(feature = "mobile-e2e-probe")]
            {
                window_builder =
                    window_builder.initialization_script(crate::bridge_js::e2e_probe_js());
            }

            let window = window_builder.build()?;

            // Desktop window chrome (transparent titlebar / Mica-Acrylic / Linux
            // blur) was removed — desktop went Electron (ARCH-013), this Tauri
            // window is mobile-only and packaged nowhere on desktop.
            let _ = &window;

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error building SetJoin mobile shell")
        .run(|app, event| {
            let owner = app.state::<mam_lifecycle_owner::MamLifecycleOwner>();
            match event {
                RunEvent::Ready => owner.start(),
                RunEvent::Resumed => owner.resume(),
                RunEvent::WindowEvent {
                    event: WindowEvent::Focused(false),
                    ..
                } => owner.pause(),
                RunEvent::WindowEvent {
                    event: WindowEvent::Focused(true),
                    ..
                } => owner.resume(),
                #[cfg(mobile)]
                RunEvent::WindowEvent {
                    event: WindowEvent::Suspended,
                    ..
                } => owner.pause(),
                #[cfg(mobile)]
                RunEvent::WindowEvent {
                    event: WindowEvent::Resumed,
                    ..
                } => owner.resume(),
                RunEvent::Exit => owner.stop(),
                _ => {}
            }
        });
}
