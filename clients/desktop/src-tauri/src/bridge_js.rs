//! The `window.setjoinNative` provider, injected into the webview before page
//! load via the window's `initialization_script`.
//!
//! This JS defines an object whose shape MUST match `SetjoinNativeBridge` in
//! `mailserver/webmail/src/lib/native/types.ts`. Each method `invoke()`s the
//! matching `#[tauri::command]` in `bridge.rs`. The `capabilities` array is
//! rendered from [`bridge::DESKTOP_CAPABILITIES`] so there is one source of
//! truth (and the C0 parity test guards it).

use crate::bridge::DESKTOP_CAPABILITIES;

/// Render the advertised capabilities as a JS array literal, e.g.
/// `["secureStore","vault",...]`, sourced from [`DESKTOP_CAPABILITIES`].
fn capabilities_js_array() -> String {
    let items: Vec<String> = DESKTOP_CAPABILITIES
        .iter()
        .map(|c| format!("'{c}'"))
        .collect();
    format!("[{}]", items.join(", "))
}

/// Build the init script injected before first paint. Defines
/// `window.setjoinNative` and fires a `setjoin-native-ready` event so the
/// webmail facade can detect the shell. The capabilities array is filled in
/// from [`DESKTOP_CAPABILITIES`] so Rust is the single source of truth.
///
/// The `push` / `biometric` / `share` method bodies are `#[cfg]`-selected: the
/// mobile build wires them to real `invoke()`s of the mobile-only commands
/// (`push_register`, `biometric_unlock`, `share`); the desktop build keeps the
/// honest "unavailable" answers (push → null, biometric → false) and the
/// mailto share fallback.
pub fn bridge_init_js() -> String {
    BRIDGE_INIT_JS_TEMPLATE
        .replace("__CAPABILITIES__", &capabilities_js_array())
        .replace("__PUSH_REGISTER__", PUSH_REGISTER_JS)
        .replace("__BIOMETRIC_UNLOCK__", BIOMETRIC_UNLOCK_JS)
        .replace("__SHARE__", SHARE_JS)
        .replace("__VAULT_IS_ENROLLED__", VAULT_IS_ENROLLED_JS)
        .replace("__VAULT_VERSION__", &VAULT_VERSION.to_string())
        .replace("__SURFACE_ROUTE_WATCHER__", SURFACE_ROUTE_WATCHER_JS)
}

/// `window.setjoinNative.vault`'s own sub-shape version (C2 Task 2 Step 3b),
/// independent of the whole-bridge `version` above — mirrors
/// `mailserver/webmail/src/lib/native/types.ts` VAULT_VERSION and the
/// Electron `bridge.ts` VAULT_VERSION. Bump in lock-step with a vault contract
/// change.
const VAULT_VERSION: u32 = 1;

// ── cfg-selected mobile vs desktop method bodies ────────────────────────────
//
// C2 cfg(mobile) — target-checked post-init: the mobile bodies invoke the
// mobile-only commands; desktop keeps the honest unavailable / mailto answers.

#[cfg(any(target_os = "ios", target_os = "android"))]
const PUSH_REGISTER_JS: &str = "async pushRegister() { return invoke('push_register'); }";
#[cfg(not(any(target_os = "ios", target_os = "android")))]
const PUSH_REGISTER_JS: &str = "async pushRegister() { return null; }";

#[cfg(any(target_os = "ios", target_os = "android"))]
const BIOMETRIC_UNLOCK_JS: &str =
    "async biometricUnlock(reason) { return invoke('biometric_unlock', { reason }); }";
#[cfg(not(any(target_os = "ios", target_os = "android")))]
const BIOMETRIC_UNLOCK_JS: &str = "async biometricUnlock(_reason) { return false; }";

#[cfg(any(target_os = "ios", target_os = "android"))]
const SHARE_JS: &str = "share: (payload) => invoke('share', { path: payload && payload.path, mime: payload && payload.mime })";
#[cfg(not(any(target_os = "ios", target_os = "android")))]
const SHARE_JS: &str = "share: (payload) => {\n      const text = [payload && payload.text, payload && payload.url].filter(Boolean).join(' ');\n      const subject = (payload && payload.title) || '';\n      const url = 'mailto:?subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(text);\n      return invoke('open_external', { url });\n    }";

/// `vault.isEnrolled()` — real on mobile (device biometric hardware + enrollment,
/// via `biometric_status`); honest `false` on desktop (no platform biometric API).
#[cfg(any(target_os = "ios", target_os = "android"))]
const VAULT_IS_ENROLLED_JS: &str = "isEnrolled: () => invoke('biometric_status')";
#[cfg(not(any(target_os = "ios", target_os = "android")))]
const VAULT_IS_ENROLLED_JS: &str = "isEnrolled: async () => false";

/// DESKTOP-007, Android build only: a document-start watcher that reports every
/// webmail route transition to `mam_set_surface_route`, so the activity window
/// carries `FLAG_SECURE` exactly while message content is on screen (chat
/// conversations, email bodies) and clears it on non-sensitive screens unless
/// the MAM policy blocks capture. The path is forwarded verbatim — the
/// sensitivity classification is Rust-owned (`mam_lifecycle::classify_surface`)
/// so every shell tests one decision table. SvelteKit is a path-based SPA:
/// `pushState`/`replaceState` are property-looked-up at call time, so patching
/// them intercepts client-side navigation; `popstate` covers back/forward.
#[cfg(target_os = "android")]
const SURFACE_ROUTE_WATCHER_JS: &str = r#"
(() => {
  const invoke = window.__TAURI__.core.invoke;
  let lastPath = null;
  function reportSurfaceRoute() {
    const path = location.pathname;
    if (path === lastPath) return;
    lastPath = path;
    // DESKTOP-007 r2: the command rejects when a REQUIRED FLAG_SECURE could
    // not be applied (surface NOT protected). Navigation must never break on
    // it, but the failure is not swallowed — it lands in the device log.
    // DESKTOP-007 r3: the rejection must not poison this path's dedupe —
    // reset lastPath so a later report of the SAME path (query-only
    // navigation, hash change) is not suppressed as already-reported and
    // re-drives the protection instead of leaving it pending forever.
    invoke('mam_set_surface_route', { route: path }).catch((e) => {
      lastPath = null;
      console.warn('mam_set_surface_route: FLAG_SECURE not applied:', e);
    });
  }
  for (const name of ['pushState', 'replaceState']) {
    const original = history[name].bind(history);
    history[name] = function () {
      const result = original.apply(null, arguments);
      reportSurfaceRoute();
      return result;
    };
  }
  window.addEventListener('popstate', reportSurfaceRoute);
  reportSurfaceRoute();
})();
"#;

/// Desktop/iOS: no route-driven FLAG_SECURE (desktop ships no capture-block
/// API; iOS keeps the policy-level secure overlay).
#[cfg(not(target_os = "android"))]
const SURFACE_ROUTE_WATCHER_JS: &str = "";

const BRIDGE_INIT_JS_TEMPLATE: &str = r#"
(() => {
  const invoke = window.__TAURI__.core.invoke;

  async function pathToFile(path) {
    if (!path) return null;
    // Read the picked file via Tauri's asset protocol so the bridge can hand
    // the webmail a real File (the SetjoinNativeBridge.pickFile contract).
    try {
      const url = window.__TAURI__.core.convertFileSrc(path);
      const res = await fetch(url);
      const blob = await res.blob();
      const name = path.split(/[\\/]/).pop() || 'file';
      return new File([blob], name, { type: blob.type });
    } catch (_e) {
      return null;
    }
  }

  window.setjoinNative = {
    version: 1,
    capabilities: __CAPABILITIES__,

    // push / biometric are cfg-selected (desktop: honest unavailable; mobile:
    // real invoke of push_register / biometric_unlock).
    __PUSH_REGISTER__,
    // Push-MFA ECDH key registration: null until APNs/FCM token capture lands
    // (device-gated stub, push.rs) — the SPA glue skips registration when
    // pushRegister() is null anyway, so nothing depends on this yet on Tauri.
    async pushDevicePublicKey() { return null; },
    __BIOMETRIC_UNLOCK__,

    secureStore: {
      get: (key) => invoke('secure_store_get', { key }),
      set: (key, value) => invoke('secure_store_set', { key, value }),
      remove: (key) => invoke('secure_store_remove', { key }),
    },

    vault: {
      version: __VAULT_VERSION__,
      unlock: (passphrase) => invoke('vault_unlock', { passphrase }),
      isUnlocked: () => invoke('vault_is_unlocked'),
      listTotp: () => invoke('vault_list_totp'),
      generateTotp: (id) => invoke('vault_generate_totp', { id }),
      // Closed drift (C2 Task 2 Step 3b): unlockPassphrase aliases unlock (same
      // as Electron's closure of this gap); isEnrolled is real on mobile,
      // honest false on desktop; unlockBiometric stays honest false on EVERY
      // platform — biometric_unlock only gates the OS prompt, there is no
      // hardware-wrapped-key release path yet (ARCH-015 custody design is not
      // wired into guard-core), so claiming success here would unlock nothing.
      unlockPassphrase: (passphrase) => invoke('vault_unlock', { passphrase }),
      unlockBiometric: async () => false,
      __VAULT_IS_ENROLLED__,
    },

    __SHARE__,

    pickFile: async (_accept) => {
      const path = await invoke('pick_file');
      return pathToFile(path);
    },

    notify: (payload) => invoke('notify', { title: payload.title, body: payload.body }),

    openExternal: (url) => invoke('open_external', { url }),

    db: {
      open:   (appKey, profile)           => invoke('db_open',    { appKey, profile: profile ?? 'standard' }),
      isOpen: (appKey)                    => invoke('db_is_open', { appKey }),
      exec:   (appKey, sql, params = []) => invoke('db_exec',   { appKey, sql, params }),
      query:  (appKey, sql, params = []) => invoke('db_query',  { appKey, sql, params }).then(JSON.parse),
      wipe:   (appKey)                    => invoke('db_wipe',   { appKey }),
    },

    recoveryBlob: {
      writeBegin: (sha256, size) => invoke('recovery_blob_write_begin', { sha256, size }).then(JSON.parse),
      writeChunk: (handle, offset, bytes) => invoke('recovery_blob_write_chunk', { handle, offset, bytes: Array.from(bytes) }),
      writeCommit: (handle) => invoke('recovery_blob_write_commit', { handle }),
      writeAbort: (handle) => invoke('recovery_blob_write_abort', { handle }),
      readOpen: (sha256) => invoke('recovery_blob_read_open', { sha256 }).then(JSON.parse),
      readChunk: (handle, offset, length) => invoke('recovery_blob_read_chunk', { handle, offset, length }).then((v) => new Uint8Array(v)),
      readClose: (handle) => invoke('recovery_blob_read_close', { handle }),
      ref: (sha256) => invoke('recovery_blob_ref', { sha256 }),
      unref: (sha256) => invoke('recovery_blob_unref', { sha256 }),
    },

    // HMAC secret is native-side only — JS receives { hmac } or null, never the secret.
    deviceProof: ({ deviceId, timestamp }) => invoke('device_proof', { deviceId, timestamp }),
  };

  // DESKTOP-007 (Android only): route watcher driving the FLAG_SECURE window
  // flag — empty substitution elsewhere.
  __SURFACE_ROUTE_WATCHER__

  window.dispatchEvent(new Event('setjoin-native-ready'));
})();
"#;

/// Queue B #6 mobile-runtime e2e harness only (feature `mobile-e2e-probe`,
/// never in a shipped build). Injected as a second `initialization_script`
/// alongside [`bridge_init_js`]. Runs the offline-core database round trip and
/// a two-launch recovery-blob write/resume/read cycle once
/// `setjoin-native-ready` fires. The first launch durably writes one bounded
/// chunk and reports `restart-required`; the harness terminates and relaunches
/// the app, and the second launch must resume at the acknowledged offset before
/// it can report `complete`. Results go through `e2e_probe_report` so
/// `clients/desktop/scripts/mobile-e2e.sh` can retain them off-device. The
/// final launch renders an on-screen PASS/FAIL banner (mirrors the C2 Task 1
/// `ping` probe's evidence pattern, but permanent + gated).
#[cfg(feature = "mobile-e2e-probe")]
pub fn e2e_probe_js() -> &'static str {
    r#"
(() => {
  const invoke = window.__TAURI__.core.invoke;
  // 'mail' is the only appKey the native db_open allowlist accepts today
  // (bridge.rs::store_db_path) — the same store the real offline-mail feature
  // uses, so this probe exercises the actual production path, not a synthetic
  // one. The table name is namespaced so it can't collide with real mail-sync
  // schema objects.
  const APP = 'mail';
  const RECOVERY_BYTES = new Uint8Array([83, 69, 84, 74, 79, 73, 78, 45, 82, 69, 67, 79, 86, 69, 82, 89]);
  const RECOVERY_SHA256 = '36ae8e20022d3205ab9e8ace9c4c7ed1fb977bc95cf2cf18eb0d78974df3868d';
  const RECOVERY_SPLIT = 7;

  async function runProbe() {
    const steps = [];
    let ok = true;
    let error = null;
    try {
      steps.push('vault.unlock');
      const unlocked = await window.setjoinNative.vault.unlock('sj-e2e-probe-passphrase');
      if (!unlocked) throw new Error('vault.unlock returned false');
      steps.push('db.open');
      await window.setjoinNative.db.open(APP, 'standard');
      steps.push('recoveryBlob.writeBegin');
      const begun = await window.setjoinNative.recoveryBlob.writeBegin(RECOVERY_SHA256, RECOVERY_BYTES.length);
      if (begun.nextOffset === 0) {
        const acknowledged = await window.setjoinNative.recoveryBlob.writeChunk(
          begun.handle,
          0,
          RECOVERY_BYTES.slice(0, RECOVERY_SPLIT),
        );
        if (acknowledged !== RECOVERY_SPLIT) {
          throw new Error('first recovery chunk acknowledged unexpected offset ' + acknowledged);
        }
        steps.push('recoveryBlob.partial-write:' + acknowledged);
        await invoke('e2e_probe_report', {
          msg: JSON.stringify({ ok: true, phase: 'restart-required', steps, error: null }),
        });
        return;
      }
      if (begun.nextOffset !== RECOVERY_SPLIT) {
        throw new Error('recovery write resumed at unexpected offset ' + begun.nextOffset);
      }
      steps.push('recoveryBlob.resume:' + begun.nextOffset);
      const completeOffset = await window.setjoinNative.recoveryBlob.writeChunk(
        begun.handle,
        begun.nextOffset,
        RECOVERY_BYTES.slice(begun.nextOffset),
      );
      if (completeOffset !== RECOVERY_BYTES.length) {
        throw new Error('resumed recovery chunk acknowledged unexpected offset ' + completeOffset);
      }
      steps.push('recoveryBlob.writeCommit');
      const committed = await window.setjoinNative.recoveryBlob.writeCommit(begun.handle);
      if (committed !== RECOVERY_SHA256) throw new Error('recovery commit hash mismatch');
      steps.push('recoveryBlob.readOpen');
      const opened = await window.setjoinNative.recoveryBlob.readOpen(RECOVERY_SHA256);
      if (opened.size !== RECOVERY_BYTES.length) throw new Error('recovery read size mismatch');
      const recovered = await window.setjoinNative.recoveryBlob.readChunk(opened.handle, 0, RECOVERY_BYTES.length);
      await window.setjoinNative.recoveryBlob.readClose(opened.handle);
      if (recovered.length !== RECOVERY_BYTES.length ||
          recovered.some((byte, index) => byte !== RECOVERY_BYTES[index])) {
        throw new Error('recovery read bytes mismatch');
      }
      steps.push('recoveryBlob.restart-read');
      const refs = await window.setjoinNative.recoveryBlob.ref(RECOVERY_SHA256);
      if (refs !== 1) throw new Error('recovery refcount did not become 1');
      const remaining = await window.setjoinNative.recoveryBlob.unref(RECOVERY_SHA256);
      if (remaining !== 0) throw new Error('recovery refcount did not return to 0');
      steps.push('db.exec:create');
      await window.setjoinNative.db.exec(APP, 'CREATE TABLE IF NOT EXISTS _e2e_probe (id INTEGER PRIMARY KEY, v TEXT)', []);
      steps.push('db.exec:insert');
      await window.setjoinNative.db.exec(APP, 'INSERT INTO _e2e_probe (v) VALUES (?)', ['probe']);
      steps.push('db.query');
      const rows = await window.setjoinNative.db.query(APP, 'SELECT * FROM _e2e_probe', []);
      if (!Array.isArray(rows) || rows.length !== 1 || rows[0].v !== 'probe') {
        throw new Error('query mismatch: ' + JSON.stringify(rows));
      }
      steps.push('db.exec:drop');
      await window.setjoinNative.db.exec(APP, 'DROP TABLE _e2e_probe', []);
      steps.push('db.wipe');
      await window.setjoinNative.db.wipe(APP);
      steps.push('db.isOpen-after-wipe');
      const stillOpen = await window.setjoinNative.db.isOpen(APP);
      if (stillOpen) throw new Error('store still open after wipe');
    } catch (e) {
      ok = false;
      error = String((e && e.message) || e);
    }

    // Native readiness and application readiness are separate gates. The DB
    // round trip can finish while Svelte is still showing its loading spinner;
    // wait boundedly for a real unauthenticated application surface so PASS
    // means both layers work. With no gateway attached, the intentional
    // fail-loud surface is the auth-unavailable page rather than the login form.
    const visualDeadline = Date.now() + 15000;
    const applicationSurface = () =>
      document.querySelector('.sj-login-page') || document.querySelector('.sj-auth-unavailable');
    while (!applicationSurface() && Date.now() < visualDeadline) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    if (!applicationSurface()) {
      ok = false;
      error = error || 'unauthenticated application surface did not render within 15s';
    }

    // Diagnostic snapshot of the loaded page — independent of the db probe's
    // outcome, so a blank-looking WebView can be told apart from a broken
    // bridge (queue-B #6: this surfaced a real blank-page investigation).
    const loginPage = document.querySelector('.sj-login-page');
    const loginTitle = document.querySelector('.sj-login-title');
    const unavailablePage = document.querySelector('.sj-auth-unavailable');
    const unavailableTitle = unavailablePage && unavailablePage.querySelector('h1');
    const elementDiag = (element) => {
      if (!element) return null;
      const rect = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      return {
        text: element.textContent.slice(0, 80),
        rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
        display: style.display,
        visibility: style.visibility,
        opacity: style.opacity,
        color: style.color,
        background: style.backgroundColor,
      };
    };
    const pageDiag = {
      href: location.href,
      title: document.title,
      bodyChildren: document.body ? document.body.children.length : -1,
      bodyTextLen: document.body ? document.body.textContent.length : -1,
      bodyText: document.body ? document.body.innerText.slice(0, 240) : '',
      shellKind: loginPage ? 'login' : (unavailablePage ? 'auth-unavailable' : null),
      shell: elementDiag(loginPage || unavailablePage),
      shellTitle: elementDiag(loginTitle || unavailableTitle),
      loginPage: elementDiag(loginPage),
      loginTitle: elementDiag(loginTitle),
      htmlSnippet: document.documentElement.outerHTML.slice(0, 400),
    };

    const render = () => {
      const banner = document.createElement('div');
      banner.id = 'sj-e2e-banner';
      banner.textContent = ok ? 'SETJOIN_E2E: PASS' : ('SETJOIN_E2E: FAIL ' + error);
      banner.style.cssText =
        'position:fixed;top:max(env(safe-area-inset-top), 24px);left:0;right:0;z-index:999999;padding:8px;' +
        'font:14px monospace;color:#fff;text-align:center;' +
        'background:' + (ok ? '#0a0' : '#a00') + ';';
      document.body.appendChild(banner);
    };
    if (document.body) render();
    else {
      await new Promise((resolve) => {
        window.addEventListener('DOMContentLoaded', () => { render(); resolve(); }, { once: true });
      });
    }

    // The result file is the harness's screenshot trigger. Report only after
    // the banner and app body have crossed two animation frames; reporting
    // first raced iOS simctl, which repeatedly captured a blank WKWebView even
    // though the DOM and native database probe were healthy.
    await new Promise((resolve) => {
      requestAnimationFrame(() => requestAnimationFrame(resolve));
    });

    const result = { ok, phase: 'complete', steps, error, pageDiag };
    try {
      await invoke('e2e_probe_report', { msg: JSON.stringify(result) });
    } catch (_e) {
      // best-effort — the on-screen banner is the fallback evidence channel.
    }
  }

  // `bridge_init_js()` is a separate, earlier initialization_script that
  // defines window.setjoinNative and dispatches 'setjoin-native-ready'
  // synchronously at its own end — by document-start ordering it has already
  // run (and the event already fired) by the time this script executes, so
  // listening for the event alone would miss it. Check readiness directly
  // first; only fall back to the listener if this script somehow runs first.
  if (window.setjoinNative) {
    void runProbe();
  } else {
    window.addEventListener('setjoin-native-ready', () => { void runProbe(); }, { once: true });
  }
})();
"#
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::REGISTERED_NATIVE_COMMANDS;

    fn invoked_commands(js: &str) -> Vec<&str> {
        let mut commands = Vec::new();
        let mut rest = js;
        while let Some(at) = rest.find("invoke('") {
            rest = &rest[at + "invoke('".len()..];
            let end = rest
                .find('\'')
                .expect("bridge invoke command string must have a closing quote");
            commands.push(&rest[..end]);
            rest = &rest[end + 1..];
        }
        commands.sort_unstable();
        commands.dedup();
        commands
    }

    #[test]
    fn native_contract_dispatch_projection_matches_generate_handler() {
        let registered: std::collections::BTreeSet<&str> = REGISTERED_NATIVE_COMMANDS
            .iter()
            .map(|qualified| qualified.rsplit("::").next().unwrap_or(qualified).trim())
            .collect();
        for invoked in invoked_commands(&bridge_init_js()) {
            assert!(
                registered.contains(invoked),
                "rendered bridge invokes unregistered native command {invoked:?}; \
                 with_native_commands! is the generate_handler! authority; registered={registered:?}"
            );
        }
    }

    /// Every command name the JS invokes must be a registered handler. This is
    /// a cheap guard against a rename drifting one side out of sync.
    #[test]
    fn bridge_js_invokes_known_commands() {
        let js = bridge_init_js();
        for cmd in [
            "secure_store_get",
            "secure_store_set",
            "secure_store_remove",
            "vault_unlock",
            "vault_is_unlocked",
            "vault_list_totp",
            "vault_generate_totp",
            "open_external",
            "pick_file",
            "notify",
            "db_open",
            "db_is_open",
            "db_exec",
            "db_query",
            "db_wipe",
            "recovery_blob_write_begin",
            "recovery_blob_write_chunk",
            "recovery_blob_write_commit",
            "recovery_blob_write_abort",
            "recovery_blob_read_open",
            "recovery_blob_read_chunk",
            "recovery_blob_read_close",
            "recovery_blob_ref",
            "recovery_blob_unref",
            "device_proof",
        ] {
            assert!(
                js.contains(&format!("'{cmd}'")),
                "bridge_init_js() is missing an invoke('{cmd}')"
            );
        }
    }

    /// The advertised capabilities array in JS must list DESKTOP_CAPABILITIES.
    #[test]
    fn bridge_js_capabilities_match_rust() {
        let js = bridge_init_js();
        for cap in DESKTOP_CAPABILITIES {
            assert!(
                js.contains(&format!("'{cap}'")),
                "bridge_init_js() capabilities array is missing {cap:?}"
            );
        }
        // The placeholder must have been substituted.
        assert!(
            !js.contains("__CAPABILITIES__"),
            "capabilities placeholder was not substituted"
        );
    }

    /// The bridge must define every SetjoinNativeBridge method by name.
    #[test]
    fn bridge_js_defines_contract_methods() {
        let js = bridge_init_js();
        for member in [
            "version",
            "capabilities",
            "pushRegister",
            "pushDevicePublicKey",
            "biometricUnlock",
            "secureStore",
            "vault",
            "share",
            "pickFile",
            "notify",
            "openExternal",
            "db",
            "recoveryBlob",
            "deviceProof",
        ] {
            assert!(
                js.contains(member),
                "bridge_init_js() does not define `{member}`"
            );
        }
    }

    #[cfg(feature = "mobile-e2e-probe")]
    #[test]
    fn mobile_probe_requires_recovery_blob_restart_resume() {
        let js = e2e_probe_js();
        for required in [
            "phase: 'restart-required'",
            "recoveryBlob.partial-write:",
            "recoveryBlob.resume:",
            "recoveryBlob.restart-read",
            "phase: 'complete'",
        ] {
            assert!(
                js.contains(required),
                "mobile probe is missing {required:?}"
            );
        }
    }

    #[cfg(feature = "mobile-e2e-probe")]
    #[test]
    fn mobile_probe_accepts_the_two_valid_unauthenticated_surfaces() {
        let js = e2e_probe_js();
        for required in [
            ".sj-login-page",
            ".sj-auth-unavailable",
            "shellKind",
            "auth-unavailable",
        ] {
            assert!(
                js.contains(required),
                "mobile probe is missing application-surface contract {required:?}"
            );
        }
    }

    /// C2 Task 2 Step 3b: `vault` carries its own version + the full closed-drift
    /// member set (unlockPassphrase/unlockBiometric/isEnrolled), and no template
    /// placeholder survives substitution.
    #[test]
    fn bridge_js_vault_subshape_is_versioned_and_complete() {
        let js = bridge_init_js();
        assert!(js.contains(&format!("version: {VAULT_VERSION}")));
        for member in ["unlockPassphrase", "unlockBiometric", "isEnrolled"] {
            assert!(js.contains(member), "vault is missing `{member}`");
        }
        for placeholder in ["__VAULT_IS_ENROLLED__", "__VAULT_VERSION__"] {
            assert!(
                !js.contains(placeholder),
                "unsubstituted placeholder {placeholder} leaked into bridge_init_js()"
            );
        }
    }

    /// DESKTOP-007: the FLAG_SECURE route-watcher placeholder is always
    /// substituted, and outside the Android build the watcher is fully absent —
    /// no `mam_set_surface_route` invoke may survive where the command path is
    /// not enforced (desktop: no platform API; iOS: policy-level overlay only).
    #[test]
    fn bridge_js_surface_route_watcher_substituted_and_seamed() {
        let js = bridge_init_js();
        assert!(
            !js.contains("__SURFACE_ROUTE_WATCHER__"),
            "unsubstituted placeholder __SURFACE_ROUTE_WATCHER__ leaked into bridge_init_js()"
        );
        #[cfg(not(target_os = "android"))]
        assert!(
            !js.contains("mam_set_surface_route"),
            "route watcher must not ship outside the Android build"
        );
    }
}
