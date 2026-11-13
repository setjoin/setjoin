//! Secure store handlers (vault-backed encrypted key/value). Ported 1:1 from
//! Tauri `bridge.rs`: secure_store_get / secure_store_set / secure_store_remove.
//! `get` returns null when locked/absent; set/remove require an unlocked vault
//! (the native module raises when locked).
//!
//! Namespace confinement (deep-scan package desktop-drive-bridge-unconfined):
//! these handlers are the RENDERER's only secure-store surface, and while the
//! vault is unlocked a renderer-supplied key used to read/write any value in
//! the flat `ss:` namespace — including the MAM device-proof enrolment secrets
//! (`mam:hmac_secret`/`mam:device_id`/`mam:server_url`, written here only by
//! main-process `mam.ts`). Reserved namespaces are therefore NATIVE-HOST
//! only: renderer calls naming one are denied before the native invoke. The
//! native module itself cannot enforce this (the same exports legitimately
//! carry `mam:*` for `mam.ts`), so this handler — plus the ArkTS twin in
//! `BridgeProxy.ets` — IS the renderer boundary. Re-enrollment does NOT rotate
//! the stored secret (authserver `identity.go` ON CONFLICT preserves it), so a
//! renderer read of `mam:hmac_secret` would impersonate the device's proof
//! indefinitely — hence the hard denial.
//!
//! `meet-capture:` (MEET M5 slice 2) joins the same boundary: the Electron
//! local-capture composition (`src/meet/localCapture.ts`) keeps consent
//! records and the capture device id there, and a renderer able to write
//! `meet-capture:consent` could grant itself recording consent past the
//! non-dismissible consent machine. The Meet substrate has no ArkTS carrier
//! yet, so `BridgeProxy.ets` denies `mam:*` and `meet-capture:*` until one lands
//! (named in the clients DOX row).

import type { NativeBinding } from '../native';
import type { HandlerMap } from './db';

/** Key prefixes under these namespaces are native-host-only (main-process
 * state the renderer must never read or write). */
const RENDERER_DENIED_PREFIXES = ['mam:', 'meet-capture:'] as const;

/** Throws when a renderer-supplied secure-store key names a reserved namespace. */
export function assertSecureStoreKeyRendererAllowed(key: string): void {
	for (const prefix of RENDERER_DENIED_PREFIXES) {
		if (key.startsWith(prefix)) {
			throw new Error(
				`secure_store: keys under '${prefix}' are native-host-only and not renderer-accessible`,
			);
		}
	}
}

export function makeSecureStoreHandlers(native: NativeBinding): HandlerMap {
	return {
		secure_store_get: (key: unknown) => {
			assertSecureStoreKeyRendererAllowed(String(key));
			return native.secureStoreGet(String(key));
		},
		secure_store_set: (key: unknown, value: unknown) => {
			assertSecureStoreKeyRendererAllowed(String(key));
			return native.secureStoreSet(String(key), String(value));
		},
		secure_store_remove: (key: unknown) => {
			assertSecureStoreKeyRendererAllowed(String(key));
			return native.secureStoreRemove(String(key));
		},
	} as HandlerMap;
}
