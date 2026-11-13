import type { SetjoinNativeBridge, NativeCapability } from './types';
import { BRIDGE_VERSION } from './types';
import { webFallbacks } from './fallbacks';

/**
 * Contract check for an injected shell bridge (SJ-NATIVE-BRIDGE-UNVALIDATED-
 * INJECTION hardening): the directory's versioning contract says a shell bumps
 * `BRIDGE_VERSION` on any breaking change, so the webmail asserts the version
 * it was compiled against plus the minimal top-level shape (a capability list
 * to gate `hasCapability()` on). A bridge that DECLARES a different version
 * fails closed to the web fallbacks — it must not be mis-called. Bridges that
 * predate the whole-bridge version field are tolerated: each sub-shape
 * (vault/driveMirror) carries and checks its own independent version at its
 * call site.
 */
function isCompatibleBridge(bridge: unknown): bridge is SetjoinNativeBridge {
	if (typeof bridge !== 'object' || bridge === null) return false;
	const b = bridge as { version?: unknown; capabilities?: unknown };
	return (
		(b.version === undefined || b.version === BRIDGE_VERSION) &&
		Array.isArray(b.capabilities)
	);
}

/** The active bridge: the injected shell bridge if present and contract-valid, else the web fallbacks. */
export function getNative(): SetjoinNativeBridge {
	const injected = typeof window !== 'undefined' ? window.setjoinNative : undefined;
	return injected && isCompatibleBridge(injected) ? injected : webFallbacks;
}

/** True only when a real native shell injected a contract-valid bridge. */
export function isNative(): boolean {
	return typeof window !== 'undefined' && isCompatibleBridge(window.setjoinNative);
}

/** Whether the active bridge advertises a capability (always check before using a native-only feature). */
export function hasCapability(cap: NativeCapability): boolean {
	return getNative().capabilities.includes(cap);
}

export type { SetjoinNativeBridge, NativeCapability } from './types';
export { BRIDGE_VERSION, NATIVE_CAPABILITIES, NATIVE_DB_APP_KEYS } from './types';
export type { NativeDbAppKey } from './types';
