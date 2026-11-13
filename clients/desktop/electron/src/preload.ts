//! Preload: expose `window.setjoinNative` via contextBridge over ipcRenderer.
//! Runs in the isolated preload context (contextIsolation:true, sandbox:true).
//! The bridge shape lives in `bridge.ts` (electron-free, unit-tested); this file
//! is only the electron wiring + the ready-event dispatch.

import { contextBridge, ipcRenderer } from 'electron';
import { buildBridge } from './bridge';
import { connectivityBridgeModeFor } from './connectivity/rollout';

const invoke = (channel: string, ...args: unknown[]): Promise<unknown> =>
	ipcRenderer.invoke(channel, ...args);

// Harness-only connectivity seam (see rollout.ts): under the E6 mode env the
// bridge carries the instance's rollout mode so the composed webmail
// coordinator (lib/offline/boot.ts) can gate on the pair member's flag delta.
// Unset in every production launch → null → the bridge gains NO new field.
const harnessConnectivity = connectivityBridgeModeFor(process.env);
const bridge: Record<string, unknown> = buildBridge(invoke);
if (harnessConnectivity !== null) bridge.connectivity = harnessConnectivity;

contextBridge.exposeInMainWorld('setjoinNative', bridge);

// Signal the webmail facade that the native shell is present.
window.dispatchEvent(new Event('setjoin-native-ready'));
