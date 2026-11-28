// deviceBlock.ts — reactive store for the CA-2 device-lockdown blocked state.
// Set by jmap/client.ts when a 403 BZ095 is received; consumed by +layout.svelte
// to navigate to /blocked. The ref (X-CA-Correlation-Id) is passed as ?ref=
// so the blocked page can surface it as a de-emphasised admin-aid reference.

import { writable } from 'svelte/store';

export interface DeviceBlockState {
	blocked: boolean;
	ref?: string;
}

// ponytail: plain writable; no complex reactive machinery needed here.
export const deviceBlock = writable<DeviceBlockState>({ blocked: false });
