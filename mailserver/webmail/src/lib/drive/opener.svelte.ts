// opener.svelte.ts — the R4 SecureOpener seam (spec §8.1). ONE impl in v1;
// Windows-Sandbox / customer-VDI integrations plug in here later. Do NOT add
// a second impl in v1.
//
// Unlike a native shell, this codebase has no imperative "mount a component"
// convention — every dialog/sheet is state-driven from its host component
// (Dialog/MembersSheet/SelectiveSyncSheet, …). So `inAppRenderer` holds
// reactive state a host component watches and renders <SecureViewer> against,
// rather than mounting one itself. DriveApp.svelte is that host: VersionDrawer's
// secure/gxp "View" action calls `inAppRenderer.open(...)`.
import type { DriveManifest } from '$lib/native/types';

export interface VersionMeta {
	versionId: number;
	name: string;
	contentType: string | null;
	size: number;
	classification: 'regular' | 'secure' | 'gxp';
	/** DriveVersion.previewStatus (api.ts) — 'none' | 'pending' | 'ready' | 'failed' | 'unsupported'. */
	previewStatus: string;
}

export type ContentSource =
	| { kind: 'online' } // regular original or server-generated protected rendition
	| { kind: 'vault'; manifest: DriveManifest }; // offline: chunks already local

export interface SecureOpener {
	canOpen(v: VersionMeta): boolean;
	open(v: VersionMeta, source: ContentSource): void;
	close(): void;
}

class SecureOpenerState implements SecureOpener {
	current = $state<{ version: VersionMeta; source: ContentSource } | null>(null);

	/** Every type has at least the metadata-card fallback — always openable. */
	canOpen(_v: VersionMeta): boolean {
		return true;
	}

	open(version: VersionMeta, source: ContentSource): void {
		this.current = { version, source };
	}

	close(): void {
		this.current = null;
	}
}

export const inAppRenderer = new SecureOpenerState();
