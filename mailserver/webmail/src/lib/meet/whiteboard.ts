// whiteboard.ts — Meet B3 Task 9 (spec §4.4, DN5, F15). Excalidraw (MIT)
// embedded as a React chunk, loaded ONLY via a dynamic `import('$lib/meet/
// whiteboard')` from WhiteboardPanel.svelte — this file is the ONE place in
// the whole app that imports React/@excalidraw. Client-only, no server
// surface, no toggle (DN6): the board lives in memory and is lost when the
// meeting ends unless someone exports it to chat (design D2/D6/D9 — see
// WhiteboardPanel.svelte/ControlsBar.svelte/MeetApp.svelte for the entry
// point + main-stage composition this file doesn't own).
//
// Split in two halves on purpose (the task's own TDD split): the protocol
// glue below (cap enforcement, the version-diff broadcast filter, and
// wireRoomSync) is plain data-in/data-out logic, fully testable in jsdom
// with fake objects — no React, no canvas. Only `mountWhiteboard` itself
// touches React/Excalidraw and needs a real browser canvas, so it is
// deliberately left untested at the unit level here (mocked at this
// module's import seam by WhiteboardPanel.test.ts instead, per this
// project's own guidance for exactly this situation).
import { createRoot, type Root } from 'react-dom/client';
import { createElement } from 'react';
import { Excalidraw, exportToBlob, reconcileElements, CaptureUpdateAction } from '@excalidraw/excalidraw';
import '@excalidraw/excalidraw/index.css';
import type { ExcalidrawImperativeAPI } from '@excalidraw/excalidraw/types';
import type { OrderedExcalidrawElement } from '@excalidraw/excalidraw/element/types';
import type { RemoteExcalidrawElement } from '@excalidraw/excalidraw/data/reconcile';
import { t } from '$lib/i18n';

export type WhiteboardTheme = 'light' | 'dark';

/** F15: LiveKit reliable data caps a single frame at ~15KiB, and a full
 *  `wb_sync` answer must be chunked+reassembled (Task 6's WB_CHUNK_BYTES) —
 *  capping the scene keeps that reassembly bounded regardless of how long a
 *  meeting/board has been open. */
export const WB_ELEMENT_CAP = 1000;

export function isOverCap(elements: readonly unknown[]): boolean {
	return elements.length > WB_ELEMENT_CAP;
}

interface VersionedElement {
	id: string;
	version: number;
}

/** Broadcast filter: only elements whose `version` moved since the last
 *  broadcast are sent — Excalidraw's onChange fires on every pointer-move
 *  during a draw, and `{t:'wb', elements}` is documented as "changed
 *  elements only" (Task 6/spec §4.4), not a full-scene resend. A soft
 *  delete still shows up here (isDeleted:true bumps version like any other
 *  mutation), so deletes propagate correctly. */
export function diffChangedElements<T extends VersionedElement>(
	prevVersions: ReadonlyMap<string, number>,
	elements: readonly T[],
): T[] {
	return elements.filter((el) => prevVersions.get(el.id) !== el.version);
}

export function versionsOf<T extends VersionedElement>(elements: readonly T[]): Map<string, number> {
	return new Map(elements.map((el) => [el.id, el.version]));
}

/** The room.svelte.ts (Task 6) surface this file's sync glue drives —
 *  restated structurally here (not imported from room.svelte.ts) so this
 *  module's protocol logic stays testable against a plain fake, with zero
 *  compile-time dependency on the Svelte/LiveKit room class. */
export interface RoomWhiteboardOps {
	onWhiteboard(cb: (elements: unknown) => void): void;
	onWhiteboardRequest(cb: () => void): void;
	sendWhiteboard(elements: unknown): void;
	requestWhiteboardSync(): void;
	sendWhiteboardSync(elements: unknown): void;
}

export interface WhiteboardHandle {
	/** Merges an incoming `wb`/reassembled `wb_sync` payload via Excalidraw's
	 *  own version/versionNonce last-writer-wins reconciliation. */
	applyRemote(elements: unknown): void;
	getSceneElements(): unknown[];
	setTheme(theme: WhiteboardTheme): void;
	unmount(): void;
}

/** Wires a mounted whiteboard to the room's data-channel plane (Task 6's
 *  contract, exact names): incoming live deltas reconcile in; an incoming
 *  `wb_req` is answered with the full (chunked) scene; and — the late-
 *  joiner half — a `wb_req` is sent once on open so an existing board syncs
 *  in immediately rather than waiting for someone else's next edit. Plain
 *  function over a structural interface: testable with a fake room, no
 *  Svelte/LiveKit/React needed. */
export function wireRoomSync(room: RoomWhiteboardOps, handle: WhiteboardHandle): void {
	room.onWhiteboard((elements) => handle.applyRemote(elements));
	room.onWhiteboardRequest(() => room.sendWhiteboardSync(handle.getSceneElements()));
	room.requestWhiteboardSync();
}

export interface MountWhiteboardOptions {
	/** Fires with the CHANGED elements only (diffChangedElements above)
	 *  whenever the local user edits the board. Wire to room.sendWhiteboard. */
	onChange: (elements: unknown) => void;
	/** Fires with a rendered PNG Blob when the user clicks the "Export to
	 *  chat" button this file renders inside Excalidraw's OWN top-right UI
	 *  chrome (design D9 — the one sanctioned non-token-styled surface, since
	 *  the button lives inside Excalidraw's own rendered UI, not ours).
	 *  Omitted (undefined) hides the button entirely — the caller passes
	 *  nothing when there is no bridged chat channel to export into. */
	onExport?: (blob: Blob) => void;
	/** Fires once per local edit that would push the scene over
	 *  WB_ELEMENT_CAP — that edit's diff is dropped (never broadcast, F15),
	 *  so the board never grows past the cap for anyone else. The caller
	 *  toasts meet.wb.full. */
	onFull?: () => void;
	theme: WhiteboardTheme;
}

declare global {
	interface Window {
		EXCALIDRAW_ASSET_PATH?: string;
	}
}

/** Mounts Excalidraw into `el` via `createRoot` + `React.createElement` (no
 *  JSX — this stays a plain .ts file, no build-plugin change, per DN5).
 *  Self-hosted assets only: EXCALIDRAW_ASSET_PATH points at the fonts
 *  committed under static/excalidraw/ (copied from the pinned package at
 *  task time) — never the package's default CDN. */
export function mountWhiteboard(el: HTMLElement, opts: MountWhiteboardOptions): WhiteboardHandle {
	if (typeof window !== 'undefined' && !window.EXCALIDRAW_ASSET_PATH) {
		window.EXCALIDRAW_ASSET_PATH = '/excalidraw/';
	}

	let api: ExcalidrawImperativeAPI | null = null;
	let lastVersions = new Map<string, number>();

	function handleChange(elements: readonly OrderedExcalidrawElement[]): void {
		if (isOverCap(elements)) {
			opts.onFull?.();
			return;
		}
		const changed = diffChangedElements(lastVersions, elements);
		lastVersions = versionsOf(elements);
		if (changed.length > 0) opts.onChange(changed);
	}

	async function handleExport(): Promise<void> {
		if (!api || !opts.onExport) return;
		const blob = await exportToBlob({
			elements: api.getSceneElements(),
			appState: api.getAppState(),
			files: api.getFiles(),
			mimeType: 'image/png',
		});
		opts.onExport(blob);
	}

	const root: Root = createRoot(el);

	function renderScene(theme: WhiteboardTheme): void {
		root.render(
			createElement(Excalidraw, {
				excalidrawAPI: (a: ExcalidrawImperativeAPI) => {
					api = a;
				},
				onChange: handleChange,
				theme,
				renderTopRightUI: () =>
					opts.onExport
						? createElement(
								'button',
								{ type: 'button', onClick: () => void handleExport() },
								t('meet.wb.exportToChat'),
							)
						: null,
			}),
		);
	}
	renderScene(opts.theme);

	return {
		applyRemote(elements: unknown): void {
			if (!api) return;
			// Malformed-frame hardening: a peer frame is untrusted data on a
			// plane every participant can write. A non-array payload degrades to
			// the established empty-merge path; array members that are not even
			// element-shaped (an object carrying a string `id`) are dropped
			// instead of cast through to the reconciler.
			const remote = (Array.isArray(elements) ? elements : []).filter(
				(el): el is RemoteExcalidrawElement =>
					typeof el === 'object' && el !== null && typeof (el as { id?: unknown }).id === 'string',
			);
			// Defensive cap on the RECEIVE side too (a buggy/stale peer's own
			// cap check must not be the only backstop) — silently truncated,
			// no onFull toast here (that's the LOCAL-edit signal only).
			const bounded = isOverCap(remote) ? remote.slice(0, WB_ELEMENT_CAP) : remote;
			// Error isolation: a reconcile/apply failure (a frame Excalidraw's
			// own validation rejects) is contained to THIS frame and logged —
			// never allowed to abort the room's dispatch loop until reconnect.
			try {
				const merged = reconcileElements(api.getSceneElementsIncludingDeleted(), bounded, api.getAppState());
				lastVersions = versionsOf(merged);
				api.updateScene({ elements: merged, captureUpdate: CaptureUpdateAction.NEVER });
			} catch (err) {
				console.error('whiteboard: dropped a malformed remote frame', err);
			}
		},
		getSceneElements(): unknown[] {
			return api ? [...api.getSceneElements()] : [];
		},
		setTheme(theme: WhiteboardTheme): void {
			renderScene(theme);
		},
		unmount(): void {
			root.unmount();
		},
	};
}
