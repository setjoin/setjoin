// viewAttempt.svelte.ts — AR-02: one owner for every Drive preview acquisition
// (architecture review 2026-09-12, card AR-02 / CP5 cleanup half).
//
// The two Drive viewers (SecureViewer.svelte, CompareView.svelte) previously
// each hand-rolled the same async resource recipe — create a blob URL or a
// native serve ticket after some awaits, then try to revoke it in effect
// cleanup. That shape leaks whenever acquisition completes AFTER teardown
// (late blob URL never revoked, late serveGrant registers a ticket nothing
// revokes) or when a sibling promise rejects (CompareView's catch-less
// Promise.all abandoning the settled side's URL). This module owns the
// acquisition lifetime so those windows close by construction:
//
//   const attempt = openViewAttempt();          // one per effect run / load()
//   const res = await attempt.acquire('blob-url', () => blobUrlAdapter(blob));
//   if (!res) return;                           // stale/closed — already released
//   objectUrl = res.value;                      // register for render
//   // cleanup: attempt.releaseAll() — idempotent, exactly-once per resource
//
// The stale check: `closed` + a monotonic generation. Any acquisition that
// completes for a closed (teardown, retry, prop-change supersession) attempt
// has its fresh resource released immediately by the attempt and resolves
// null — late completions have an owner, and never reach live component
// state. Superseded attempts self-release the same way: their owner called
// releaseAll() before opening the replacement.
//
// Render policy stays OUT of this module on purpose (review evidence card):
// no MIME, ACL, classification, CSP, governed-export or fetch decisions move
// here. The module never fetches, classifies, retries or renders — it only
// pairs created resources with their exactly-once release.

import type { DriveBridge, DriveManifest } from '$lib/native/types';

/** A created resource paired with its release. `value` is what the caller
 *  renders (blob URL, ticket path, text…); `release` is owned by the
 *  attempt — callers never invoke it themselves. */
export interface AcquiredResource<T = string> {
	readonly value: T;
	release(): void;
}

/** One viewing attempt: every acquisition of a version's preview content.
 *  Resources registered on a live attempt are released by `releaseAll()`;
 *  acquisitions completing after `releaseAll()` are released by the attempt
 *  itself and resolve null. */
export interface ViewAttempt {
	/** Process-wide monotonic generation — a later attempt is always higher.
	 *  Gives tests and triage a stable identity for superseded vs live runs. */
	readonly generation: number;
	/** True once releaseAll() ran. A closed attempt never registers a
	 *  resource and never creates one for a fresh acquire() call. */
	readonly closed: boolean;
	/** The ONLY path a preview resource may be created through. Runs
	 *  `acquire` and either registers the result (resolves it back for the
	 *  caller to render) or — if the attempt went stale/closed while the
	 *  acquisition was in flight — releases the fresh resource immediately
	 *  and resolves null. Throws only when `acquire` itself rejects
	 *  (component error path); nothing is registered or released then. */
	acquire<T>(kind: string, acquire: () => AcquiredResource<T> | Promise<AcquiredResource<T>>): Promise<AcquiredResource<T> | null>;
	/** Closes the attempt and releases every registered resource exactly
	 *  once. Idempotent — safe to call from both effect teardown and the
	 *  post-cleanup late-completion path (and plain twice). */
	releaseAll(): void;
	/** Kinds of resources still registered — leak triage / test diagnostics. */
	readonly liveKinds: readonly string[];
}

let nextGeneration = 0;

/** Wraps a resource so its release runs at most once, whichever path gets
 *  there first (releaseAll iteration vs the late-completion stale path). */
function exactlyOnce<T>(resource: AcquiredResource<T>): AcquiredResource<T> {
	let released = false;
	return {
		value: resource.value,
		release: () => {
			if (released) return;
			released = true;
			resource.release();
		},
	};
}

class ViewAttemptImpl implements ViewAttempt {
	readonly generation = ++nextGeneration;
	#closed = false;
	#live: { kind: string; resource: AcquiredResource<unknown> }[] = [];

	get closed(): boolean {
		return this.#closed;
	}

	get liveKinds(): readonly string[] {
		return this.#live.map((entry) => entry.kind);
	}

	async acquire<T>(
		kind: string,
		acquire: () => AcquiredResource<T> | Promise<AcquiredResource<T>>,
	): Promise<AcquiredResource<T> | null> {
		// Closed before we even start: do not create a resource nobody needs.
		if (this.#closed) return null;
		const resource = exactlyOnce(await acquire());
		// Closed while the acquisition was in flight: the fresh resource is
		// OURS to release — the late completion has an owner (this attempt),
		// never the caller, and never live component state.
		if (this.#closed) {
			resource.release();
			return null;
		}
		this.#live.push({ kind, resource: resource as AcquiredResource<unknown> });
		return resource;
	}

	releaseAll(): void {
		this.#closed = true;
		const live = this.#live;
		this.#live = [];
		for (const entry of live) entry.resource.release();
	}
}

/** Opens a fresh attempt. One per effect run / load(); superseded attempts
 *  are closed by their owner calling releaseAll() before opening the next. */
export function openViewAttempt(): ViewAttempt {
	return new ViewAttemptImpl();
}

/** The caller-side half of the stale contract: acquire `kind` through the
 *  attempt and, only if the attempt is STILL current after the acquisition
 *  resolves, hand `resource.value` to `commit` — the component's state write.
 *
 *  `acquire()` rechecks `closed` at registration time, but cleanup can still
 *  land between that resolution and the component's own continuation (the
 *  acquisition-to-render handoff: AR-02 HOLD r2, P1). Rechecking attempt
 *  currency immediately before the write — here, in one choke point every
 *  viewer state write goes through — closes that window by construction:
 *  the check and the write run back-to-back with no await between them. */
export async function acquireAndCommit<T>(
	attempt: ViewAttempt,
	kind: string,
	acquire: () => AcquiredResource<T> | Promise<AcquiredResource<T>>,
	commit: (value: T) => void,
): Promise<void> {
	const resource = await attempt.acquire(kind, acquire);
	if (!resource || attempt.closed) return; // stale/closed: already released, never rendered
	commit(resource.value);
}

// ── adapters ────────────────────────────────────────────────────────────────
// Thin create+release pairings, injectable for tests (a test passes its own
// thunk to attempt.acquire; components pass these builders).

/** Blob URL adapter — create: URL.createObjectURL, release: revokeObjectURL.
 *  CompareView panes and SecureViewer's RAM-blob paths. */
export function blobUrlAdapter(blob: Blob): AcquiredResource<string> {
	const url = URL.createObjectURL(blob);
	return {
		value: url,
		release: () => URL.revokeObjectURL(url),
	};
}

/** Native ticket adapter — create: serveGrant(manifest) against an
 *  already-started serve port (serveStart stays with the caller: it is
 *  idempotent server startup, not a per-attempt resource); release:
 *  serveRevoke(ticket). The native side fails grant fast on missing chunks;
 *  revoke may reject asynchronously (e.g. "serve stopped" once the port is
 *  already closed) — release handles that rejection so teardown never
 *  surfaces an unhandledRejection (AR-02 HOLD r2). */
export async function nativeTicketAdapter(
	drive: DriveBridge,
	manifest: DriveManifest,
): Promise<AcquiredResource<string>> {
	const ticket = await drive.serveGrant(manifest);
	return {
		value: ticket,
		release: () => {
			drive.serveRevoke(ticket).catch(() => {
				// Tolerated: the serve server already stopped (or the bridge is
				// gone) — nothing is left to revoke or report on this path.
			});
		},
	};
}

/** Non-resource carrier for text / sanitized HTML — nothing to revoke, but
 *  flowing through acquire() keeps the stale check uniform with blob URLs
 *  and tickets. Its release is a no-op. */
export function valueResource<T>(value: T): AcquiredResource<T> {
	return { value, release: () => {} };
}
