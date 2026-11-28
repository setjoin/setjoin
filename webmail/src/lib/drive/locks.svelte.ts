// locks.svelte.ts — P4 Task 14 presence + heartbeat runes store (§5.4).
//
// Soft auto-checkout: opening an office-edit file type (office.ts's
// OFFICE_EDIT_EXTS) for editing acquires a soft lock so other members see
// "editing" presence, and renews it every 5 min (LR-10 — the TTL, 480 min
// server-side, is the ceiling; this cadence just keeps a live session's
// lock from expiring). Non-office types never lock (§5.4: soft checkout is
// an office-type courtesy, not a universal rule).
//
// checkOut() explicitly escalates to a hard lock (always requestable,
// §5.4). close() best-effort releases with fetch keepalive so a tab close
// mid-navigation still frees the lock server-side once its TTL would
// otherwise have to expire on its own.
//
// Presence for a file we do NOT hold (someone else's lock) only updates via
// the 'held' response our own acquire attempts return — this store never
// probes with a lock-acquiring PUT purely to read someone else's status,
// since a probe against an actually-expired lock would silently grant IT to
// us. The live nudge (DriveWatch push, Task 11's drive-watch:<uid> channel
// via $lib/jmap/websocket's subscribeEvent) only re-runs our OWN renew when
// we already hold something — the FileList/DriveTree presence badge (which
// reads server rows directly) stays the source of truth for locks this
// session never touched.
import * as api from './api';
import { subscribeEvent } from '$lib/jmap/websocket';
import { isOfficeEditPath } from './office';

const HEARTBEAT_MS = 5 * 60 * 1000; // LR-10

export interface LockPresence {
	holderId: number;
	mode: string;
	since: string;
	branchId: number | null;
}

export interface OpenForEditOptions {
	/** File name — gates soft auto-checkout via isOfficeEditPath. */
	name: string;
	branchId?: number | null;
	versionId?: number | null;
	deviceLabel?: string;
	/** Space/folder policy `edit_lock:'required'` — acquire hard instead of soft. */
	hardRequired?: boolean;
}

export class DriveLockStore {
	nodeId = $state<number | null>(null);
	/** The mode WE hold, or null if we hold nothing (either never opened, or someone else holds it — see `presence`). */
	mode = $state<'soft' | 'hard' | null>(null);
	/** Someone else's active hold, populated from a 'held' acquire response. */
	presence = $state<LockPresence | null>(null);

	#branchId: number | null = null;
	#versionId: number | null = null;
	#deviceLabel: string | undefined;
	#heartbeat: ReturnType<typeof setInterval> | null = null;
	#unsubscribeWatch: (() => void) | null = null;

	async openForEdit(nodeId: number, opts: OpenForEditOptions): Promise<void> {
		if (this.nodeId !== nodeId) this.close();
		this.nodeId = nodeId;
		this.#branchId = opts.branchId ?? null;
		this.#versionId = opts.versionId ?? null;
		this.#deviceLabel = opts.deviceLabel;
		if (!opts.hardRequired && !isOfficeEditPath(opts.name)) return;
		await this.#acquire(opts.hardRequired ? 'hard' : 'soft');
		this.#startHeartbeat();
		this.#subscribeWatch();
	}

	async checkOut(): Promise<void> {
		if (this.nodeId == null) return;
		await this.#acquire('hard');
		if (!this.#heartbeat) this.#startHeartbeat();
		if (!this.#unsubscribeWatch) this.#subscribeWatch();
	}

	async #acquire(mode: 'soft' | 'hard'): Promise<void> {
		if (this.nodeId == null) return;
		const res = await api.lockFile(this.nodeId, {
			mode,
			branchId: this.#branchId,
			versionId: this.#versionId,
			deviceLabel: this.#deviceLabel,
		});
		if (res.status === 'held') {
			this.presence = {
				holderId: res.holderId ?? 0,
				mode: res.mode ?? '',
				since: res.since ?? '',
				branchId: res.branchId ?? null,
			};
			this.mode = null;
		} else {
			this.mode = (res.mode as 'soft' | 'hard' | undefined) ?? mode;
			this.presence = null;
		}
	}

	#startHeartbeat(): void {
		this.#stopHeartbeat();
		this.#heartbeat = setInterval(() => {
			if (this.mode) void this.#acquire(this.mode);
		}, HEARTBEAT_MS);
	}

	#stopHeartbeat(): void {
		if (this.#heartbeat) {
			clearInterval(this.#heartbeat);
			this.#heartbeat = null;
		}
	}

	#subscribeWatch(): void {
		this.#unsubscribeWatch?.();
		this.#unsubscribeWatch = subscribeEvent<{ nodeId?: number }>('DriveWatch', (event) => {
			if (event.nodeId !== this.nodeId) return;
			if (this.mode) void this.#acquire(this.mode);
		});
	}

	/** Best-effort release; clears local state regardless of the request outcome. */
	close(): void {
		this.#stopHeartbeat();
		this.#unsubscribeWatch?.();
		this.#unsubscribeWatch = null;
		if (this.nodeId != null && this.mode) {
			void api.unlockFile(this.nodeId, { keepalive: true }).catch(() => {
				/* best-effort — the server-side TTL is the backstop */
			});
		}
		this.nodeId = null;
		this.mode = null;
		this.presence = null;
	}
}

/** Shared process-wide instance — mirrors mirrorBridge.svelte.ts's singleton pattern. */
export const driveLocks = new DriveLockStore();
