// watches.svelte.ts — P6 Task 13: single reactive cache of the caller's own
// Drive change-subscriptions (§5.6).
//
// Bug this replaces: DriveApp, VersionDrawer, and SubscriptionsSheet each ran
// their own `api.listWatches()` fetch into a private local cache/`$state`.
// Toggling a watch in one (e.g. the VersionDrawer bell) never touched the
// other two's cache, so the FileList quick-toggle and the Subscriptions
// manager kept showing stale state until their own next mount/open. One
// shared `$state` array fixes it: every reader derives off the same rows, so
// a mutation from ANY of them re-renders ALL of them.
import * as api from './api';
import type { DriveWatchRow } from './api';

export class DriveWatchStore {
	rows = $state<DriveWatchRow[]>([]);

	/** Reactive read of every watch the caller owns. */
	list(): DriveWatchRow[] {
		return this.rows;
	}

	/** Reactive read — is this node (exactly, not an ancestor) watched? */
	isWatched(nodeId: number): boolean {
		return this.rows.some((w) => w.nodeId === nodeId);
	}

	/** Refetch from the server and replace the shared cache. */
	async load(): Promise<void> {
		this.rows = await api.listWatches();
	}

	/** Unconditional add/update (server upserts) — the FileList "watch this"
	 *  quick action and the SubscriptionsSheet per-op checkbox editor both
	 *  want this rather than a flip, since neither reads prior state first. */
	async watch(nodeId: number, ops?: string[]): Promise<void> {
		await api.setWatch(nodeId, ops);
		await this.load();
	}

	/** Unconditional remove. */
	async unwatch(nodeId: number): Promise<void> {
		await api.removeWatch(nodeId);
		await this.load();
	}

	/** Flip based on current cached state — the VersionDrawer bell button. */
	async toggle(nodeId: number, ops?: string[]): Promise<void> {
		if (this.isWatched(nodeId)) {
			await this.unwatch(nodeId);
		} else {
			await this.watch(nodeId, ops);
		}
	}
}

/** Shared process-wide instance — mirrors locks.svelte.ts's singleton pattern. */
export const driveWatches = new DriveWatchStore();
