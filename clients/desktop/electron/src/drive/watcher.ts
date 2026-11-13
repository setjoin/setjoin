// watcher.ts — normalize @parcel/watcher events into settled LocalChanges.
// Settle window (default 750 ms, injectable for tests): editors save via
// temp-write + rename; a per-path timer collapses the storm into the final
// state, decided by an lstat() at flush time (exists -> upsert, gone ->
// delete; a symlink is skipped and reported via onSkipped rather than mirrored
// — spec §4.1 has no symlink story, and following one risks escaping the
// mirror root). Exclusion (selective sync) is the engine's job, not the
// watcher's — one owner (Task 6's SyncEngine.isExcluded already guards intake).
import * as parcelWatcher from '@parcel/watcher';
import { lstat, realpath } from 'node:fs/promises';
import * as path from 'node:path';
import { isIgnoredName } from '../../../../../mailserver/webmail/src/lib/drive/sync/names.js';
import type { LocalChange } from '../../../../../mailserver/webmail/src/lib/drive/sync/types.js';

export interface WatcherDeps {
	root: string;
	onChange: (c: LocalChange) => void;
	onSkipped?: (relPath: string, reason: 'symlink') => void;
	settleMs?: number;
}

export class MirrorWatcher {
	private sub: parcelWatcher.AsyncSubscription | null = null;
	private pending = new Map<string, ReturnType<typeof setTimeout>>();
	/** @parcel/watcher reports realpath'd event paths (e.g. macOS /private/var/...
	 *  for a /var/... tmpdir); resolve the watch root the same way at start() so
	 *  path.relative doesn't produce a bogus '../..' for every event. */
	private realRoot: string;

	constructor(private deps: WatcherDeps) {
		this.realRoot = deps.root;
	}

	async start(): Promise<void> {
		this.realRoot = await realpath(this.deps.root).catch(() => this.deps.root);
		this.sub = await parcelWatcher.subscribe(this.deps.root, (err, events) => {
			if (err) return; // ponytail: transient watcher errors surface on the next poll/verify pass, not here
			for (const ev of events) {
				const relPath = path.relative(this.realRoot, ev.path).split(path.sep).join('/');
				if (!relPath || relPath.startsWith('..')) continue;
				if (relPath.split('/').some(isIgnoredName)) continue;
				this.schedule(relPath);
			}
		});
	}

	async stop(): Promise<void> {
		for (const t of this.pending.values()) clearTimeout(t);
		this.pending.clear();
		if (this.sub) {
			await this.sub.unsubscribe();
			this.sub = null;
		}
	}

	private schedule(relPath: string): void {
		const existing = this.pending.get(relPath);
		if (existing) clearTimeout(existing);
		this.pending.set(
			relPath,
			setTimeout(() => {
				this.pending.delete(relPath);
				void this.flush(relPath);
			}, this.deps.settleMs ?? 750)
		);
	}

	private async flush(relPath: string): Promise<void> {
		const abs = path.join(this.realRoot, relPath);
		try {
			const st = await lstat(abs);
			if (st.isSymbolicLink()) {
				this.deps.onSkipped?.(relPath, 'symlink');
				return;
			}
			this.deps.onChange({ kind: 'upsert', relPath });
		} catch {
			this.deps.onChange({ kind: 'delete', relPath });
		}
	}
}
