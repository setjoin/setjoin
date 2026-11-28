// search.svelte.ts — P6 Task 13: debounced search-state helper for the Drive
// toolbar search box. Owns the whole query lifecycle (300ms debounce, a
// 2-char floor so every keystroke doesn't round-trip, and cancellation of a
// stale in-flight request via AbortController) so DriveApp.svelte only binds
// text to `query()` and reads `results`/`loading`/`error`.
import * as api from './api';
import type { DriveSearchItem } from './api';

const DEBOUNCE_MS = 300;
const MIN_LEN = 2;

export class DriveSearchStore {
	results = $state<DriveSearchItem[]>([]);
	loading = $state(false);
	/** Raw caught error (e.g. a DriveError) — the caller localizes it (BZ code map). */
	error = $state<unknown>(null);

	#timer: ReturnType<typeof setTimeout> | null = null;
	#controller: AbortController | null = null;

	/** Debounced entry point — call on every input event. */
	query(q: string, opts: { spaceId?: number | null } = {}): void {
		if (this.#timer) clearTimeout(this.#timer);
		const trimmed = q.trim();
		if (trimmed.length < MIN_LEN) {
			this.clear();
			return;
		}
		this.#timer = setTimeout(() => void this.#run(trimmed, opts.spaceId ?? null), DEBOUNCE_MS);
	}

	async #run(q: string, spaceId: number | null): Promise<void> {
		this.#controller?.abort();
		const controller = new AbortController();
		this.#controller = controller;
		this.loading = true;
		this.error = null;
		try {
			const res = await api.searchNodes(q, { spaceId, signal: controller.signal });
			if (controller.signal.aborted) return;
			this.results = res.items;
		} catch (e) {
			if (controller.signal.aborted) return;
			this.error = e;
		} finally {
			if (!controller.signal.aborted) this.loading = false;
		}
	}

	/** Cancels any pending debounce + in-flight request and resets state. */
	clear(): void {
		if (this.#timer) {
			clearTimeout(this.#timer);
			this.#timer = null;
		}
		this.#controller?.abort();
		this.results = [];
		this.loading = false;
		this.error = null;
	}
}
