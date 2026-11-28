// Per-sender remote-image trust (WAVE-5 #5) — a lazy client cache over the
// V091 user_image_allow endpoints (GET/POST/DELETE /api/settings/trusted-senders).
//
// EXACT-ADDRESS grain. The allowlist ungates the remote-image FETCH only — the
// HTML body always still passes DOMPurify sanitize (renderEmailBodyHTML); a
// trusted sender never bypasses the sanitizer (see sanitize.test.ts).

import { typedFetch, httpRequest } from '$lib/http';

export interface TrustedSender {
	sender: string;
	createdAt: string;
}

class ImageTrustStore {
	senders = $state<TrustedSender[]>([]);
	loaded = $state(false);
	#loading: Promise<void> | null = null;

	has(sender: string): boolean {
		const s = sender.trim().toLowerCase();
		return s !== '' && this.senders.some((r) => r.sender === s);
	}

	/** Load the list once (lazy); safe to call from every message card. */
	ensureLoaded(): Promise<void> {
		if (this.loaded) return Promise.resolve();
		this.#loading ??= (async () => {
			try {
				const data = await typedFetch<{ senders: TrustedSender[] | null }>(
					'/api/settings/trusted-senders',
					{ loginRedirect: null }
				);
				this.senders = data.senders ?? [];
				this.loaded = true;
			} catch {
				// Stay unloaded (fail closed to "not trusted"); the next call retries.
				this.#loading = null;
			}
		})();
		return this.#loading;
	}

	/** Optimistically add a sender; rolls back and rethrows on failure. */
	async add(sender: string): Promise<void> {
		const s = sender.trim().toLowerCase();
		if (!s) return;
		const had = this.has(s);
		if (!had) this.senders = [{ sender: s, createdAt: new Date().toISOString() }, ...this.senders];
		try {
			await typedFetch('/api/settings/trusted-senders', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ sender: s }),
				loginRedirect: null
			});
		} catch (e) {
			if (!had) this.senders = this.senders.filter((r) => r.sender !== s);
			throw e;
		}
	}

	/** Optimistically remove a sender; rolls back and rethrows on failure. */
	async remove(sender: string): Promise<void> {
		const s = sender.trim().toLowerCase();
		const prev = this.senders;
		this.senders = this.senders.filter((r) => r.sender !== s);
		try {
			await httpRequest(`/api/settings/trusted-senders/${encodeURIComponent(s)}`, {
				method: 'DELETE',
				loginRedirect: null
			});
		} catch (e) {
			this.senders = prev;
			throw e;
		}
	}
}

/** Process-wide singleton — one list per session, shared by cards + settings. */
export const imageTrust = new ImageTrustStore();
