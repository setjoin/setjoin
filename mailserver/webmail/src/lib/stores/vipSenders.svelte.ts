// VIP senders (QoL #10a) — a lazy client cache over /api/user/vip-senders
// (GET/PUT). Emails are stored lowercased server-side; the store mirrors that
// so `isVip()` lookups never miss on casing.

import { typedFetch, httpRequest } from '$lib/http';

class VipSendersStore {
	senders = $state<string[]>([]);
	loaded = $state(false);
	#loading: Promise<void> | null = null;

	isVip(email: string): boolean {
		return this.senders.includes(email.toLowerCase());
	}

	async load(): Promise<void> {
		if (this.#loading) return this.#loading;
		this.#loading = (async () => {
			try {
				const data = await typedFetch<{ senders: string[] | null }>('/api/user/vip-senders', {
					loginRedirect: null
				});
				this.senders = data.senders ?? [];
				this.loaded = true;
			} finally {
				this.#loading = null;
			}
		})();
		return this.#loading;
	}

	/** Toggle VIP membership for one sender email. Optimistic — rolls back on
	 *  a failed request. */
	async set(email: string, vip: boolean): Promise<void> {
		const lower = email.toLowerCase();
		const prev = this.senders;
		this.senders = vip ? [...prev.filter((s) => s !== lower), lower] : prev.filter((s) => s !== lower);
		try {
			await httpRequest('/api/user/vip-senders', {
				method: 'PUT',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ email: lower, vip }),
				loginRedirect: null
			});
		} catch (e) {
			this.senders = prev;
			throw e;
		}
	}

	reset(): void {
		this.senders = [];
		this.loaded = false;
		this.#loading = null;
	}
}

/** Process-wide singleton — one VIP list per session. */
export const vipSenders = new VipSendersStore();
