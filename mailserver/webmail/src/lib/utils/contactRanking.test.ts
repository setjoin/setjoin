import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
	rankContacts,
	recordSend,
	getSendCount,
	suggestRecipients,
	removeRecipient
} from './contactRanking';
import { user, registerAuthSessionTeardown } from '$lib/stores/auth';

// contactRanking only needs the identity seam. Keep this unit suite isolated from
// auth.ts's import graph; auth's own tests cover registration and teardown
// dispatch independently (chat/store.svelte.test.ts precedent).
vi.mock('$lib/stores/auth', async () => {
	const { writable } = await import('svelte/store');
	return {
		user: writable(null),
		registerAuthSessionTeardown: vi.fn(() => vi.fn())
	};
});

let accountSeq = 0;
const nextIdentity = () => ({ email: `acct${++accountSeq}@x.test`, isAdmin: false, hasMailbox: true });

describe('contactRanking', () => {
	// One fixed identity for the block: frequencies keep accumulating across these
	// tests exactly as they did when the store was a single localStorage key.
	beforeEach(() => user.set({ email: 'block1@x.test', isAdmin: false, hasMailbox: true }));

	it('ranks frequently contacted addresses higher', () => {
		recordSend('alice@setjoin.com');
		recordSend('alice@setjoin.com');
		recordSend('alice@setjoin.com');
		recordSend('bob@setjoin.com');

		const results = rankContacts(['bob@setjoin.com', 'alice@setjoin.com', 'charlie@setjoin.com']);
		expect(results[0]).toBe('alice@setjoin.com'); // 3 sends, ranked highest
		expect(results[1]).toBe('bob@setjoin.com');    // 1 send
		expect(results[2]).toBe('charlie@setjoin.com'); // 0 sends, ranked lowest
	});

	it('returns getSendCount for a single contact', () => {
		recordSend('  Dave@Setjoin.com  ');
		recordSend('dave@setjoin.com');
		expect(getSendCount(' DAVE@SETJOIN.COM ')).toBe(2);
		expect(getSendCount('unknown@setjoin.com')).toBe(0);
	});

	it('persists counts across calls', () => {
		recordSend('eve@setjoin.com');
		recordSend('eve@setjoin.com');
		// Simulate page reload by clearing memory and re-reading
		const count = getSendCount('eve@setjoin.com');
		expect(count).toBe(2);
	});
});

describe('auto-complete cache', () => {
	beforeEach(() => {
		localStorage.clear();
		// A fresh identity per test: the identity transition purges all persisted
		// contact history, giving each test the clean slate localStorage.clear()
		// used to provide alone.
		user.set(nextIdentity());
	});

	it('suggests previously sent addresses ranked by frequency', () => {
		recordSend('alice@x.test', 'Alice Smith');
		recordSend('alice@x.test', 'Alice Smith');
		recordSend('bob@x.test', 'Bob Lee');
		const out = suggestRecipients('a');
		expect(out[0].email).toBe('alice@x.test');
		expect(out[0].name).toBe('Alice Smith');
	});

	it('matches on name and address substrings', () => {
		recordSend('carol@x.test', 'Carol Danvers');
		expect(suggestRecipients('danv').map((s) => s.email)).toContain('carol@x.test');
		expect(suggestRecipients('carol@').map((s) => s.email)).toContain('carol@x.test');
	});

	it('removes an entry so it no longer suggests', () => {
		recordSend('dave@x.test', 'Dave');
		removeRecipient(' DAVE@X.TEST ');
		expect(suggestRecipients('dave')).toHaveLength(0);
	});

	it('keeps getSendCount working after recording a name (backward compatible)', () => {
		recordSend('frank@x.test', 'Frank');
		recordSend('frank@x.test');
		expect(getSendCount('frank@x.test')).toBe(2);
	});

	it('expires a learned display name instead of persisting it indefinitely', () => {
		recordSend('poison@x.test', 'Evi1 Boss');
		expect(suggestRecipients('poison')).toHaveLength(1);
		// Age the entry past the retention window; the next read prunes it.
		vi.useFakeTimers();
		try {
			vi.setSystemTime(Date.now() + 91 * 24 * 60 * 60 * 1000);
			expect(suggestRecipients('poison')).toHaveLength(0);
			expect(getSendCount('poison@x.test')).toBe(0);
		} finally {
			vi.useRealTimers();
		}
		// Re-learning the address restores the suggestion with a fresh stamp.
		recordSend('poison@x.test', 'Evi1 Boss');
		expect(suggestRecipients('poison')).toHaveLength(1);
	});

	it('drops entries it cannot interpret instead of surfacing them', () => {
		recordSend('keeper@x.test', 'Keeper');
		// Overwrite the current identity's namespace with malformed + legacy entries.
		const identityKeys: string[] = [];
		for (let i = 0; i < localStorage.length; i++) {
			const k = localStorage.key(i);
			if (k !== null && k.startsWith('setjoin-contact-frequencies:')) identityKeys.push(k);
		}
		expect(identityKeys.length).toBeGreaterThan(0);
		localStorage.setItem(identityKeys[0], JSON.stringify({ 'bad@x.test': { count: 'many' }, 'num@x.test': 3 }));
		expect(suggestRecipients('bad@')).toHaveLength(0);
		expect(getSendCount('bad@x.test')).toBe(0);
		expect(getSendCount('num@x.test')).toBe(3); // legacy numeric entries keep working
	});

	it('treats the legacy shared store as residue: never read, evicted on identity acquisition', () => {
		// The pre-scoping key was account-INDEPENDENT: it blended every identity's
		// contacts and survived logout. It must not feed any identity's suggestions.
		localStorage.setItem('setjoin-contact-frequencies', JSON.stringify({ 'legacy@x.test': 5 }));
		user.set(nextIdentity()); // acquisition transition purges the legacy key
		expect(localStorage.getItem('setjoin-contact-frequencies')).toBeNull();
		expect(getSendCount('legacy@x.test')).toBe(0);
		expect(suggestRecipients('legacy')).toHaveLength(0);
	});
});
