// med-shard2-004: account scoping + auth-teardown purge for the contact-frequency
// cache (D-MAILSERVER-WEBMAIL-SRC-LIB-UTILS-001 / the UTILS half of the package).
//
// Covers the package's proposed tests:
// - logout / impersonation end / account switch evict contact-frequency entries;
//   the next profile user gets zero prior-identity suggestions;
// - the legacy account-independent key is residue: never readable, evicted;
// - with no authenticated identity, frequencies are never persisted at all.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
	recordSend,
	getSendCount,
	suggestRecipients,
	rankContacts,
	purgeContactFrequencies
} from './contactRanking';
import { user, registerAuthSessionTeardown } from '$lib/stores/auth';

vi.mock('$lib/stores/auth', async () => {
	const { writable } = await import('svelte/store');
	return {
		user: writable(null),
		registerAuthSessionTeardown: vi.fn(() => vi.fn())
	};
});

const alice = { email: 'alice@x.test', name: 'Alice Smith' };
let accountSeq = 0;
const loginAs = () => user.set({ email: `acct${++accountSeq}@x.test`, isAdmin: false, hasMailbox: true });
const flush = () => new Promise((r) => setTimeout(r, 0));

const storedKeys = () => {
	const keys: string[] = [];
	for (let i = 0; i < localStorage.length; i++) {
		const k = localStorage.key(i);
		if (k !== null) keys.push(k);
	}
	return keys.filter(
		(k) => k === 'setjoin-contact-frequencies' || k.startsWith('setjoin-contact-frequencies:')
	);
};

beforeEach(async () => {
	localStorage.clear();
	user.set(null);
	await flush();
});

describe('account scoping of the contact-frequency cache', () => {
	it('persists frequencies under a per-identity namespace, never the shared key', () => {
		loginAs();
		recordSend(alice.email, alice.name);
		expect(localStorage.getItem('setjoin-contact-frequencies')).toBeNull();
		expect(storedKeys()).toHaveLength(1);
		expect(storedKeys()[0]).toMatch(/^setjoin-contact-frequencies:email:acct\d+@x\.test$/);
		expect(suggestRecipients('alice')).toHaveLength(1);
	});

	it('logout evicts all entries: the next profile user gets zero prior-identity suggestions', async () => {
		loginAs();
		recordSend(alice.email, alice.name);
		recordSend('bob@x.test', 'Bob');

		user.set(null); // logout resets the identity
		await flush();

		expect(suggestRecipients('')).toHaveLength(0);
		expect(suggestRecipients('alice')).toHaveLength(0);
		expect(getSendCount(alice.email)).toBe(0);
		expect(storedKeys()).toHaveLength(0);
	});

	it('account switch purges the prior identity: the new user starts from zero', async () => {
		loginAs();
		recordSend(alice.email, alice.name);

		loginAs(); // different account
		await flush();

		expect(suggestRecipients('')).toHaveLength(0);
		expect(getSendCount(alice.email)).toBe(0);
		// and the new account's own history accumulates under its own namespace
		recordSend('carol@x.test');
		expect(suggestRecipients('carol')).toHaveLength(1);
		expect(suggestRecipients('alice')).toHaveLength(0);
	});

	it('a prior session residue namespace for another identity is invisible and evicted', async () => {
		localStorage.setItem(
			'setjoin-contact-frequencies:email:prior@x.test',
			JSON.stringify({ [alice.email]: { count: 9, name: alice.name } })
		);
		loginAs(); // acquisition transition purges every namespace, incl. the residue
		await flush();

		expect(storedKeys()).toHaveLength(0);
		expect(suggestRecipients('')).toHaveLength(0);
		expect(getSendCount(alice.email)).toBe(0);
	});

	it('with no authenticated identity, frequencies work in-page but are never persisted', () => {
		recordSend(alice.email, alice.name);
		expect(suggestRecipients('alice')).toHaveLength(1); // usable this page
		expect(storedKeys()).toHaveLength(0); // but nothing reached storage
	});

	it('re-login after logout starts from an empty cache (teardown semantics, not retention)', async () => {
		loginAs();
		recordSend(alice.email, alice.name);
		user.set(null);
		await flush();
		loginAs(); // same-shaped new session
		await flush();
		expect(getSendCount(alice.email)).toBe(0);
	});

	it('rankContacts reads only the current identity namespace', async () => {
		loginAs();
		recordSend(alice.email);
		user.set(null);
		await flush();
		loginAs();
		await flush();
		// prior identity's counts no longer influence ranking (all zero → alphabetical)
		expect(rankContacts([alice.email, 'aaron@x.test'])).toEqual(['aaron@x.test', alice.email]);
	});
});

describe('auth teardown wiring', () => {
	it('registers a teardown that purges the whole cache', () => {
		expect(registerAuthSessionTeardown).toHaveBeenCalled();
		const teardown = vi.mocked(registerAuthSessionTeardown).mock.calls[0][0];

		loginAs();
		recordSend(alice.email, alice.name);
		localStorage.setItem(
			'setjoin-contact-frequencies:email:someone-else@x.test',
			JSON.stringify({ 'other@x.test': 3 })
		);

		teardown();

		expect(storedKeys()).toHaveLength(0);
		expect(suggestRecipients('alice')).toHaveLength(0);
		expect(suggestRecipients('other')).toHaveLength(0);
	});

	it('purgeContactFrequencies is idempotent and safe on an empty store', () => {
		expect(() => purgeContactFrequencies()).not.toThrow();
		purgeContactFrequencies();
		expect(storedKeys()).toHaveLength(0);
	});
});
