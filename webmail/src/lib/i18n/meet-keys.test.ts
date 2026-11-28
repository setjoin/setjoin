import { describe, it, expect } from 'vitest';
import en from './en';
import de from './de';
import zh from './zh';

function meetKeys(bundle: Record<string, string>): string[] {
	return Object.keys(bundle).filter((k) => k.startsWith('meet.'));
}

// Every static `t('meet.…')` literal referenced anywhere under the meet app's
// own source — the completeness gate the plan calls for (no dead or missing
// keys), the chat-keys.test.ts genre.
function scanSourceForMeetKeys(): Set<string> {
	const modules = import.meta.glob(
		['/src/lib/components/meet/**/*.{svelte,ts}', '/src/lib/meet/**/*.ts', '/src/routes/meet/**/*.svelte'],
		{ query: '?raw', import: 'default', eager: true },
	) as Record<string, string>;
	const found = new Set<string>();
	const re = /t\('(meet\.[a-zA-Z0-9_.]+)'/g;
	for (const src of Object.values(modules)) {
		for (const m of src.matchAll(re)) found.add(m[1]);
	}
	return found;
}

// arch #6 / UX #18 — the reverse-direction guard, generalized from the old
// meet.recording.*-only scope to ALL meet.* keys. meet.* keys leak outside
// the meet app's own dirs (CalendarApp's "Add setjoin Meet" checkbox,
// ChatApp/MessageRow's meet↔chat bridge strings), so this scans the WHOLE
// webmail source tree, not just src/lib/components/meet — a scope-matching
// scan above (meet-dir-only) would false-flag those as dead. It also matches
// a bare quoted key literal, not just `t('key')`, to catch indirection
// through a variable (`const key = cond ? 'meet.a' : 'meet.b'; t(key)`) —
// see the analogous chat.compliance.retention{Floor,Ceiling} case in
// chat-keys.test.ts's version of this guard.
function scanWholeTreeForKeyLiterals(prefix: string): Set<string> {
	const modules = import.meta.glob(['/src/**/*.svelte', '/src/**/*.ts'], {
		query: '?raw',
		import: 'default',
		eager: true,
	}) as Record<string, string>;
	const found = new Set<string>();
	const escapedPrefix = prefix.replace(/\./g, '\\.');
	const litRe = new RegExp(`'(${escapedPrefix}[a-zA-Z0-9_.]+)'`, 'g');
	const tplRe = new RegExp(`\`(${escapedPrefix}[a-zA-Z0-9_.]+)\``, 'g');
	for (const [path, src] of Object.entries(modules)) {
		if (path.startsWith('/src/lib/i18n/')) continue; // exclude the bundles themselves + this test file
		for (const m of src.matchAll(litRe)) found.add(m[1]);
		for (const m of src.matchAll(tplRe)) found.add(m[1]);
	}
	return found;
}

// Dynamic-key prefixes built via template-literal interpolation
// (`t(\`meet.role.${role}\`)`) that a literal-string scan can never resolve —
// every key under these prefixes is exempt from the dead-key check below.
const MEET_DYNAMIC_KEY_PREFIXES = ['meet.role.', 'meet.tile.quality.'];

describe('meet i18n keys', () => {
	it('en/de/zh define exactly the same meet.* key set', () => {
		const enKeys = new Set(meetKeys(en));
		const deKeys = new Set(meetKeys(de));
		const zhKeys = new Set(meetKeys(zh));
		expect([...deKeys].sort()).toEqual([...enKeys].sort());
		expect([...zhKeys].sort()).toEqual([...enKeys].sort());
	});

	it('every meet.* value is a non-empty string in all three bundles', () => {
		for (const k of meetKeys(en)) {
			expect(typeof en[k], `en[${k}]`).toBe('string');
			expect(en[k].length, `en[${k}] empty`).toBeGreaterThan(0);
			expect(typeof de[k], `de[${k}]`).toBe('string');
			expect(de[k].length, `de[${k}] empty`).toBeGreaterThan(0);
			expect(typeof zh[k], `zh[${k}]`).toBe('string');
			expect(zh[k].length, `zh[${k}] empty`).toBeGreaterThan(0);
		}
	});

	it('zh is a real translation, not an en/de stub', () => {
		for (const k of meetKeys(en)) {
			expect(zh[k], `zh[${k}] === en[${k}] (looks stubbed)`).not.toBe(en[k]);
		}
	});

	it('every literal meet.* key referenced in the meet app source exists in en (no dead/missing keys)', () => {
		const referenced = scanSourceForMeetKeys();
		expect(referenced.size).toBeGreaterThan(0); // sanity: the scan actually found something
		for (const k of referenced) {
			expect(en[k], `referenced but missing from en: ${k}`).toBeDefined();
		}
	});

	// B2 retro F6, generalized by arch #6 / UX #18: the reverse direction —
	// originally scoped to meet.recording.* only (it caught
	// `meet.recording.blockedByGuests` sitting dead in all three bundles
	// before MeetApp's doStartRecording BZ199 arm wired it in), now covers
	// EVERY meet.* key so the whole class can't recur (it caught
	// meet.chatBridge.title/join, meet.chat.disabled, and meet.app.create —
	// an abandoned bridge-panel design + an unwired disabled-notice — the
	// 2026-07-16 whole-pipeline review pass that deleted them).
	it('every meet.* key defined in en is referenced somewhere in the webmail source, or is under an allowlisted dynamic-key prefix (no dead keys)', () => {
		const referenced = scanWholeTreeForKeyLiterals('meet.');
		const allMeetKeys = meetKeys(en);
		expect(allMeetKeys.length).toBeGreaterThan(0); // sanity
		for (const k of allMeetKeys) {
			if (MEET_DYNAMIC_KEY_PREFIXES.some((p) => k.startsWith(p))) continue;
			expect(referenced.has(k), `defined but never referenced: ${k}`).toBe(true);
		}
	});

	// Task 17: the guest join page's own key surface, pinned explicitly (the
	// generic scan above only catches referenced-but-missing-from-en; it would
	// not catch a key silently deleted from de/zh only while still present in
	// en and still "referenced").
	it('the meet.guestJoin.* key set (Task 17) is exactly this list, in all three locales', () => {
		const expected = [
			'meet.guestJoin.heading',
			'meet.guestJoin.nameLabel',
			'meet.guestJoin.namePlaceholder',
			'meet.guestJoin.submit',
			'meet.guestJoin.trustLine',
			'meet.guestJoin.reconnecting',
		].sort();
		const guestJoinKeys = (bundle: Record<string, string>) =>
			Object.keys(bundle)
				.filter((k) => k.startsWith('meet.guestJoin.'))
				.sort();
		expect(guestJoinKeys(en)).toEqual(expected);
		expect(guestJoinKeys(de)).toEqual(expected);
		expect(guestJoinKeys(zh)).toEqual(expected);
	});
});
