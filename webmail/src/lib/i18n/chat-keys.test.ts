import { describe, it, expect } from 'vitest';
import en from './en';
import de from './de';
import zh from './zh';

function chatKeys(bundle: Record<string, string>): string[] {
	return Object.keys(bundle).filter((k) => k.startsWith('chat.'));
}

// Every static `t('chat.…')` literal referenced anywhere under the chat app's
// own source — the completeness gate the plan calls for (no dead or missing
// keys). Dynamic template-literal calls, if any emerge, get enumerated
// separately below the way drive-keys.test.ts does for its dynamic families.
function scanSourceForChatKeys(): Set<string> {
	const modules = import.meta.glob(
		['/src/lib/components/chat/**/*.{svelte,ts}', '/src/lib/chat/**/*.ts', '/src/routes/chat/**/*.svelte'],
		{ query: '?raw', import: 'default', eager: true },
	) as Record<string, string>;
	const found = new Set<string>();
	const re = /t\('(chat\.[a-zA-Z0-9_.]+)'/g;
	for (const src of Object.values(modules)) {
		for (const m of src.matchAll(re)) found.add(m[1]);
	}
	return found;
}

// arch #6 / UX #18 — the reverse-direction guard (the meet-keys.test.ts
// genre, added there first for meet.recording.* — see that file's comment).
// chat.* keys leak outside the chat app's own dirs (service-worker.ts's push
// notification copy), so this scans the WHOLE webmail source tree, not just
// src/lib/components/chat. It also matches a bare quoted key literal, not
// just `t('key')`, to catch indirection through a variable — e.g.
// store.svelte.ts's `errorKeyByCode` BZ-code map and `retentionNotice`'s
// ternary key selection both assign a key string to a local before calling
// `t(key)`, which a `t('literal')`-only scan can't see.
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

// Dynamic-key prefix built via template-literal interpolation
// (`t(\`chat.schedule.reason.${code}\`)`) that a literal-string scan can
// never resolve — every key under it is exempt from the dead-key check below.
const CHAT_DYNAMIC_KEY_PREFIXES = ['chat.schedule.reason.'];

describe('chat i18n keys', () => {
	it('en/de/zh define exactly the same chat.* key set', () => {
		const enKeys = new Set(chatKeys(en));
		const deKeys = new Set(chatKeys(de));
		const zhKeys = new Set(chatKeys(zh));
		expect([...deKeys].sort()).toEqual([...enKeys].sort());
		expect([...zhKeys].sort()).toEqual([...enKeys].sort());
	});

	it('every chat.* value is a non-empty string in all three bundles', () => {
		for (const k of chatKeys(en)) {
			expect(typeof en[k], `en[${k}]`).toBe('string');
			expect(en[k].length, `en[${k}] empty`).toBeGreaterThan(0);
			expect(typeof de[k], `de[${k}]`).toBe('string');
			expect(de[k].length, `de[${k}] empty`).toBeGreaterThan(0);
			expect(typeof zh[k], `zh[${k}]`).toBe('string');
			expect(zh[k].length, `zh[${k}] empty`).toBeGreaterThan(0);
		}
	});

	it('zh is a real translation, not an en/de stub', () => {
		for (const k of chatKeys(en)) {
			// A handful of keys are legitimately identical across locales
			// (bare mention tokens like "channel"/"all", which chat renders
			// verbatim as `@channel`/`@all` regardless of locale).
			if (k === 'chat.composer.mentionChannel' || k === 'chat.composer.mentionAll') continue;
			expect(zh[k], `zh[${k}] === en[${k}] (looks stubbed)`).not.toBe(en[k]);
		}
	});

	it('every literal chat.* key referenced in the chat app source exists in en (no dead/missing keys)', () => {
		const referenced = scanSourceForChatKeys();
		expect(referenced.size).toBeGreaterThan(0); // sanity: the scan actually found something
		for (const k of referenced) {
			expect(en[k], `referenced but missing from en: ${k}`).toBeDefined();
		}
	});

	it('the relative-time / date-divider dynamic-format keys (Task 16) are present', () => {
		for (const key of ['chat.time.justNow', 'chat.messageList.dateToday', 'chat.messageList.dateYesterday']) {
			expect(en[key], `en missing ${key}`).toBeTruthy();
			expect(de[key], `de missing ${key}`).toBeTruthy();
			expect(zh[key], `zh missing ${key}`).toBeTruthy();
		}
	});

	// A2 Task 9 — an EXPLICIT pin of the chat.attach.* surface (Composer chip
	// list/cap/progress/retry/remove, MessageRow thumbnail-tombstone/download/
	// open-in-drive, and G4 preview/view-only posture), on top of the generic source-scan above. The scan only
	// catches a key someone forgot to ADD (referenced-but-missing-from-en); it
	// would NOT catch someone silently deleting/renaming a key out of de or zh
	// only (still "referenced" and still present in en). This list pins the
	// exact three-locale set so that direction fails loudly too. Update only
	// when the attach UI's own key surface genuinely changes.
	it('the chat.attach.* key set (Chat A2 attachments, Task 9) is exactly this list, in all three locales', () => {
		const expected = [
			'chat.attach.button',
			'chat.attach.list',
			'chat.attach.capReached',
			'chat.attach.uploading',
			'chat.attach.unavailable',
			'chat.attach.remove',
			'chat.attach.retry',
			'chat.attach.download',
			'chat.attach.openInDrive',
			'chat.attach.preview',
			'chat.attach.viewOnly',
		].sort();
		const attachKeys = (bundle: Record<string, string>) =>
			Object.keys(bundle)
				.filter((k) => k.startsWith('chat.attach.'))
				.sort();
		expect(attachKeys(en)).toEqual(expected);
		expect(attachKeys(de)).toEqual(expected);
		expect(attachKeys(zh)).toEqual(expected);
	});

	// A3 QoL Task 17 review fix — the failed-scheduled-send reason mapping is
	// never referenced via a static `t('chat.schedule.reason.BZ163')` literal
	// (Composer builds the key dynamically from the payload's failureCode), so
	// the generic source-scan above can't see it at all. Pin the exact family
	// the reducer can emit (docs/reducer-error-codes.md BZ163 section /
	// scheduled_action_chat_send.sql's catch list) so a silently-deleted or
	// stubbed key fails loudly here instead of only at runtime for a real user.
	it('the chat.schedule.reason.* key set (A3 scheduled-send failure i18n, Task 17 fix) is exactly this list, in all three locales', () => {
		const expected = ['BZ163', 'BZ164', 'BZ166', 'BZ168', 'BZ171']
			.map((code) => `chat.schedule.reason.${code}`)
			.sort();
		const reasonKeys = (bundle: Record<string, string>) =>
			Object.keys(bundle)
				.filter((k) => k.startsWith('chat.schedule.reason.'))
				.sort();
		expect(reasonKeys(en)).toEqual(expected);
		expect(reasonKeys(de)).toEqual(expected);
		expect(reasonKeys(zh)).toEqual(expected);
	});

	// arch #6 / UX #18 (2026-07-16 whole-pipeline review): caught
	// chat.messageList.loadingOlder sitting dead in all three bundles
	// (defined, never once referenced — an abandoned older-messages spinner
	// design) before this pass deleted it.
	it('every chat.* key defined in en is referenced somewhere in the webmail source, or is under an allowlisted dynamic-key prefix (no dead keys)', () => {
		const referenced = scanWholeTreeForKeyLiterals('chat.');
		const allChatKeys = chatKeys(en);
		expect(allChatKeys.length).toBeGreaterThan(0); // sanity
		for (const k of allChatKeys) {
			if (CHAT_DYNAMIC_KEY_PREFIXES.some((p) => k.startsWith(p))) continue;
			expect(referenced.has(k), `defined but never referenced: ${k}`).toBe(true);
		}
	});
});
