import { describe, it, expect } from 'vitest';

import {
	buildAttachmentTransferUrl,
	isRedirectStatus,
	validateAttachmentTransferUrl,
} from './transferDestination';

const ORIGIN = 'https://mail.example.net';
const SHA = 'ab'.repeat(32);

describe('E4-I transfer destination boundary', () => {
	it('builds the exact canonical /mail-attachment/{sha256} URL from the approved origin', () => {
		const built = buildAttachmentTransferUrl({ approvedOrigin: ORIGIN, blobSha256: SHA });
		expect(built).toEqual({
			kind: 'ok',
			url: `${ORIGIN}/mail-attachment/${SHA}`,
			origin: ORIGIN,
			pathname: `/mail-attachment/${SHA}`,
			sha256: SHA,
		});
	});

	it('rejects non-HTTPS and malformed origins before any bearer exists', () => {
		expect(buildAttachmentTransferUrl({ approvedOrigin: 'http://mail.example.net', blobSha256: SHA }))
			.toMatchObject({ kind: 'rejected', reason: 'non-https-origin' });
		expect(buildAttachmentTransferUrl({ approvedOrigin: 'ftp://mail.example.net', blobSha256: SHA }))
			.toMatchObject({ kind: 'rejected', reason: 'invalid-origin' });
		expect(buildAttachmentTransferUrl({ approvedOrigin: `${ORIGIN}/path?q=1`, blobSha256: SHA }))
			.toMatchObject({ kind: 'rejected', reason: 'invalid-origin' });
		expect(buildAttachmentTransferUrl({ approvedOrigin: ORIGIN, blobSha256: 'zz' }))
			.toMatchObject({ kind: 'rejected', reason: 'invalid-sha256' });
	});

	it('accepts caller URLs that exactly match the canonical destination and identity', () => {
		const validated = validateAttachmentTransferUrl({
			approvedOrigin: ORIGIN,
			blobSha256: SHA,
			callerUrl: `${ORIGIN}/mail-attachment/${SHA}`,
		});
		expect(validated.kind).toBe('ok');
	});

	it('rejects foreign origins, downgrades, userinfo, query credentials, fragments and encoded paths', () => {
		const cases: Array<[string, string]> = [
			['https://evil.example.net/mail-attachment/' + SHA, 'foreign-origin'],
			['http://mail.example.net/mail-attachment/' + SHA, 'non-https-origin'],
			['https://mail.example.net:8443/mail-attachment/' + SHA, 'port-mismatch'],
			['https://user:secret@mail.example.net/mail-attachment/' + SHA, 'userinfo-present'],
			[`https://mail.example.net/mail-attachment/${SHA}?token=x`, 'query-present'],
			[`https://mail.example.net/mail-attachment/${SHA}#frag`, 'fragment-present'],
			// Astra correction: ambiguity is checked on the RAW caller text BEFORE
			// URL parsing can normalize it away — encoded dot segments are an
			// explicit encoded-path rejection, not a silent normalization.
			['https://mail.example.net/mail-attachment/%2e%2e/' + SHA, 'encoded-path'],
			['https://mail.example.net/mail-attachment/%2e/' + SHA, 'encoded-path'],
			['https://mail.example.net/mail-attachment/%2e%2e', 'encoded-path'],
			// Backslashes are folded into slashes by URL parsing; the raw-text
			// check rejects them before that.
			['https://mail.example.net\\mail-attachment\\' + SHA, 'encoded-path'],
			['https:\\/\\/mail.example.net\\/mail-attachment\\' + SHA, 'encoded-path'],
			// Encoded separators survive URL normalization and are refused as
			// ambiguous encoded paths.
			['https://mail.example.net/mail-attachment/x%2f' + SHA, 'encoded-path'],
			['https://mail.example.net//mail-attachment/' + SHA, 'encoded-path'],
			['https://mail.example.net/mail-attachment/' + 'cd'.repeat(32), 'path-mismatch'],
			['https://mail.example.net/mail-attachment-evil/x', 'path-mismatch'],
		];
		for (const [callerUrl, reason] of cases) {
			expect(validateAttachmentTransferUrl({ approvedOrigin: ORIGIN, blobSha256: SHA, callerUrl }))
				.toMatchObject({ kind: 'rejected', reason });
		}
		// The exact canonical destination still validates.
		expect(validateAttachmentTransferUrl({
			approvedOrigin: ORIGIN,
			blobSha256: SHA,
			callerUrl: `${ORIGIN}/mail-attachment/${SHA}`,
		}).kind).toBe('ok');
	});

	it('redirect statuses are always rejected, never followed', () => {
		for (const status of [300, 301, 302, 303, 307, 308, 399]) {
			expect(isRedirectStatus(status)).toBe(true);
		}
		for (const status of [200, 206, 404, 500]) {
			expect(isRedirectStatus(status)).toBe(false);
		}
	});

	it('control characters that URL parsing strips are rejected in the raw text (r2)', () => {
		// Astra r2 finding 13 reproduction: WHATWG parsing removes tab/newline/CR
		// BEFORE path processing, so a dot segment smuggling a literal tab or
		// newline normalized into the accepted canonical destination. The raw
		// caller text is rejected first.
		const smugglingCases: Array<[string, string]> = [
			// '/x/<TAB>../' parses to '/x/../' and normalizes onto the canonical path.
			[`https://mail.example.net/x/\t../mail-attachment/${SHA}`, 'encoded-path'],
			// '/x/.<TAB>./' parses to '/x/../' — the same parent traversal.
			[`https://mail.example.net/x/.\t./mail-attachment/${SHA}`, 'encoded-path'],
			// '/x/.<LF>./' — the newline variant of the same smuggling.
			[`https://mail.example.net/x/.\n./mail-attachment/${SHA}`, 'encoded-path'],
			// '/x/.<CR>./' — the carriage-return variant.
			[`https://mail.example.net/x/.\r./mail-attachment/${SHA}`, 'encoded-path'],
		];
		for (const [callerUrl, reason] of smugglingCases) {
			// Prove the normalization WOULD have repaired these: the parsed URL
			// lands exactly on the canonical path — only the raw-text rejection
			// catches the smuggled dot segment.
			expect(new URL(callerUrl).pathname).toBe(`/mail-attachment/${SHA}`);
			expect(validateAttachmentTransferUrl({ approvedOrigin: ORIGIN, blobSha256: SHA, callerUrl }))
				.toMatchObject({ kind: 'rejected', reason });
		}
		// The exact canonical destination still validates.
		expect(validateAttachmentTransferUrl({
			approvedOrigin: ORIGIN,
			blobSha256: SHA,
			callerUrl: `${ORIGIN}/mail-attachment/${SHA}`,
		}).kind).toBe('ok');
	});
});
