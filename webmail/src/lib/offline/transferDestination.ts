/**
 * E4 Astra integration correction — network destination is a separate boundary
 * from caller origin.
 *
 * The trusted layer resolves the configured approved HTTPS server origin and
 * constructs the exact `GET /mail-attachment/{sha256}` path for the authorized
 * account/device/job. Caller URL input must match that canonical destination
 * and exact identity; foreign origins, userinfo, query-carried credentials,
 * ambiguous encoded paths and transport downgrade are rejected BEFORE any
 * bearer is attached. V1 native attachment transfers reject redirects rather
 * than forward credentials to any redirected destination, including same-origin
 * redirects; route relocation needs a new approved token/contract, not
 * redirect-following.
 */

const SHA256_RE = /^[0-9a-f]{64}$/;
/** The one and only native attachment transfer path. */
export const ATTACHMENT_TRANSFER_PATH = '/mail-attachment/';

export const TRANSFER_DESTINATION_REJECTION_REASONS = [
	'invalid-origin',
	'non-https-origin',
	'invalid-sha256',
	'foreign-origin',
	'userinfo-present',
	'query-present',
	'fragment-present',
	'path-mismatch',
	'encoded-path',
	'port-mismatch',
] as const;
export type TransferDestinationRejectionReason = (typeof TRANSFER_DESTINATION_REJECTION_REASONS)[number];

export type TransferDestination =
	| { kind: 'ok'; url: string; origin: string; pathname: string; sha256: string }
	| { kind: 'rejected'; reason: TransferDestinationRejectionReason };

function parseApprovedOrigin(origin: unknown): URL | null {
	if (typeof origin !== 'string' || origin.length === 0) return null;
	let parsed: URL;
	try {
		parsed = new URL(origin);
	} catch {
		return null;
	}
	if (parsed.protocol !== 'https:') return null;
	if (parsed.username !== '' || parsed.password !== '') return null;
	if (parsed.search !== '' || parsed.hash !== '') return null;
	return parsed;
}

function normalizePathname(pathname: string): string | null {
	// Reject ambiguous encoded paths: dot segments, encoded slashes/backslashes,
	// double slashes and any remaining percent-escapes in the identity path.
	const lower = pathname.toLowerCase();
	if (lower.includes('%2e') || lower.includes('%2f') || lower.includes('%5c')) return null;
	if (lower.includes('\\')) return null;
	if (pathname.includes('//')) return null;
	if (pathname.includes('/./') || pathname.endsWith('/.')) return null;
	if (pathname.includes('/../') || pathname.endsWith('/..')) return null;
	if (/%[0-9a-f]{2}/i.test(pathname)) return null;
	return pathname;
}

/**
 * E4-I Astra correction: WHATWG URL parsing normalizes encoded dot segments
 * and folds backslashes into slashes BEFORE validation ever sees the path, so
 * ambiguity checks that run on the parsed pathname never fire. The raw
 * caller-supplied text is inspected FIRST, before any normalization: any
 * encoded dot segment, encoded separator, backslash, percent-escape, doubled
 * slash, dot segment or CONTROL CHARACTER in the raw text is rejected outright.
 * WHATWG parsing strips tab/newline/CR anywhere and leading/trailing C0
 * controls before path processing, so a dot segment smuggling a literal tab or
 * newline would otherwise normalize into an accepted canonical destination.
 */
function rawPathIsAmbiguous(rawUrl: string): boolean {
	if (typeof rawUrl !== 'string') return true;
	// Any C0 control (U+0000-U+001F) or DEL anywhere in the raw text is a
	// rejection: URL parsing removes or re-encodes several of them, which can
	// silently repair a rejected shape into a canonical-looking path.
	// eslint-disable-next-line no-control-regex
	if (/[\u0000-\u001f\u007f]/.test(rawUrl)) return true;
	const lower = rawUrl.toLowerCase();
	const schemeEnd = lower.indexOf('://');
	// A well-formed https URL never contains a backslash anywhere after the
	// scheme; WHATWG parsing would fold them into slashes, so reject first.
	const afterScheme = schemeEnd >= 0 ? lower.slice(schemeEnd + 3) : lower;
	if (afterScheme.includes('\\')) return true;
	const afterAuthority = afterScheme.indexOf('/');
	const rawPath = afterAuthority >= 0 ? afterScheme.slice(afterAuthority) : '';
	if (rawPath.length === 0) return false;
	if (rawPath.includes('%2e') || rawPath.includes('%2f') || rawPath.includes('%5c')) return true;
	if (/%[0-9a-f]{2}/i.test(rawPath)) return true;
	if (rawPath.includes('/./') || rawPath.endsWith('/.')) return true;
	if (rawPath.includes('/../') || rawPath.endsWith('/..')) return true;
	if (rawPath.includes('//')) return true;
	return false;
}

/**
 * Construct the canonical transfer URL from the approved origin plus the
 * immutable blob identity. No caller-supplied URL participates.
 */
export function buildAttachmentTransferUrl(input: {
	approvedOrigin: string;
	blobSha256: string;
}): TransferDestination {
	if (typeof input.approvedOrigin === 'string' && /^http:\/\//i.test(input.approvedOrigin)) {
		return { kind: 'rejected', reason: 'non-https-origin' };
	}
	const origin = parseApprovedOrigin(input.approvedOrigin);
	if (!origin) return { kind: 'rejected', reason: 'invalid-origin' };
	if (!SHA256_RE.test(input.blobSha256)) return { kind: 'rejected', reason: 'invalid-sha256' };
	const pathname = normalizePathname(`${ATTACHMENT_TRANSFER_PATH}${input.blobSha256}`);
	if (pathname === null) return { kind: 'rejected', reason: 'encoded-path' };
	const url = `${origin.origin}${pathname}`;
	return { kind: 'ok', url, origin: origin.origin, pathname, sha256: input.blobSha256 };
}

/**
 * Validate caller-supplied URL input against the canonical destination and
 * exact identity. Any mismatch — foreign origin, downgrade, userinfo, query
 * or fragment (credential carriers), ambiguous encoded paths, wrong path or
 * hash — is a rejection before a bearer exists.
 */
export function validateAttachmentTransferUrl(input: {
	approvedOrigin: string;
	blobSha256: string;
	callerUrl: string;
}): TransferDestination {
	const canonical = buildAttachmentTransferUrl(input);
	if (canonical.kind === 'rejected') return canonical;
	if (typeof input.callerUrl !== 'string' || rawPathIsAmbiguous(input.callerUrl)) {
		// Raw-text ambiguity (encoded dot segments, backslashes, escapes) is a
		// rejection BEFORE URL normalization can silently fold it away.
		return { kind: 'rejected', reason: 'encoded-path' };
	}
	let parsed: URL;
	try {
		parsed = new URL(input.callerUrl);
	} catch {
		return { kind: 'rejected', reason: 'path-mismatch' };
	}
	if (parsed.protocol !== 'https:') return { kind: 'rejected', reason: 'non-https-origin' };
	const origin = parseApprovedOrigin(input.approvedOrigin)!;
	if (parsed.protocol !== origin.protocol) return { kind: 'rejected', reason: 'non-https-origin' };
	if (parsed.host !== origin.host) {
		// Same hostname with a different port (or the reverse) is still foreign.
		if (parsed.hostname === origin.hostname) return { kind: 'rejected', reason: 'port-mismatch' };
		return { kind: 'rejected', reason: 'foreign-origin' };
	}
	if (parsed.username !== '' || parsed.password !== '') {
		return { kind: 'rejected', reason: 'userinfo-present' };
	}
	if (parsed.search !== '') return { kind: 'rejected', reason: 'query-present' };
	if (parsed.hash !== '') return { kind: 'rejected', reason: 'fragment-present' };
	const pathname = normalizePathname(parsed.pathname);
	if (pathname === null) return { kind: 'rejected', reason: 'encoded-path' };
	if (pathname !== canonical.pathname) return { kind: 'rejected', reason: 'path-mismatch' };
	if (!SHA256_RE.test(parsed.pathname.slice(ATTACHMENT_TRANSFER_PATH.length))) {
		return { kind: 'rejected', reason: 'invalid-sha256' };
	}
	return canonical;
}

/** True for any redirect status: V1 transfers reject, never follow. */
export function isRedirectStatus(status: number): boolean {
	return Number.isSafeInteger(status) && status >= 300 && status < 400;
}
