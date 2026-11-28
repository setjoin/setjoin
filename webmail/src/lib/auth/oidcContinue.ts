const OIDC_OP_COMPLETE_PATH = '/auth/oidc/op/complete';
const MAX_CONTINUATION_BYTES = 1024;
const MAX_REQUEST_ID_BYTES = 256;

/**
 * Accept only the one same-origin continuation that the OIDC OP login hand-off
 * creates. Keeping this allowlist narrower than a generic "relative URL"
 * prevents an attacker from turning the login page into an open redirect or
 * smuggling an unrelated state-changing route through post-login navigation.
 */
export function parseOIDCOPContinuation(raw: string | null): string | null {
	if (
		!raw ||
		raw.length > MAX_CONTINUATION_BYTES ||
		!raw.startsWith('/') ||
		raw.startsWith('//')
	) {
		return null;
	}

	let parsed: URL;
	try {
		parsed = new URL(raw, 'https://setjoin.invalid');
	} catch {
		return null;
	}
	if (
		parsed.origin !== 'https://setjoin.invalid' ||
		parsed.pathname !== OIDC_OP_COMPLETE_PATH ||
		parsed.hash !== ''
	) {
		return null;
	}

	const ids = parsed.searchParams.getAll('id');
	if (
		ids.length !== 1 ||
		ids[0].length === 0 ||
		ids[0].length > MAX_REQUEST_ID_BYTES ||
		[...parsed.searchParams.keys()].some((key) => key !== 'id')
	) {
		return null;
	}

	return `${OIDC_OP_COMPLETE_PATH}?id=${encodeURIComponent(ids[0])}`;
}
