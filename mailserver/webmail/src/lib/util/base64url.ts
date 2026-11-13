// Base64url <-> ArrayBuffer conversion. Single owner so WebAuthn (stores/auth.ts,
// settings passkey enrollment) and DPoP (auth/dpop.ts) share one implementation
// instead of two copies drifting apart.

/** Typed decode failure. Malformed base64url input fails closed on this class
 *  instead of leaking atob's raw InvalidCharacterError (or silently decoding
 *  garbage the authenticator then rejects). */
export class Base64UrlDecodeError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'Base64UrlDecodeError';
	}
}

export function base64urlToBuffer(b64url: string): ArrayBuffer {
	// The backend emits Go base64.RawURLEncoding — UNPADDED, url-safe alphabet —
	// while atob speaks padded standard base64. Translate the alphabet, strip
	// any padding, then re-pad canonically so padded and unpadded input both
	// decode; a length%4===1 input still fails atob and lands on the typed error.
	const base64 = b64url.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
	const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
	let binary: string;
	try {
		binary = window.atob(padded);
	} catch {
		throw new Base64UrlDecodeError('malformed base64url input');
	}
	// atob yields one Latin-1 char per byte; charCodeAt preserves that exact
	// byte mapping — no UTF-8 reinterpretation to corrupt the decoded bytes.
	const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
	return bytes.buffer;
}

export function bufferToBase64url(buffer: ArrayBuffer): string {
	const bytes = new Uint8Array(buffer);
	let binary = '';
	for (let i = 0; i < bytes.length; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
