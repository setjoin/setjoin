// nativeToken.ts — the SPA-side mint/cache for POST /api/drive/native-token
// (Drive P3, batch-3 #1(b)). The route is P1's (mailserver/internal/drive/
// native_token.go); this file owns only the renderer-side caching so
// VaultStore/SecureViewer don't mint a fresh token on every chunk fetch.
// Only the renderer holds the SPA's cookie session, so only it can mint —
// same auth handoff mirrorBridge.svelte.ts uses for the P2 FolderMirror main
// process, minus the "hand it to native main" leg (VaultStore runs IN the
// renderer and calls the native drive bridge directly with the bearer).
import { typedFetch } from '$lib/http';
import { registerAuthSessionTeardown } from '$lib/stores/auth';

interface NativeTokenResponse {
	token: string;
	expiresAt: string;
}

/** Re-mint once the cached token is within this long of expiring. */
const SLIDE_MS = 60_000;

let cached: { token: string; expiresAtMs: number } | null = null;

/** Returns a valid drive-scoped bearer for native chunk fetch/push, minting a
 *  fresh one via the cookie-authenticated route when the cache is empty or
 *  within SLIDE_MS of expiry. */
export async function getNativeToken(): Promise<string> {
	if (cached && cached.expiresAtMs - SLIDE_MS > Date.now()) return cached.token;
	const res = await typedFetch<NativeTokenResponse>('/api/drive/native-token', { method: 'POST' });
	cached = { token: res.token, expiresAtMs: Date.parse(res.expiresAt) };
	return cached.token;
}

/** Test/logout hook — drop the cache so the next call re-mints. */
export function resetNativeTokenCache(): void {
	cached = null;
}

// The logout hook is wired via the same session-teardown registry the offline
// queue uses: the drive-scoped bearer lives in module memory and must not
// survive a teardown (logout, impersonation end, account switch). Server-side
// session-family revocation remains the authoritative backstop; this drops the
// renderer's copy the moment the session goes away.
registerAuthSessionTeardown(resetNativeTokenCache);
