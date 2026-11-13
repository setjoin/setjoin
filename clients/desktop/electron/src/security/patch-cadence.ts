//! ADR-013 invariant 5: Electron patch-cadence gate. Electron backports Chromium
//! security fixes only to the current + last two majors, so a pinned major more
//! than N-2 behind stable is a security-stale build. The CI script
//! (scripts/check-electron-patch-cadence.mjs) fetches npm's latest stable
//! major and fails the build if the pin is too old — with a graceful
//! skip-not-fail on a network error (the gate's job is to catch a stale pin, not
//! to enforce network reachability).

/** True when a pinned major is within the supported window (>= latest - 2). */
export function isSupportedMajor(pinnedMajor: number, latestMajor: number): boolean {
	return pinnedMajor >= latestMajor - 2;
}

/** Extract the major from a package.json version range, e.g. "^43.0.0" → 43. */
export function parseMajor(range: string): number {
	const m = range.match(/(\d+)/);
	if (!m) throw new Error(`cannot parse Electron major from "${range}"`);
	return Number.parseInt(m[1], 10);
}

/**
 * Fetch the latest stable Electron major from npm's authoritative `latest`
 * dist-tag. The former releases.electronjs.org JSON endpoint now redirects to
 * HTML, which made this gate skip forever. Returns null on any bounded
 * network/parse error so an outage is reported as an explicit skip.
 */
export async function fetchLatestElectronMajor(
	fetchImpl: typeof fetch = fetch,
): Promise<number | null> {
	try {
		const resp = await fetchImpl('https://registry.npmjs.org/electron/latest', {
			headers: { Accept: 'application/json' },
			signal: AbortSignal.timeout(10_000),
		});
		if (!resp.ok) return null;
		const data = (await resp.json()) as { version?: unknown };
		const major = Number.parseInt(String(data.version ?? '').split('.')[0] ?? '', 10);
		return !Number.isNaN(major) && major > 0 ? major : null;
	} catch {
		return null;
	}
}
