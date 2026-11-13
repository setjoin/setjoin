export function isLocksSupported(): boolean {
	return typeof navigator !== 'undefined' && 'locks' in navigator;
}

// withSyncOwnership runs fn iff this window can immediately acquire the exclusive
// offline-sync lock. ifAvailable:true => the callback gets null when another
// window already owns it, so only one window ever syncs (review A2: no
// double-write race). Native shells are usually single-window, but the lock
// still guards the multi-window/multi-process case.
// ponytail: no-Locks fallback acts as owner — fine because native WebViews are
// single-window; if multi-window native ever ships, gate isLocksSupported() first.
export async function withSyncOwnership<T>(fn: () => Promise<T>): Promise<T | null> {
	if (!isLocksSupported()) return fn(); // ponytail: no-Locks fallback: act as owner
	return navigator.locks.request(
		'offline-sync',
		{ mode: 'exclusive', ifAvailable: true },
		async (lock) => (lock ? fn() : null)
	);
}
