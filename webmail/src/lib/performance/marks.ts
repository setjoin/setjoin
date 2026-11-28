export type SetjoinPerformanceMark =
	| 'public-visible'
	| 'public-interactive'
	| 'shell-visible'
	| 'inbox-list-visible'
	| 'inbox-interactive';

/**
 * Record a product-readiness mark once per document. These names describe
 * useful UI states, not arbitrary timers, and intentionally contain no user
 * or mailbox data.
 */
export function markProductReady(name: SetjoinPerformanceMark): void {
	if (typeof performance === 'undefined' || typeof performance.mark !== 'function') return;
	if (performance.getEntriesByName(name, 'mark').length > 0) return;
	performance.mark(name);
}

/** Record interactivity after the browser has had one opportunity to paint. */
export function markProductInteractive(name: SetjoinPerformanceMark): () => void {
	if (typeof requestAnimationFrame !== 'function') {
		markProductReady(name);
		return () => {};
	}
	const frame = requestAnimationFrame(() => markProductReady(name));
	return () => cancelAnimationFrame(frame);
}
