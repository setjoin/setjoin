// Pagination math — kept in a plain module so it is unit-testable without the DOM.

function fmt(n: number): string {
	// 'en-US' pinned for deterministic comma grouping ("1,283") across environments.
	return n.toLocaleString('en-US');
}

/** Total number of pages; never less than 1. */
export function pageCount(total: number, pageSize: number): number {
	if (pageSize <= 0) return 1;
	return Math.max(1, Math.ceil(total / pageSize));
}

/** Range label in the form "1–50 of 1,283" (en dash). `page` is 1-based. */
export function formatRange(page: number, pageSize: number, total: number): string {
	if (total <= 0) return '0 of 0';
	const start = (page - 1) * pageSize + 1;
	const end = Math.min(page * pageSize, total);
	return `${fmt(start)}–${fmt(end)} of ${fmt(total)}`;
}
