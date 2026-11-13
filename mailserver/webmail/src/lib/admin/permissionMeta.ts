import type { PermissionCatalogEntry } from './roles';

/** Group catalog entries by their category, preserving input order within each. */
export function groupByCategory(
	catalog: PermissionCatalogEntry[]
): Record<string, PermissionCatalogEntry[]> {
	const out: Record<string, PermissionCatalogEntry[]> = {};
	for (const p of catalog) {
		(out[p.category] ??= []).push(p);
	}
	return out;
}

/** Compute added/removed keys going from set `a` to set `b`. */
export function diffPerms(a: string[], b: string[]): { added: string[]; removed: string[] } {
	const sa = new Set(a);
	const sb = new Set(b);
	return {
		added: b.filter((k) => !sa.has(k)).sort(),
		removed: a.filter((k) => !sb.has(k)).sort(),
	};
}
