/**
 * SPA per-console route guards (S6 layer 1 — UX only).
 *
 * The real security boundary is the server-side RequirePerm 403; these helpers
 * prevent the shell from rendering a broken page when a user navigates directly
 * to a console they cannot see. Unknown paths default to allowed (no false
 * lockout).
 */
import { CONSOLES, type ConsoleId } from './consoles';

/**
 * Resolve which console a given admin path belongs to by longest-prefix match
 * over every nav item across all four consoles. Returns null for unknown paths
 * (which are allowed — no false lockout; the server enforces 403).
 */
export function consoleForPath(pathname: string): ConsoleId | null {
	let best: { console: ConsoleId; len: number } | null = null;
	for (const c of CONSOLES) {
		for (const item of c.items) {
			// Exact match
			if (item.path === pathname) return c.id;
			// Prefix match for sub-paths (e.g. /admin/users/123 matching /admin/users).
			// Skip /admin as a prefix because it would match everything.
			if (item.path !== '/admin' && pathname.startsWith(item.path + '/')) {
				const len = item.path.length;
				if (!best || len > best.len) {
					best = { console: c.id, len };
				}
			}
		}
	}
	return best?.console ?? null;
}

/**
 * Returns true when the path may be rendered for the given console set.
 * - `/admin` root is always accessible (the layout entry point).
 * - Paths whose console cannot be resolved default to allowed (no false lockout).
 * - Otherwise the path's console must be in the user's set.
 */
export function allowedPath(pathname: string, consoles: ConsoleId[]): boolean {
	// The layout root is always accessible.
	if (pathname === '/admin') return true;
	const c = consoleForPath(pathname);
	// Unknown paths: allow (no false lockout — server enforces 403).
	if (!c) return true;
	return consoles.includes(c);
}

/**
 * Return the first navigable path for a set of consoles. Falls back to /apps
 * when the user holds no consoles.
 */
export function firstConsolePath(consoles: ConsoleId[]): string {
	if (consoles.length === 0) return '/apps';
	const def = CONSOLES.find((c) => c.id === consoles[0]);
	if (def && def.items.length > 0) return def.items[0].path;
	return '/apps';
}
