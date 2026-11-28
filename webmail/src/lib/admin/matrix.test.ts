/**
 * Per-console permission -> view matrix verification (S6 two-layer).
 *
 * This test locks down spec §6.6 risk #5: "auditor least-privilege is a stated
 * product property". It verifies that:
 *
 *   1. The auditor (consoles=['logs']) sees ONLY Logs console nav items.
 *   2. The union of nav items across all four consoles has no duplicate paths
 *      (every page is assigned to exactly one console).
 *   3. Every CONSOLES path resolves to exactly one console via consoleForPath.
 *   4. navForConsoles respects declared order.
 */
import { describe, it, expect } from 'vitest';
import { CONSOLES, navForConsoles } from './consoles';
import { consoleForPath } from './guard';
import type { ConsoleId } from './consoles';

// ── 1. Auditor least-privilege ───────────────────────────────────────────────

describe('auditor least-privilege (navForConsoles)', () => {
	it('auditor (logs only) nav contains only Logs items', () => {
		const auditorConsoles: ConsoleId[] = ['logs'];
		const nav = navForConsoles(auditorConsoles);
		expect(nav).toHaveLength(1);
		expect(nav[0].id).toBe('logs');
	});

	it('auditor nav items are all Logs console paths', () => {
		const logsDef = CONSOLES.find((c) => c.id === 'logs')!;
		const auditorItems = navForConsoles(['logs'])[0].items;
		const logsPaths = new Set(logsDef.items.map((i) => i.path));
		for (const item of auditorItems) {
			expect(logsPaths.has(item.path)).toBe(true);
		}
	});

	it('auditor sees no auth console items', () => {
		const nav = navForConsoles(['logs']);
		const authDef = CONSOLES.find((c) => c.id === 'auth')!;
		const authPaths = new Set(authDef.items.map((i) => i.path));
		for (const c of nav) {
			for (const item of c.items) {
				expect(authPaths.has(item.path)).toBe(false);
			}
		}
	});

	it('auditor sees no mail console items', () => {
		const nav = navForConsoles(['logs']);
		const mailDef = CONSOLES.find((c) => c.id === 'mail')!;
		const mailPaths = new Set(mailDef.items.map((i) => i.path));
		for (const c of nav) {
			for (const item of c.items) {
				expect(mailPaths.has(item.path)).toBe(false);
			}
		}
	});

	it('auditor sees no system console items', () => {
		const nav = navForConsoles(['logs']);
		const systemDef = CONSOLES.find((c) => c.id === 'system')!;
		const systemPaths = new Set(systemDef.items.map((i) => i.path));
		for (const c of nav) {
			for (const item of c.items) {
				expect(systemPaths.has(item.path)).toBe(false);
			}
		}
	});
});

// ── 2. No duplicate paths across consoles ────────────────────────────────────

describe('no duplicate paths across consoles', () => {
	it('every path appears exactly once in CONSOLES', () => {
		const seen = new Map<string, string>(); // path -> console id
		const dupes: string[] = [];

		for (const c of CONSOLES) {
			for (const item of c.items) {
				if (seen.has(item.path)) {
					dupes.push(
						`${item.path} is in both "${seen.get(item.path)}" and "${c.id}"`,
					);
				}
				seen.set(item.path, c.id);
			}
		}

		expect(dupes).toEqual([]);
	});
});

// ── 3. Every CONSOLES path resolves to exactly one console ───────────────────

describe('consoleForPath resolves every CONSOLES path uniquely', () => {
	it('every nav item path maps to the console that owns it', () => {
		const mismatches: string[] = [];
		for (const c of CONSOLES) {
			for (const item of c.items) {
				const resolved = consoleForPath(item.path);
				if (resolved !== c.id) {
					mismatches.push(
						`${item.path}: expected "${c.id}", got "${resolved}"`,
					);
				}
			}
		}
		expect(mismatches).toEqual([]);
	});

	it('every nav item path maps to exactly one console (no ambiguous prefix)', () => {
		// Longest-prefix match means a path like /admin/updates/server
		// should not accidentally resolve to the shorter /admin/updates
		// unless they are in the same console.  This is already covered
		// by the uniqueness test above; this is a double-check.
		const mismatches: string[] = [];
		for (const c of CONSOLES) {
			for (const item of c.items) {
				// consoleForPath returns the console id (or null).
				const result = consoleForPath(item.path);
				if (result === null) {
					mismatches.push(`${item.path}: resolved to null (should be "${c.id}")`);
				}
			}
		}
		expect(mismatches).toEqual([]);
	});
});

// ── 4. Declared order ────────────────────────────────────────────────────────

describe('navForConsoles respects declared order', () => {
	it('returns [mail, system, logs, auth] in declared order regardless of input', () => {
		// navForConsoles filters CONSOLES in its declared order, not input order.
		// This matches Go's declaredOrder: [mail, system, logs, auth].
		const nav = navForConsoles(['auth', 'mail', 'logs', 'system']);
		expect(nav).toHaveLength(4);
		expect(nav[0].id).toBe('mail');
		expect(nav[1].id).toBe('system');
		expect(nav[2].id).toBe('logs');
		expect(nav[3].id).toBe('auth');
	});

	it('returns partial in declared order when given [auth, logs]', () => {
		const nav = navForConsoles(['auth', 'logs']);
		expect(nav).toHaveLength(2);
		expect(nav[0].id).toBe('logs');
		expect(nav[1].id).toBe('auth');
	});

	it('filters out unknown console ids silently', () => {
		const nav = navForConsoles(['mail' as ConsoleId, 'unknown' as ConsoleId]);
		expect(nav).toHaveLength(1);
		expect(nav[0].id).toBe('mail');
	});
});

// ── 5. Empty / all consoles ──────────────────────────────────────────────────

describe('navForConsoles edge cases', () => {
	it('returns empty array for empty input', () => {
		expect(navForConsoles([])).toEqual([]);
	});

	it('returns all four consoles when given all four', () => {
		const nav = navForConsoles(['mail', 'system', 'logs', 'auth']);
		expect(nav).toHaveLength(4);
	});

	it('each console has at least one nav item', () => {
		for (const c of CONSOLES) {
			expect(c.items.length).toBeGreaterThan(0);
		}
	});

	it('every console has an id, icon, and label', () => {
		for (const c of CONSOLES) {
			expect(c.id).toBeTruthy();
			expect(c.icon).toBeTruthy();
			expect(c.label).toBeTruthy();
		}
	});

	it('every nav item has a label, path starting with /admin, and icon', () => {
		for (const c of CONSOLES) {
			for (const item of c.items) {
				expect(item.label).toBeTruthy();
				expect(item.path).toMatch(/^\/admin/);
				expect(item.icon).toBeTruthy();
			}
		}
	});
});

// ── 6. Cross-console path isolation ──────────────────────────────────────────

describe('cross-console path isolation', () => {
	it('logs paths do not leak into other consoles', () => {
		const logsDef = CONSOLES.find((c) => c.id === 'logs')!;
		const logsPaths = new Set(logsDef.items.map((i) => i.path));
		for (const c of CONSOLES) {
			if (c.id === 'logs') continue;
			for (const item of c.items) {
				expect(logsPaths.has(item.path)).toBe(false);
			}
		}
	});

	it('auth paths do not leak into other consoles', () => {
		const authDef = CONSOLES.find((c) => c.id === 'auth')!;
		const authPaths = new Set(authDef.items.map((i) => i.path));
		for (const c of CONSOLES) {
			if (c.id === 'auth') continue;
			for (const item of c.items) {
				expect(authPaths.has(item.path)).toBe(false);
			}
		}
	});

	it('system paths do not leak into other consoles', () => {
		const systemDef = CONSOLES.find((c) => c.id === 'system')!;
		const systemPaths = new Set(systemDef.items.map((i) => i.path));
		for (const c of CONSOLES) {
			if (c.id === 'system') continue;
			for (const item of c.items) {
				expect(systemPaths.has(item.path)).toBe(false);
			}
		}
	});

	it('mail paths do not leak into other consoles', () => {
		const mailDef = CONSOLES.find((c) => c.id === 'mail')!;
		const mailPaths = new Set(mailDef.items.map((i) => i.path));
		for (const c of CONSOLES) {
			if (c.id === 'mail') continue;
			for (const item of c.items) {
				expect(mailPaths.has(item.path)).toBe(false);
			}
		}
	});
});
