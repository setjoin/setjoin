import { describe, it, expect } from 'vitest';
import { CONSOLES, navForConsoles, type ConsoleId } from './consoles';
import en from '$lib/i18n/en';
import zh from '$lib/i18n/zh';
import de from '$lib/i18n/de';

// All existing admin routes from mailserver/webmail/AGENTS.md that should be
// assigned to one of the four consoles. Pages that are sub-pages (e.g.
// /admin/mam/devices/[id]) are intentionally excluded as they are not top-level
// sidebar items.
const EXISTING_ADMIN_ROUTES = [
	// Mail admin pages (mailserver/webmail/AGENTS.md Mail admin table)
	'/admin',                       // dashboard
	'/admin/domains',
	'/admin/mailboxes',
	'/admin/departments',
	'/admin/quarantine',
	'/admin/queue',
	'/admin/background-jobs',
	'/admin/dmarc',
	'/admin/dns',
	'/admin/tls',
	'/admin/spam',
	'/admin/retention',
	'/admin/storage',
	'/admin/rules',
	'/admin/migration',
	'/admin/exchange-replacement',
	'/admin/reports',
	'/admin/trace',
	'/admin/ediscovery',
	'/admin/content-search',
	'/admin/mam/devices',
	'/admin/mam/policies',
	// Auth admin pages (mailserver/webmail/AGENTS.md Identity admin table)
	'/admin/users',
	'/admin/conditional-access',
	'/admin/identity',
	'/admin/device-lockdown',
	// System pages (mailserver/webmail/AGENTS.md System table)
	'/admin/system',
	'/admin/deploy',
	'/admin/features',
	'/admin/updates',
	'/admin/logs',
	'/admin/webhooks',
	'/admin/recovery',
	// Logs & threats console pages (B6 threat read-APIs + auth log + alerts)
	'/admin/threats',
	'/admin/alerts',
	'/admin/audit',
	'/admin/auth-log',
	// Access console (RBAC role-group editor)
	'/admin/roles',
];

describe('consoles', () => {
	it('has exactly 5 console entries', () => {
		expect(CONSOLES).toHaveLength(5);
	});

	it('each console has id, icon, label, and non-empty items array', () => {
		for (const c of CONSOLES) {
			expect(c.id).toBeTruthy();
			expect(c.icon).toBeTruthy();
			expect(c.label).toBeTruthy();
			expect(Array.isArray(c.items)).toBe(true);
			expect(c.items.length).toBeGreaterThan(0);
		}
	});

	it('each nav item has label, path, and icon', () => {
		for (const c of CONSOLES) {
			for (const item of c.items) {
				expect(item.label).toBeTruthy();
				expect(item.path).toBeTruthy();
				expect(item.icon).toBeTruthy();
			}
		}
	});

	it('every console and navigation label exists in every locale', () => {
		const labels = CONSOLES.flatMap((console) => [
			console.label,
			...console.items.map((item) => item.label),
		]);
		for (const [locale, messages] of Object.entries({ en, zh, de })) {
			for (const label of labels) {
				expect(messages[label], `${locale} is missing ${label}`).toBeTruthy();
			}
		}
	});

	it('every item path starts with /admin', () => {
		for (const c of CONSOLES) {
			for (const item of c.items) {
				expect(item.path, `"${item.path}" does not start with /admin`).toMatch(/^\/admin/);
			}
		}
	});

	it('console ids are the five expected values matching Go admin.ConsoleID', () => {
		const ids = CONSOLES.map((c) => c.id);
		expect(ids).toContain('mail');
		expect(ids).toContain('system');
		expect(ids).toContain('logs');
		expect(ids).toContain('auth');
		expect(ids).toContain('access');
	});

	it('system console includes the welcome-email page with a registered icon', () => {
		const system = CONSOLES.find((c) => c.id === 'system');
		expect(system).toBeTruthy();
		const item = system!.items.find((i) => i.path === '/admin/system/welcome-email');
		expect(item).toBeTruthy();
		expect(item!.label).toBe('admin.sidebar.welcome_email');
		expect(item!.icon).toBe('Mail');
	});

	it('auth console includes device-lockdown with Fingerprint icon', () => {
		const auth = CONSOLES.find((c) => c.id === 'auth');
		expect(auth).toBeTruthy();
		const item = auth!.items.find((i) => i.path === '/admin/device-lockdown');
		expect(item).toBeTruthy();
		expect(item!.label).toBe('admin.sidebar.device_lockdown');
		expect(item!.icon).toBe('Fingerprint');
	});

	it('access console includes the permission-gated guest administration page', () => {
		const access = CONSOLES.find((c) => c.id === 'access');
		const item = access?.items.find((i) => i.path === '/admin/guests');
		expect(item).toMatchObject({
			label: 'admin.sidebar.guests',
			icon: 'Users',
			perm: ['guests.view', 'guests.manage'],
		});
	});

	it('mail console includes the background-jobs page with a registered icon', () => {
		const mail = CONSOLES.find((c) => c.id === 'mail');
		expect(mail).toBeTruthy();
		const item = mail!.items.find((i) => i.path === '/admin/background-jobs');
		expect(item).toBeTruthy();
		expect(item!.label).toBe('admin.sidebar.background_jobs');
		expect(item!.icon).toBe('ListChecks');
	});

	it('access console maps to the roles page', () => {
		const access = CONSOLES.find((c) => c.id === 'access');
		expect(access).toBeTruthy();
		expect(access!.items.some((i) => i.path === '/admin/roles')).toBe(true);
	});

	it('system.recovery is reachable only through the access console', () => {
		const access = CONSOLES.find((c) => c.id === 'access')!;
		const system = CONSOLES.find((c) => c.id === 'system')!;
		expect(access.items.find((i) => i.path === '/admin/recovery')).toMatchObject({
			perm: 'system.recovery',
			icon: 'RotateCcw',
		});
		expect(system.items.some((i) => i.path === '/admin/recovery')).toBe(false);
		expect(navForConsoles(['access'])[0].items.some((i) => i.path === '/admin/recovery')).toBe(true);
	});

	it('drive.view surfaces live in the ACCESS console, never system (consolidated-review fix)', () => {
		// Go's ConsoleScopes[system] also derives the requireSystemPerm route
		// guard, so drive.view can never ride the system console; the pages ride
		// access (the sharing.read/chat.compliance_view visibility precedent) so
		// a drive.view-only admin can actually reach them.
		const access = CONSOLES.find((c) => c.id === 'access')!;
		const system = CONSOLES.find((c) => c.id === 'system')!;
		for (const path of ['/admin/drive', '/admin/meet-recordings']) {
			const item = access.items.find((i) => i.path === path);
			expect(item, `${path} missing from access console`).toBeTruthy();
			expect(item!.perm).toBe('drive.view');
			expect(system.items.some((i) => i.path === path)).toBe(false);
		}
	});

	it('navForConsoles filters to only the requested consoles', () => {
		const logs = navForConsoles(['logs']);
		expect(logs).toHaveLength(1);
		expect(logs[0].id).toBe('logs');

		const multi = navForConsoles(['mail', 'auth']);
		expect(multi).toHaveLength(2);
		expect(multi.map((c) => c.id)).toEqual(['mail', 'auth']);
	});

	it('navForConsoles with empty array returns empty array', () => {
		expect(navForConsoles([])).toEqual([]);
	});

	it('navForConsoles preserves declared order', () => {
		const reversed = navForConsoles(['auth', 'logs']);
		expect(reversed.map((c) => c.id)).toEqual(['logs', 'auth']);
	});

	it('every existing admin route is covered by the union of all CONSOLES items', () => {
		const coveredPaths = new Set<string>();
		for (const c of CONSOLES) {
			for (const item of c.items) {
				coveredPaths.add(item.path);
			}
		}
		for (const route of EXISTING_ADMIN_ROUTES) {
			expect(coveredPaths.has(route),
				`Route "${route}" is not assigned to any console`).toBe(true);
		}
	});

	it('no duplicate paths across consoles', () => {
		const seen = new Map<string, string>();
		for (const c of CONSOLES) {
			for (const item of c.items) {
				if (seen.has(item.path)) {
					expect.fail(
						`Path "${item.path}" appears in both "${seen.get(item.path)}" and "${c.id}"`);
				}
				seen.set(item.path, c.id);
			}
		}
		// If we get here, no duplicates
		expect(true).toBe(true);
	});

	it('does not advertise the retired server-update mutation surface in navigation', () => {
		const paths = CONSOLES.flatMap((console) => console.items.map((item) => item.path));
		expect(paths).not.toContain('/admin/updates/server');
	});

	it('ConsoleId type accepts only valid console ids', () => {
		// Type-level test: these assignments should compile
		const _a: ConsoleId = 'mail';
		const _b: ConsoleId = 'system';
		const _c: ConsoleId = 'logs';
		const _d: ConsoleId = 'auth';
		const _e: ConsoleId = 'access';
		// Avoid unused warnings
		expect([_a, _b, _c, _d, _e]).toHaveLength(5);
	});
});
