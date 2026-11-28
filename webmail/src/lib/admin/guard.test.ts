import { describe, it, expect } from 'vitest';
import { consoleForPath, allowedPath, firstConsolePath } from './guard';
import type { ConsoleId } from './consoles';

describe('consoleForPath', () => {
	it('maps /admin/threats to logs', () => {
		expect(consoleForPath('/admin/threats')).toBe('logs');
	});

	it('maps /admin/users to auth', () => {
		expect(consoleForPath('/admin/users')).toBe('auth');
	});

	it('maps /admin/queue to mail', () => {
		expect(consoleForPath('/admin/queue')).toBe('mail');
	});

	it('maps /admin/features to system', () => {
		expect(consoleForPath('/admin/features')).toBe('system');
	});

	it('maps /admin/audit to logs', () => {
		expect(consoleForPath('/admin/audit')).toBe('logs');
	});

	it('maps /admin/alerts to logs', () => {
		expect(consoleForPath('/admin/alerts')).toBe('logs');
	});

	it('maps /admin to mail (dashboard is in mail console)', () => {
		expect(consoleForPath('/admin')).toBe('mail');
	});

	it('maps sub-path /admin/users/123 to auth', () => {
		expect(consoleForPath('/admin/users/123')).toBe('auth');
	});

	it('maps sub-path /admin/mam/devices/abc to mail', () => {
		expect(consoleForPath('/admin/mam/devices/abc')).toBe('mail');
	});

	it('returns null for unknown admin path', () => {
		expect(consoleForPath('/admin/xyz')).toBeNull();
	});

	it('returns null for non-admin path', () => {
		expect(consoleForPath('/inbox')).toBeNull();
	});

	it('maps the nested static server-update runbook through the client-updates prefix', () => {
		expect(consoleForPath('/admin/updates/server')).toBe('system');
	});
});

describe('allowedPath', () => {
	it('allows /admin root regardless of consoles', () => {
		expect(allowedPath('/admin', [])).toBe(true);
	});

	it('allows when console is in user set', () => {
		expect(allowedPath('/admin/users', ['auth'])).toBe(true);
	});

	it('rejects when console is NOT in user set', () => {
		expect(allowedPath('/admin/users', ['mail'])).toBe(false);
	});

	it('allows unknown paths (no false lockout)', () => {
		expect(allowedPath('/admin/xyz', [])).toBe(true);
	});

	it('allows non-admin paths (no false lockout)', () => {
		expect(allowedPath('/inbox', [])).toBe(true);
	});

	it('allows sub-path when user has the right console', () => {
		expect(allowedPath('/admin/users/42', ['auth'])).toBe(true);
	});

	it('rejects sub-path when user lacks the console', () => {
		expect(allowedPath('/admin/users/42', ['logs'])).toBe(false);
	});

	it('allows when user has multiple consoles', () => {
		expect(allowedPath('/admin/queue', ['mail', 'system'])).toBe(true);
	});

	it('rejects when user has different consoles only', () => {
		expect(allowedPath('/admin/queue', ['auth', 'logs'])).toBe(false);
	});
});

describe('firstConsolePath', () => {
	it('returns /admin for mail console (first item is dashboard)', () => {
		expect(firstConsolePath(['mail'])).toBe('/admin');
	});

	it('returns first system item when user has only system', () => {
		expect(firstConsolePath(['system'])).toBe('/admin/system');
	});

	it('returns first logs item when user has only logs', () => {
		expect(firstConsolePath(['logs'])).toBe('/admin/threats');
	});

	it('returns first auth item when user has only auth', () => {
		expect(firstConsolePath(['auth'])).toBe('/admin/users');
	});

	it('returns /apps when user has no consoles', () => {
		expect(firstConsolePath([])).toBe('/apps');
	});

	it('respects input order (which is the declared order from the server)', () => {
		// When server returns consoles in declared order [mail, auth], we pick
		// the first in that list (mail, not auth).
		expect(firstConsolePath(['mail', 'auth'])).toBe('/admin');
	});

	it('returns /apps for empty array (not undefined)', () => {
		const empty: ConsoleId[] = [];
		expect(firstConsolePath(empty)).toBe('/apps');
	});
});
