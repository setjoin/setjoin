import { describe, expect, it } from 'vitest';
import type { AppId } from '$lib/types/jmap';
import { APP_ORDER, APP_PATHS, RAIL_APPS, appForPath } from './navConfig';

const EXPECTED_APPS: readonly AppId[] = [
	'mail',
	'calendar',
	'contacts',
	'tasks',
	'approvals',
	'drive',
	'chat',
	'meet',
];

describe('capability app catalog', () => {
	it('is exhaustive, unique, and preserves the canonical launch order', () => {
		expect(APP_ORDER).toEqual(EXPECTED_APPS);
		expect(new Set(APP_ORDER).size).toBe(APP_ORDER.length);
		expect(RAIL_APPS.map((app) => app.id)).toEqual(APP_ORDER);
	});

	it('derives exactly one canonical landing path for every app', () => {
		expect(Object.keys(APP_PATHS).sort()).toEqual([...EXPECTED_APPS].sort());
		for (const app of RAIL_APPS) {
			expect(APP_PATHS[app.id]).toBe(app.path);
			expect(app.prefixes).toContain(app.path);
			expect(appForPath(app.path)).toBe(app.id);
		}
	});

	it.each(RAIL_APPS.flatMap((app) => [
		[app.path, app.id],
		[`${app.path}/nested`, app.id],
	] as const))('maps %s to %s', (pathname, app) => {
		expect(appForPath(pathname)).toBe(app);
	});

	it.each(RAIL_APPS.flatMap((app) => [
		`${app.path}ty`,
		`${app.path}-legacy`,
	] as const))('does not classify the near-prefix path %s', (pathname) => {
		expect(appForPath(pathname)).toBeNull();
	});

	it.each(['/', '/apps', '/settings', '/admin', '/blocked', '/chatty']) (
		'does not classify non-app path %s',
		(pathname) => expect(appForPath(pathname)).toBeNull(),
	);
});
