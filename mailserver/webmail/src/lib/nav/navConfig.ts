/**
 * Shared navigation configuration for app rail and mobile drawer.
 * Extracted to avoid copy-paste between AppRail.svelte and GlobalDrawer.svelte.
 * This module is the single source of truth for capability-app order, landing
 * paths, route ownership, rail/drawer/launcher entries, and app-route guards.
 * Labels are resolved at the consumer via t(`app.${id}`) / t(`admin.console.${id}`).
 */
import type { AppId } from '$lib/types/jmap';
import type { ConsoleId } from '$lib/admin/consoles';
import type { IconName } from '$lib/components/Icon.svelte';

/** Re-exported from ConsoleId — single source of truth. */
export type AdminConsoleId = ConsoleId;

export interface NavApp {
	id: AppId;
	icon: IconName;
	path: string;
	prefixes: readonly string[];
}

export interface NavAdmin {
	id: AdminConsoleId;
	icon: IconName;
	path: string;
}

export const RAIL_APPS = [
	{ id: 'mail',      icon: 'Inbox',          path: '/inbox',     prefixes: ['/inbox'] },
	{ id: 'calendar',  icon: 'Calendar',       path: '/calendar',  prefixes: ['/calendar'] },
	{ id: 'contacts',  icon: 'Users',          path: '/contacts',  prefixes: ['/contacts'] },
	{ id: 'tasks',     icon: 'SquareCheck',    path: '/tasks',     prefixes: ['/tasks'] },
	{ id: 'approvals', icon: 'ClipboardCheck', path: '/approvals', prefixes: ['/approvals'] },
	{ id: 'drive',     icon: 'HardDrive',      path: '/drive',     prefixes: ['/drive'] },
	{ id: 'chat',      icon: 'MessageCircle',  path: '/chat',      prefixes: ['/chat'] },
	{ id: 'meet',      icon: 'Video',          path: '/meet',      prefixes: ['/meet'] },
] as const satisfies readonly NavApp[];

/** Canonical app launch order, derived from the visible catalog. */
export const APP_ORDER: readonly AppId[] = RAIL_APPS.map((app) => app.id);

/** Canonical landing path for every capability app. */
export const APP_PATHS: Readonly<Record<AppId, string>> = Object.freeze(
	Object.fromEntries(RAIL_APPS.map((app) => [app.id, app.path])) as Record<AppId, string>,
);

function pathMatchesPrefix(pathname: string, prefix: string): boolean {
	return pathname === prefix || pathname.startsWith(`${prefix}/`);
}

/** Resolve a pathname to its capability app using exact path segments. */
export function appForPath(pathname: string): AppId | null {
	for (const app of RAIL_APPS) {
		if (app.prefixes.some((prefix) => pathMatchesPrefix(pathname, prefix))) return app.id;
	}
	return null;
}

/** Guest constrained-shell apps. Server capabilities still decide which of
 * these are enabled; this allowlist prevents fallback caps from widening it. */
export const GUEST_APPS: AppId[] = ['chat', 'meet'];

export const RAIL_ADMIN: NavAdmin[] = [
	{ id: 'mail',   icon: 'ServerCog',   path: '/admin' },
	{ id: 'system', icon: 'Cpu',         path: '/admin/system' },
	{ id: 'logs',   icon: 'ScrollText',  path: '/admin/audit' },
	{ id: 'auth',   icon: 'ShieldCheck', path: '/admin/auth' },
	{ id: 'access', icon: 'Key',         path: '/admin/roles' },
];
