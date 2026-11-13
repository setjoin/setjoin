import { describe, it, expect } from 'vitest';
import { canConfirmGrant } from './sensitiveGrant';
import { seedEditorForm } from './roleEditor';
import { isExpiringSoon } from './memberExpiry';
import { sourceFor } from './effectivePerms';
import type { AdminRole } from '$lib/admin/roles';
import type { EffectivePerms } from '$lib/admin/roles';

// ---------------------------------------------------------------------------
// 1. canConfirmGrant (SensitiveGrantConfirm)
// ---------------------------------------------------------------------------
describe('canConfirmGrant', () => {
	it('returns false when requireType=true and typed does not match roleName', () => {
		expect(canConfirmGrant(true, 'wrong', 'Help Desk')).toBe(false);
	});

	it('returns false when requireType=true and typed is empty', () => {
		expect(canConfirmGrant(true, '', 'Help Desk')).toBe(false);
	});

	it('returns true when requireType=true and typed exactly matches roleName', () => {
		expect(canConfirmGrant(true, 'Help Desk', 'Help Desk')).toBe(true);
	});

	it('trims whitespace from typed before comparing', () => {
		expect(canConfirmGrant(true, '  Help Desk  ', 'Help Desk')).toBe(true);
	});

	it('returns true when requireType=false regardless of typed value', () => {
		expect(canConfirmGrant(false, '', 'Help Desk')).toBe(true);
		expect(canConfirmGrant(false, 'anything', 'Help Desk')).toBe(true);
	});

	it('is case-sensitive — mismatched casing returns false', () => {
		expect(canConfirmGrant(true, 'help desk', 'Help Desk')).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// 2. seedEditorForm (RoleEditorDialog)
// ---------------------------------------------------------------------------
const sampleRole: AdminRole = {
	id: 7,
	name: 'Help Desk',
	description: 'Tier-1 support',
	permissions: ['users.read', 'tickets.manage'],
	domainScope: null,
	isBuiltin: false,
	memberCount: 3,
	createdAt: '2026-01-01T00:00:00Z',
	updatedAt: '2026-01-02T00:00:00Z'
};

describe('seedEditorForm', () => {
	it('clone mode: name is empty, permissions copied from role', () => {
		const form = seedEditorForm('clone', sampleRole);
		expect(form.name).toBe('');
		expect(form.selected).toEqual(new Set(['users.read', 'tickets.manage']));
	});

	it('edit mode: name and permissions loaded from role', () => {
		const form = seedEditorForm('edit', sampleRole);
		expect(form.name).toBe('Help Desk');
		expect(form.selected).toEqual(new Set(['users.read', 'tickets.manage']));
	});

	it('create mode with null role: name empty, permissions empty', () => {
		const form = seedEditorForm('create', null);
		expect(form.name).toBe('');
		expect(form.selected.size).toBe(0);
	});

	it('clone mode preserves description from role', () => {
		const form = seedEditorForm('clone', sampleRole);
		expect(form.description).toBe('Tier-1 support');
	});

	it('edit mode preserves description from role', () => {
		const form = seedEditorForm('edit', sampleRole);
		expect(form.description).toBe('Tier-1 support');
	});

	it('create mode with undefined role: all fields empty', () => {
		const form = seedEditorForm('create', undefined);
		expect(form.name).toBe('');
		expect(form.description).toBe('');
		expect(form.selected.size).toBe(0);
	});
});

// ---------------------------------------------------------------------------
// 3. isExpiringSoon (RoleMembersPanel)
// ---------------------------------------------------------------------------
const NOW = new Date('2026-06-21T12:00:00Z').getTime();
const DAY_MS = 24 * 60 * 60 * 1000;

describe('isExpiringSoon', () => {
	it('returns true for expiry 1 day in the future (within 7-day window)', () => {
		const soon = new Date(NOW + DAY_MS).toISOString();
		expect(isExpiringSoon(soon, NOW)).toBe(true);
	});

	it('returns true for expiry exactly 6 days 23 hours 59 minutes in the future', () => {
		const borderline = new Date(NOW + 7 * DAY_MS - 60_000).toISOString();
		expect(isExpiringSoon(borderline, NOW)).toBe(true);
	});

	it('returns false for expiry already in the past', () => {
		const past = new Date(NOW - DAY_MS).toISOString();
		expect(isExpiringSoon(past, NOW)).toBe(false);
	});

	it('returns false for expiry more than 7 days in the future', () => {
		const far = new Date(NOW + 8 * DAY_MS).toISOString();
		expect(isExpiringSoon(far, NOW)).toBe(false);
	});

	it('returns false when expiresAt is null', () => {
		expect(isExpiringSoon(null, NOW)).toBe(false);
	});

	it('returns false when expiresAt is undefined', () => {
		expect(isExpiringSoon(undefined, NOW)).toBe(false);
	});

	it('returns false for expiry exactly at the boundary (now + 7 days, not within)', () => {
		const boundary = new Date(NOW + 7 * DAY_MS).toISOString();
		// delta === 7 * DAY_MS is NOT < 7 * DAY_MS, so should be false
		expect(isExpiringSoon(boundary, NOW)).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// 4. sourceFor (AccessPreview)
// ---------------------------------------------------------------------------
const permsData: EffectivePerms = {
	permissions: ['users.read', 'tickets.manage', 'system.config'],
	domainScope: null,
	sources: [
		{ roleGroupId: 1, roleName: 'Help Desk', permissions: ['users.read', 'tickets.manage'] },
		{ roleGroupId: 2, roleName: 'Admins', permissions: ['users.read', 'system.config'] }
	],
	consoles: []
};

describe('sourceFor', () => {
	it('returns single role name when only one source grants the permission', () => {
		expect(sourceFor(permsData, 'tickets.manage')).toBe('Help Desk');
	});

	it('returns comma-joined role names when multiple sources grant the permission', () => {
		expect(sourceFor(permsData, 'users.read')).toBe('Help Desk, Admins');
	});

	it('returns empty string when no source grants the permission', () => {
		expect(sourceFor(permsData, 'nonexistent.perm')).toBe('');
	});

	it('returns empty string when data is null', () => {
		expect(sourceFor(null, 'users.read')).toBe('');
	});

	it('returns empty string when data is undefined', () => {
		expect(sourceFor(undefined, 'users.read')).toBe('');
	});

	it('returns empty string when sources array is empty', () => {
		const empty: EffectivePerms = { permissions: ['users.read'], domainScope: null, sources: [], consoles: [] };
		expect(sourceFor(empty, 'users.read')).toBe('');
	});
});
