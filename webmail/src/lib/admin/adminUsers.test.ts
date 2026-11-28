// Vitest tests for adminUsers helpers (M7 Task 10).
import { describe, it, expect } from 'vitest';
import { roleBadgeVariant, statusBadge, mfaDisplay, storageDisplay } from './adminUsers';

describe('roleBadgeVariant', () => {
	it('maps super_admin → accent', () => {
		expect(roleBadgeVariant('super_admin')).toBe('accent');
	});
	it('maps user_admin → info', () => {
		expect(roleBadgeVariant('user_admin')).toBe('info');
	});
	it('maps auditor → warning', () => {
		expect(roleBadgeVariant('auditor')).toBe('warning');
	});
	it('maps user → neutral', () => {
		expect(roleBadgeVariant('user')).toBe('neutral');
	});
	it('maps unknown → neutral', () => {
		expect(roleBadgeVariant('unknown')).toBe('neutral');
	});
});

describe('statusBadge', () => {
	it('maps active → success variant + Active label', () => {
		expect(statusBadge('active')).toEqual({ variant: 'success', label: 'Active' });
	});
	it('maps locked → danger variant + Locked label', () => {
		expect(statusBadge('locked')).toEqual({ variant: 'danger', label: 'Locked' });
	});
	it('maps pending → neutral variant + Pending label', () => {
		expect(statusBadge('pending')).toEqual({ variant: 'neutral', label: 'Pending' });
	});
	it('maps unknown → neutral variant + raw string label', () => {
		expect(statusBadge('custom')).toEqual({ variant: 'neutral', label: 'custom' });
	});
});

describe('mfaDisplay', () => {
	it('returns "passkey" unchanged', () => expect(mfaDisplay('passkey')).toBe('passkey'));
	it('returns "totp" unchanged', () => expect(mfaDisplay('totp')).toBe('totp'));
	it('returns "—" for null', () => expect(mfaDisplay(null)).toBe('—'));
	it('returns "—" for undefined', () => expect(mfaDisplay(undefined)).toBe('—'));
	it('returns "—" for empty string', () => expect(mfaDisplay('')).toBe('—'));
});

describe('storageDisplay', () => {
	it('formats bytes', () => expect(storageDisplay(500)).toBe('500 B'));
	it('formats KB', () => expect(storageDisplay(1536)).toBe('1.5 KB'));
	it('formats MB', () => expect(storageDisplay(5 * 1024 * 1024)).toBe('5.0 MB'));
	it('formats GB', () => expect(storageDisplay(3.5 * 1024 * 1024 * 1024)).toBe('3.5 GB'));
	it('returns "—" for null', () => expect(storageDisplay(null)).toBe('—'));
	it('returns "—" for undefined', () => expect(storageDisplay(undefined)).toBe('—'));
});
