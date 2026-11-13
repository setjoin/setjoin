import { describe, it, expect } from 'vitest';
import { roleBadgeVariant, statusBadgeVariant, statusBadgeLabel } from './userHelpers';

describe('roleBadgeVariant', () => {
	it('returns "accent" for super_admin', () => {
		expect(roleBadgeVariant('super_admin')).toBe('accent');
	});

	it('returns "info" for user_admin', () => {
		expect(roleBadgeVariant('user_admin')).toBe('info');
	});

	it('returns "warning" for auditor', () => {
		expect(roleBadgeVariant('auditor')).toBe('warning');
	});

	it('returns "neutral" for user (or any unknown role)', () => {
		expect(roleBadgeVariant('user')).toBe('neutral');
		expect(roleBadgeVariant('read_only')).toBe('neutral');
		expect(roleBadgeVariant('')).toBe('neutral');
	});
});

describe('statusBadgeVariant', () => {
	it('returns "success" for active', () => {
		expect(statusBadgeVariant('active')).toBe('success');
	});

	it('returns "danger" for locked', () => {
		expect(statusBadgeVariant('locked')).toBe('danger');
	});

	it('returns "neutral" for pending', () => {
		expect(statusBadgeVariant('pending')).toBe('neutral');
	});

	it('returns "neutral" for unknown status', () => {
		expect(statusBadgeVariant('unknown')).toBe('neutral');
	});
});

describe('statusBadgeLabel', () => {
	it('returns human-readable labels', () => {
		expect(statusBadgeLabel('active')).toBe('Active');
		expect(statusBadgeLabel('locked')).toBe('Locked');
		expect(statusBadgeLabel('pending')).toBe('Pending');
	});

	it('returns raw status for unknown values', () => {
		expect(statusBadgeLabel('unknown')).toBe('unknown');
	});
});
