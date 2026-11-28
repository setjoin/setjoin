/**
 * Tests for audit.ts helpers — action chips, severity badges, time formatting.
 */

import { describe, it, expect } from 'vitest';
import {
	auditActionChip,
	severityBadgeVariant,
	alertSeverity,
	formatAuditTime,
	formatAuditTarget,
	type SeverityLevel,
} from './audit';

describe('severityBadgeVariant', () => {
	it('maps danger → danger', () => {
		expect(severityBadgeVariant('danger')).toBe('danger');
	});

	it('maps warning → warning', () => {
		expect(severityBadgeVariant('warning')).toBe('warning');
	});

	it('maps info → info', () => {
		expect(severityBadgeVariant('info')).toBe('info');
	});

	it('maps unknown strings → neutral', () => {
		expect(severityBadgeVariant('unknown')).toBe('neutral');
	});

	it('maps empty string → neutral', () => {
		expect(severityBadgeVariant('')).toBe('neutral');
	});
});

describe('alertSeverity', () => {
	it('returns danger for suppressed alerts', () => {
		expect(alertSeverity(5, true)).toBe('danger');
		expect(alertSeverity(1, true)).toBe('danger');
		expect(alertSeverity(0, true)).toBe('danger');
	});

	it('returns warning for firing alerts with >=3 consecutive failures', () => {
		expect(alertSeverity(3, false)).toBe('warning');
		expect(alertSeverity(5, false)).toBe('warning');
		expect(alertSeverity(10, false)).toBe('warning');
	});

	it('returns info for firing alerts with 1-2 consecutive failures', () => {
		expect(alertSeverity(1, false)).toBe('info');
		expect(alertSeverity(2, false)).toBe('info');
	});

	it('returns neutral for zero-consecutive (healthy)', () => {
		expect(alertSeverity(0, false)).toBe('neutral');
	});
});

describe('auditActionChip', () => {
	it('returns the action slug unchanged for known formats', () => {
		expect(auditActionChip('user.create')).toBe('user.create');
		expect(auditActionChip('login.success')).toBe('login.success');
		expect(auditActionChip('ip.tarpit')).toBe('ip.tarpit');
	});

	it('returns the action as-is', () => {
		expect(auditActionChip('retention.run')).toBe('retention.run');
	});

	it('handles empty string', () => {
		expect(auditActionChip('')).toBe('');
	});
});

describe('formatAuditTime', () => {
	it('formats RFC3339 timestamp to HH:MM:SS', () => {
		expect(formatAuditTime('2026-06-15T09:41:07Z')).toBe('09:41:07');
		expect(formatAuditTime('2026-06-15T14:05:30Z')).toBe('14:05:30');
		expect(formatAuditTime('2026-06-15T00:00:00Z')).toBe('00:00:00');
	});

	it('handles date-only ISO strings (no TZ suffix)', () => {
		expect(formatAuditTime('2026-06-15T09:41:07')).toBe('09:41:07');
	});

	it('handles time-only string (slice)', () => {
		expect(formatAuditTime('09:41:07')).toBe('09:41:07');
	});

	it('returns original string for unparseable input', () => {
		expect(formatAuditTime('not-a-date')).toBe('not-a-date');
	});

	it('handles empty string gracefully', () => {
		expect(formatAuditTime('')).toBe('');
	});
});

describe('formatAuditTarget', () => {
	it('returns type with id when both present', () => {
		expect(formatAuditTarget('mailbox', 42)).toBe('mailbox #42');
	});

	it('returns only type when id is null', () => {
		expect(formatAuditTarget('mailbox', null)).toBe('mailbox');
	});

	it('returns only type when id is undefined', () => {
		expect(formatAuditTarget('user', undefined)).toBe('user');
	});

	it('returns empty string when type is null and no id', () => {
		expect(formatAuditTarget(null, null)).toBe('');
	});

	it('formats string type with numeric id', () => {
		expect(formatAuditTarget('domain', 7)).toBe('domain #7');
	});
});
