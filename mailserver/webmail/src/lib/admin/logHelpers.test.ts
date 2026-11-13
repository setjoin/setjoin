import { describe, it, expect } from 'vitest';
import { logLevelBadgeVariant, eventBadgeVariant } from './logHelpers';

describe('logLevelBadgeVariant', () => {
	it('returns "danger" for error level', () => {
		expect(logLevelBadgeVariant('error')).toBe('danger');
	});

	it('returns "warning" for warn level', () => {
		expect(logLevelBadgeVariant('warn')).toBe('warning');
	});

	it('returns "warning" for warning level', () => {
		expect(logLevelBadgeVariant('warning')).toBe('warning');
	});

	it('returns "info" for info level', () => {
		expect(logLevelBadgeVariant('info')).toBe('info');
	});

	it('returns "neutral" for debug level', () => {
		expect(logLevelBadgeVariant('debug')).toBe('neutral');
	});

	it('returns "neutral" for trace level', () => {
		expect(logLevelBadgeVariant('trace')).toBe('neutral');
	});

	it('returns "neutral" for unknown level', () => {
		expect(logLevelBadgeVariant('unknown')).toBe('neutral');
	});

	it('is case-insensitive', () => {
		expect(logLevelBadgeVariant('ERROR')).toBe('danger');
		expect(logLevelBadgeVariant('WARN')).toBe('warning');
		expect(logLevelBadgeVariant('INFO')).toBe('info');
	});
});

describe('eventBadgeVariant', () => {
	it('returns "success" for login event', () => {
		expect(eventBadgeVariant('login')).toBe('success');
	});

	it('returns "danger" for login_failed event', () => {
		expect(eventBadgeVariant('login_failed')).toBe('danger');
	});

	it('returns "neutral" for unknown event', () => {
		expect(eventBadgeVariant('unknown')).toBe('neutral');
		expect(eventBadgeVariant('')).toBe('neutral');
	});
});
