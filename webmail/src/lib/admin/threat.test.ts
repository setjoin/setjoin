import { describe, it, expect } from 'vitest';
import { riskBars, actionBadgeVariant, parseThreatResponse, type ThreatFlow } from './threat';

describe('riskBars', () => {
	it('returns 3 for high risk', () => {
		expect(riskBars('high')).toBe(3);
	});

	it('returns 2 for medium risk', () => {
		expect(riskBars('medium')).toBe(2);
	});

	it('returns 1 for low risk', () => {
		expect(riskBars('low')).toBe(1);
	});

	it('returns 0 for unknown risk level', () => {
		expect(riskBars('unknown' as 'high')).toBe(0);
	});

	it('returns 0 for empty string', () => {
		expect(riskBars('' as 'high')).toBe(0);
	});
});

describe('actionBadgeVariant', () => {
	it('returns danger for Block', () => {
		expect(actionBadgeVariant('Block')).toBe('danger');
	});

	it('returns warning for Tarpit', () => {
		expect(actionBadgeVariant('Tarpit')).toBe('warning');
	});

	it('returns info for CAPTCHA', () => {
		expect(actionBadgeVariant('CAPTCHA')).toBe('info');
	});

	it('returns info for Challenge', () => {
		expect(actionBadgeVariant('Challenge')).toBe('info');
	});

	it('returns success for Allow', () => {
		expect(actionBadgeVariant('Allow')).toBe('success');
	});

	it('returns success for Pass', () => {
		expect(actionBadgeVariant('Pass')).toBe('success');
	});

	it('returns neutral for unknown action', () => {
		expect(actionBadgeVariant('Unknown')).toBe('neutral');
	});
});

describe('parseThreatResponse', () => {
	const rawResponse = {
		rows: [
			{
				sourceIp: '185.220.101.1',
				targetUsername: 'user@example.com',
				protocol: 'IMAP',
				outcome: 'blocked',
				failureReason: 'spray_detection',
				geoCountry: 'NL',
				occurredAt: '2026-06-15T09:48:36Z',
			},
			{
				sourceIp: '10.0.0.1',
				targetUsername: 'admin@corp.com',
				protocol: 'SMTP AUTH',
				outcome: 'challenged',
				failureReason: 'captcha_required',
				geoCountry: 'US',
				occurredAt: '2026-06-15T09:50:00Z',
			},
			{
				sourceIp: '192.168.1.1',
				targetUsername: 'test@local.net',
				protocol: 'HTTPS',
				outcome: 'success',
				failureReason: '',
				geoCountry: 'DE',
				occurredAt: '2026-06-15T09:42:00Z',
			},
		],
		total: 3,
		limit: 100,
		offset: 0,
	};

	it('returns typed ThreatFlow array with correct length', () => {
		const result = parseThreatResponse(rawResponse);
		expect(result.flows).toHaveLength(3);
		expect(result.total).toBe(3);
	});

	it('maps sourceIp to src', () => {
		const result = parseThreatResponse(rawResponse);
		expect(result.flows[0].src).toBe('185.220.101.1');
		expect(result.flows[1].src).toBe('10.0.0.1');
	});

	it('maps geoCountry to country', () => {
		const result = parseThreatResponse(rawResponse);
		expect(result.flows[0].country).toBe('NL');
		expect(result.flows[1].country).toBe('US');
	});

	it('maps protocol to service', () => {
		const result = parseThreatResponse(rawResponse);
		expect(result.flows[0].service).toBe('IMAP');
		expect(result.flows[2].service).toBe('HTTPS');
	});

	it('derives risk from outcome — blocked = high', () => {
		const result = parseThreatResponse(rawResponse);
		expect(result.flows[0].risk).toBe('high');
	});

	it('derives risk from outcome — challenged = medium', () => {
		const result = parseThreatResponse(rawResponse);
		expect(result.flows[1].risk).toBe('medium');
	});

	it('derives risk from outcome — success = low', () => {
		const result = parseThreatResponse(rawResponse);
		expect(result.flows[2].risk).toBe('low');
	});

	it('derives action from outcome — blocked = Block', () => {
		const result = parseThreatResponse(rawResponse);
		expect(result.flows[0].action).toBe('Block');
	});

	it('derives action from outcome — challenged = CAPTCHA', () => {
		const result = parseThreatResponse(rawResponse);
		expect(result.flows[1].action).toBe('CAPTCHA');
	});

	it('derives action from outcome — success = Allow', () => {
		const result = parseThreatResponse(rawResponse);
		expect(result.flows[2].action).toBe('Allow');
	});

	it('maps failureReason to rule for blocked/challenged outcomes', () => {
		const result = parseThreatResponse(rawResponse);
		expect(result.flows[0].rule).toBe('spray_detection');
		expect(result.flows[1].rule).toBe('captcha_required');
	});

	it('maps targetUsername to dst', () => {
		const result = parseThreatResponse(rawResponse);
		expect(result.flows[0].dst).toBe('user@example.com');
	});

	it('formats occurredAt as 24h time', () => {
		const result = parseThreatResponse(rawResponse);
		// 2026-06-15T09:48:36Z should format as something like "09:48:36"
		expect(result.flows[0].time).toMatch(/^\d{2}:\d{2}(:\d{2})?/);
	});

	it('generates unique id for each flow', () => {
		const result = parseThreatResponse(rawResponse);
		const ids = result.flows.map((f) => f.id);
		expect(ids[0]).not.toBe(ids[1]);
		expect(ids[1]).not.toBe(ids[2]);
	});

	it('handles empty rows', () => {
		const result = parseThreatResponse({ rows: [], total: 0, limit: 100, offset: 0 });
		expect(result.flows).toHaveLength(0);
		expect(result.total).toBe(0);
	});

	it('handles rows with missing fields gracefully', () => {
		const result = parseThreatResponse({
			rows: [{} as Record<string, unknown>],
			total: 1,
			limit: 100,
			offset: 0,
		});
		expect(result.flows).toHaveLength(1);
		const f = result.flows[0];
		expect(f.src).toBe('');
		expect(f.country).toBe('');
		expect(f.risk).toBe('low');
		expect(f.action).toBe('Allow');
	});
});
