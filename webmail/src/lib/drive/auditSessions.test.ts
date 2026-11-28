import { describe, expect, it } from 'vitest';
import { groupSessions, type AuditRow } from './auditSessions';

const row = (id: number, min: number, userId: number, action = 'view'): AuditRow => ({
	id,
	occurredAt: new Date(Date.UTC(2026, 6, 9, 15, min)).toISOString(),
	userId,
	userEmail: `u${userId}@x`,
	ip: '10.0.0.1',
	action,
});

describe('groupSessions', () => {
	it('groups a 2h stream of view rows by one user into ONE session (3pm-5pm)', () => {
		// 9 view events, 15 min apart (gap < 30 min throughout)
		const rows = Array.from({ length: 9 }, (_, i) => row(100 - i, i * 15, 7));
		const s = groupSessions(rows);
		expect(s).toHaveLength(1);
		expect(s[0].count).toBe(9);
		expect(s[0].start).toContain('15:00');
		expect(s[0].end).toContain('17:00');
		expect(s[0].actions).toEqual({ view: 9 });
		expect(s[0].rows).toHaveLength(9); // drill-down keeps every per-access row
	});

	it('a gap >= 30 min splits the session', () => {
		const s = groupSessions([row(3, 0, 7), row(2, 10, 7), row(1, 45, 7)]);
		expect(s).toHaveLength(2);
	});

	it('different users never merge, even interleaved', () => {
		const s = groupSessions([row(4, 0, 7), row(3, 1, 8), row(2, 2, 7), row(1, 3, 8)]);
		expect(s).toHaveLength(2);
		expect(s.map((x) => x.userId).sort()).toEqual([7, 8]);
	});

	it('mixed actions tally per session', () => {
		const s = groupSessions([row(3, 0, 7, 'view'), row(2, 5, 7, 'version.create'), row(1, 9, 7, 'view')]);
		expect(s[0].actions).toEqual({ view: 2, 'version.create': 1 });
	});

	it('empty input -> empty output', () => {
		expect(groupSessions([])).toEqual([]);
	});

	it('never drops or dedupes a row — total row count across sessions equals input length', () => {
		const rows = [row(1, 0, 7), row(2, 5, 8), row(3, 40, 7), row(4, 45, 8)];
		const s = groupSessions(rows);
		const total = s.reduce((n, sess) => n + sess.rows.length, 0);
		expect(total).toBe(rows.length);
	});
});
