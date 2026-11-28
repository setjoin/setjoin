import { describe, expect, it } from 'vitest';
import { mailWorkMatchesFilter, type MailWorkItem } from './mailWork';

const item = (status: MailWorkItem['status'], assigneeUserId: string | null = null): MailWorkItem => ({
	id: 'thread-1', threadId: 'thread-1', status, assigneeUserId, dueAt: null, generation: '1',
});

describe('mailWorkMatchesFilter', () => {
	it('treats a missing projection as unassigned', () => {
		expect(mailWorkMatchesFilter(undefined, 'unassigned', '7')).toBe(true);
		expect(mailWorkMatchesFilter(undefined, 'owned', '7')).toBe(false);
	});

	it('shows only active work assigned to the current user in Mine', () => {
		expect(mailWorkMatchesFilter(item('owned', '7'), 'mine', '7')).toBe(true);
		expect(mailWorkMatchesFilter(item('waiting', '7'), 'mine', '7')).toBe(true);
		expect(mailWorkMatchesFilter(item('done', '7'), 'mine', '7')).toBe(false);
		expect(mailWorkMatchesFilter(item('owned', '8'), 'mine', '7')).toBe(false);
		expect(mailWorkMatchesFilter(item('owned', '7'), 'mine', null)).toBe(false);
	});

	it('matches exact reducer statuses and keeps All inclusive', () => {
		expect(mailWorkMatchesFilter(item('waiting'), 'waiting', '7')).toBe(true);
		expect(mailWorkMatchesFilter(item('waiting'), 'owned', '7')).toBe(false);
		expect(mailWorkMatchesFilter(item('done'), 'all', '7')).toBe(true);
	});

	it('uses server breach evidence and a bounded 24-hour due-soon window', () => {
		const now = new Date('2026-08-11T00:00:00Z');
		expect(mailWorkMatchesFilter({ ...item('owned'), dueAt: '2026-08-11T12:00:00Z' }, 'due_soon', '7', now)).toBe(true);
		expect(mailWorkMatchesFilter({ ...item('owned'), dueAt: '2026-08-13T00:00:00Z' }, 'due_soon', '7', now)).toBe(false);
		expect(mailWorkMatchesFilter({ ...item('owned'), slaBreachedAt: '2026-08-10T23:00:00Z' }, 'breached', '7', now)).toBe(true);
		expect(mailWorkMatchesFilter({ ...item('done'), slaBreachedAt: '2026-08-10T23:00:00Z' }, 'breached', '7', now)).toBe(false);
	});
});
