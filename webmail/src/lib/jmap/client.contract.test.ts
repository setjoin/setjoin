import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as jmap from './client';

type Contract = [name: keyof typeof jmap, args: unknown[], method: string];

// Public helper-to-wire contracts. These exercise the actual request builder
// and ensure helper names cannot silently drift from the gateway method
// registry while still returning a conveniently empty result in UI tests.
const contracts: Contract[] = [
	['mailboxGet', [['m1'], 'shared'], 'Mailbox/get'],
	['emailQuery', [{ inMailbox: 'm1' }, [{ property: 'subject' }], 25, 10, undefined, 'shared'], 'Email/query'],
	['emailGet', [['e1'], ['id', 'bodyText'], undefined, 'shared'], 'Email/get'],
	['searchSnippetGet', [{ text: 'hello' }, ['e1'], 'shared'], 'SearchSnippet/get'],
	['emailSet', [{ c1: { subject: 'Hi' } }, { e1: { subject: 'Updated' } }, ['e2'], 'shared'], 'Email/set'],
	['identityGet', [], 'Identity/get'],
	['calendarGet', [['cal1']], 'Calendar/get'],
	['calendarEventQuery', [{ after: '2026-01-01' }, 20], 'CalendarEvent/query'],
	['calendarEventGet', [['ev1']], 'CalendarEvent/get'],
	['calendarEventSet', [{ c1: { title: 'Review' } }, { ev1: { title: 'Updated' } }, ['ev2']], 'CalendarEvent/set'],
	['calendarEventImport', ['cal1', 'BEGIN:VCALENDAR\nEND:VCALENDAR', 'skip'], 'CalendarEvent/import'],
	['calendarEventRsvp', ['ev1', 'accepted'], 'CalendarEvent/rsvp'],
	['calendarEventCounter', ['ev1', '2026-01-01T10:00:00Z', '2026-01-01T11:00:00Z'], 'CalendarEvent/counter'],
	['calendarEventQueryFreeSlots', [{ userIds: ['u1'], start: '2026-01-01T10:00:00Z', end: '2026-01-01T18:00:00Z' }], 'CalendarEvent/queryFreeSlots'],
	['calendarGetShared', ['owner@example.test'], 'Calendar/getShared'],
	['calendarEventGetShared', ['owner@example.test', '2026-01-01', '2026-02-01'], 'CalendarEvent/getShared'],
	['calendarShareGet', ['cal1'], 'Calendar/shareGet'],
	['calendarShareSet', ['cal1', [{ userEmail: 'user@example.test', level: 'read' }], [{ userEmail: 'old@example.test' }]], 'Calendar/shareSet'],
	['calendarDelegateList', [], 'Calendar/delegateList'],
	['calendarEventSetOccurrence', ['ev1', '20260101T100000Z', 'this', { title: 'Moved' }], 'CalendarEvent/setOccurrence'],
	['calendarEventResourceList', [], 'CalendarEvent/resourceList'],
	['calendarEventSendUpdate', ['ev1'], 'CalendarEvent/sendUpdate'],
	['calendarEventRsvpOnBehalf', ['ev1', 'declined', 'delegate@example.test'], 'CalendarEvent/rsvp'],
	['addressBookGet', [['ab1']], 'AddressBook/get'],
	['addressBookSet', [{ c1: { name: 'Personal' } }, { ab1: { name: 'People' } }, ['ab2']], 'AddressBook/set'],
	['contactQuery', [{ text: 'Ada' }, [{ property: 'name' }], 5, 25], 'ContactCard/query'],
	['contactGet', [['ct1'], ['id', 'name']], 'ContactCard/get'],
	['contactSet', [{ c1: { name: 'Ada' } }, { ct1: { name: 'Ada L.' } }, ['ct2']], 'ContactCard/set'],
	['galSearch', ['Ada', 10], 'ContactCard/galSearch'],
	['contactFindDuplicates', [], 'ContactCard/findDuplicates'],
	['contactMerge', ['ct1', 'ct2'], 'ContactCard/merge'],
	['contactGroupGet', [['g1']], 'ContactGroup/get'],
	['contactGroupQuery', [{ name: 'Team' }], 'ContactGroup/query'],
	['contactGroupSet', [{ c1: { name: 'Team' } }, { g1: { name: 'Core' } }, ['g2'], { groupId: 'g1', add: [] }], 'ContactGroup/set'],
	['contactGroupExpand', ['g1'], 'ContactGroup/expand'],
	['taskGet', [['t1']], 'Task/get'],
	['taskQuery', [{ status: 'open' }, 5, 20], 'Task/query'],
	['taskSet', [{ c1: { title: 'Review' } }, { t1: { title: 'Ship' } }, ['t2']], 'Task/set'],
	['taskActivityList', ['t1'], 'TaskComment/get'],
	['taskCommentCreate', ['t1', 'Looks good', ['reviewer@example.test']], 'TaskComment/set'],
	['taskListGet', [], 'TaskList/get'],
	['taskListSet', [{ c1: { name: 'Launch' } }, { l1: { name: 'Release' } }, ['l2']], 'TaskList/set'],
	['taskListMemberSet', ['l1', ['user@example.test'], ['old@example.test']], 'TaskListMember/set'],
	['taskListTasks', ['l1'], 'TaskList/tasks'],
	['taskListTaskSet', ['l1', ['t1', 't2']], 'TaskList/taskSet'],
	['taskAssignedGet', [], 'TaskAssigned/get'],
	['taskAssignedSetStatus', ['t1', 'done'], 'TaskAssigned/setStatus'],
	['emailSubmissionSet', [{ s1: { emailId: 'e1' } }], 'EmailSubmission/set'],
	['emailSubmissionCancel', ['e1', 'shared'], 'EmailSubmission/cancel'],
	['emailSubmissionQuery', [{ undoStatus: 'pending' }, 10], 'EmailSubmission/query'],
	['emailSubmissionGet', [['s1']], 'EmailSubmission/get'],
	['emailBundles', [10, 5], 'Email/bundles'],
	['emailNudges', [10, 5], 'Email/nudges'],
	['emailNudgeDismiss', ['th1'], 'Email/nudgeDismiss'],
	['threadGet', [['th1'], ['id', 'emailIds']], 'Thread/get'],
	['emailDeletedQuery', [20, 5], 'Email/deletedQuery'],
	['emailRecover', [['e1']], 'Email/recover'],
	['emailPurge', [['e1']], 'Email/purge'],
	['reminderGet', [], 'Reminder/get'],
	['reminderDismiss', ['r1'], 'Reminder/dismiss'],
	['reminderSnooze', ['r1', '2026-01-01T10:00:00Z'], 'Reminder/snooze'],
];

describe('JMAP helper method contracts', () => {
	let fetchMock: ReturnType<typeof vi.fn>;

	beforeEach(() => {
		fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input);
			if (url.includes('/.well-known/jmap')) {
				return {
					ok: true,
					status: 200,
					json: async () => ({ apiUrl: '/jmap', accounts: { a1: {} }, primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' }, sessionState: 's' }),
				};
			}
			const body = JSON.parse(String(init?.body ?? '{}'));
			const method = body.methodCalls?.[0]?.[0] ?? 'Unknown/method';
			return {
				ok: true,
				status: 200,
				json: async () => ({ methodResponses: [[method, { list: [], ids: [], created: {}, updated: {}, imported: 0, skipped: 0 }, '0']] }),
			};
		});
		vi.stubGlobal('fetch', fetchMock);
		vi.stubGlobal('window', { location: { href: '' } });
	});

	afterEach(() => vi.unstubAllGlobals());

	it.each(contracts)('%s emits %s', async (name, args, expectedMethod) => {
		const invoke = jmap[name] as unknown as (...values: unknown[]) => Promise<unknown>;
		await invoke(...args);
		const request = fetchMock.mock.calls.find(([, init]) => {
			try { return JSON.parse(String((init as RequestInit)?.body)).methodCalls?.[0]?.[0] === expectedMethod; }
			catch { return false; }
		});
		expect(request, `${String(name)} did not emit ${expectedMethod}`).toBeTruthy();
		const body = JSON.parse(String((request![1] as RequestInit).body));
		expect(body.using).toEqual(expect.arrayContaining(jmap.usingFor([expectedMethod])));
	});

	it('setMessageFocus preserves the result-bound REST endpoint', async () => {
		await jmap.setMessageFocus('mail/id', true);
		const [url, options] = fetchMock.mock.calls.at(-1) as [string, RequestInit];
		expect(url).toBe('/api/messages/mail%2Fid/focus');
		expect(options.method).toBe('POST');
		expect(JSON.parse(String(options.body))).toEqual({ focused: true });
	});
});
