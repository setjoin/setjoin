import { afterEach, describe, expect, it, vi } from 'vitest';
import {
	addressBookGet,
	calendarEventGet,
	calendarEventGetShared,
	calendarEventImport,
	calendarEventQuery,
	calendarEventSet,
	calendarGet,
	calendarGetShared,
	contactFindDuplicates,
	contactGet,
	contactGroupExpand,
	contactGroupGet,
	contactGroupQuery,
	contactGroupSet,
	contactQuery,
	getDelegatedAccounts,
	emailBundles,
	emailDeletedQuery,
	emailGet,
	emailNudges,
	emailQuery,
	emailSubmissionGet,
	emailSubmissionQuery,
	galSearch,
	identityGet,
	mailboxGet,
	putBlob,
	searchSnippetGet,
	taskActivityList,
	taskAssignedGet,
	taskGet,
	taskListGet,
	taskListSet,
	taskListTaskSet,
	taskListTasks,
	taskQuery,
	taskSet,
	threadGet,
	assistComplete,
	usingFor,
} from './client';

function ok(method = 'Any/get', payload: unknown = {}) {
	return {
		ok: true,
		status: 200,
		json: async () => ({ sessionState: 's1', methodResponses: [[method, payload, '0']] }),
	};
}

describe('JMAP helper boundary fallbacks', () => {
	afterEach(() => vi.unstubAllGlobals());

	it('returns deterministic empty shapes when optional server collections are absent', async () => {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(ok()));
		expect(await mailboxGet()).toEqual([]);
		expect(await emailGet([])).toEqual([]);
		expect(await searchSnippetGet({ text: 'x' }, [])).toEqual([]);
		expect(await identityGet()).toEqual([]);
		expect(await calendarGet()).toEqual([]);
		expect(await calendarEventQuery({})).toEqual([]);
		expect(await calendarEventGet([])).toEqual([]);
		expect(await calendarGetShared('owner@example.test')).toEqual([]);
		expect(await calendarEventGetShared('owner@example.test')).toEqual([]);
		expect(await addressBookGet()).toEqual([]);
		expect(await contactQuery({}, undefined, undefined, undefined)).toEqual({ ids: [], total: undefined, position: undefined });
		expect(await contactGet([])).toEqual([]);
		expect(await galSearch('x')).toEqual([]);
		expect(await contactGroupGet()).toEqual([]);
		expect(await contactGroupQuery()).toEqual({ ids: [], total: undefined });
		expect(await contactGroupExpand('g')).toEqual([]);
		expect(await taskGet([])).toEqual([]);
		expect(await taskQuery({})).toEqual([]);
		expect(await taskActivityList('t')).toEqual([]);
		expect(await taskListGet()).toEqual([]);
		expect(await taskListTasks('l')).toEqual({ state: '0', list: [] });
		expect(await taskAssignedGet()).toEqual([]);
		expect(await emailSubmissionQuery()).toEqual({ ids: [], total: undefined, position: undefined });
		expect(await emailSubmissionGet([])).toEqual([]);
		expect(await emailBundles()).toEqual({ bundles: [], position: 0 });
		expect(await emailNudges()).toEqual([]);
		expect(await threadGet([])).toEqual([]);
		expect(await emailDeletedQuery()).toEqual({ list: [] });
	});

	it('preserves explicit optional query, paging, and date-range arguments', async () => {
		const fetchMock = vi.fn().mockResolvedValue(ok());
		vi.stubGlobal('fetch', fetchMock);
		await mailboxGet(['m1']);
		await emailQuery({}, [], 10, 25);
		await calendarGet(['c1']);
		await calendarEventGetShared('owner@example.test', '2026-01-01', '2026-02-01');
		await addressBookGet(['a1']);
		await contactGroupGet(['g1']);
		await contactGroupQuery({ name: 'team' });
		await emailSubmissionQuery({ state: 'pending' }, 5, 10);
		const bodies = fetchMock.mock.calls.map((call) => JSON.parse(call[1].body).methodCalls[0][1]);
		expect(bodies[0]).toEqual(expect.objectContaining({ ids: ['m1'] }));
		expect(bodies[1]).toEqual(expect.objectContaining({ position: 25, limit: 10 }));
		expect(bodies[3]).toEqual(expect.objectContaining({ after: '2026-01-01', before: '2026-02-01' }));
		expect(bodies.at(-1)).toEqual(expect.objectContaining({ filter: { state: 'pending' }, position: 5, limit: 10 }));
	});

	it('serializes every optional mutation section only when requested', async () => {
		const fetchMock = vi.fn().mockResolvedValue(ok('Any/set', {}));
		vi.stubGlobal('fetch', fetchMock);
		await calendarEventSet({ c: { title: 'new' } }, { e: { title: 'edit' } }, ['old']);
		await taskSet({ c: { title: 'new' } }, { e: { title: 'edit' } }, ['old']);
		await contactGroupSet({ c: { name: 'new' } }, { e: { name: 'edit' } }, ['old'], { groupId: 'g', add: [] });
		await taskListTaskSet('list', { c: { title: 'new' } }, { e: { title: 'edit' } }, ['old']);
		for (const call of fetchMock.mock.calls) {
			const args = JSON.parse(call[1].body).methodCalls[0][1];
			expect(args).toEqual(expect.objectContaining({ create: expect.any(Object), update: expect.any(Object), destroy: ['old'] }));
		}
	});

	it('omits every absent optional mutation section', async () => {
		const fetchMock = vi.fn().mockResolvedValue(ok('Any/set', {}));
		vi.stubGlobal('fetch', fetchMock);
		await calendarEventSet(null, null, null);
		await taskSet(null, null, null);
		await contactGroupSet(null, null, null);
		await taskListSet(null, null, null);
		await taskListTaskSet('list', null, null, null);
		for (const call of fetchMock.mock.calls) {
			const args = JSON.parse(call[1].body).methodCalls[0][1];
			expect(args).not.toHaveProperty('create');
			expect(args).not.toHaveProperty('update');
			expect(args).not.toHaveProperty('destroy');
		}
	});

	it('normalizes malformed duplicate and import results without inventing data', async () => {
		const fetchMock = vi.fn()
			.mockResolvedValueOnce(ok('ContactCard/findDuplicates', { unexpected: true }))
			.mockResolvedValueOnce(ok('CalendarEvent/import', {}))
			.mockResolvedValueOnce(ok('ContactCard/findDuplicates', [{ email: 'same@example.test', contactIds: [1, 2] }]));
		vi.stubGlobal('fetch', fetchMock);
		expect(await contactFindDuplicates()).toEqual([]);
		expect(await calendarEventImport('c', 'BEGIN:VCALENDAR', 'skip')).toEqual({ imported: 0, skipped: 0 });
		expect(await contactFindDuplicates()).toEqual([{ email: 'same@example.test', contactIds: ['1', '2'] }]);
	});

	it('ignores unknown method families while retaining submission mail capability', () => {
		expect(usingFor(['Unknown/get'])).toEqual(['urn:ietf:params:jmap:core']);
		expect(usingFor(['EmailSubmission/set'])).toEqual(expect.arrayContaining([
			'urn:ietf:params:jmap:submission', 'urn:ietf:params:jmap:mail',
		]));
	});

	it('enumerates only delegated accounts and applies fail-closed metadata defaults', async () => {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
			ok: true, status: 200,
			json: async () => ({
				primaryAccounts: { 'urn:ietf:params:jmap:mail': 'own' },
				accounts: {
					own: { name: 'Me', isReadOnly: false },
					shared: { name: 'Shared', accountCapabilities: { 'urn:setjoin:params:jmap:mail': {
						delegateGrants: ['send_as'],
						sendAsAliases: ['sales@shared.test'],
					} } },
					legacy: { name: 'Legacy', isReadOnly: false },
				},
			}),
		}));
		expect(await getDelegatedAccounts()).toEqual([
			{
				id: 'shared',
				name: 'Shared',
				isReadOnly: true,
				grants: ['send_as'],
				sendAsAliases: ['sales@shared.test'],
			},
			{ id: 'legacy', name: 'Legacy', isReadOnly: false, grants: [], sendAsAliases: [] },
		]);
	});

	it('bounds assist locale/content fallbacks and propagates server detail', async () => {
		const fetchMock = vi.fn()
			.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({}) })
			.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ content: 'done' }) })
			.mockResolvedValueOnce({ ok: false, status: 503, json: async () => ({ detail: 'model unavailable' }) });
		vi.stubGlobal('fetch', fetchMock);
		expect(await assistComplete([{ role: 'user', content: 'x' }])).toBe('');
		expect(await assistComplete([{ role: 'user', content: 'x' }], 'zh-CN')).toBe('done');
		expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toHaveProperty('locale', 'zh-CN');
		await expect(assistComplete([])).rejects.toThrow('model unavailable');
	});

	it('covers blob upload progress, success, HTTP error, transport error, and cancellation', async () => {
		class FakeXHR {
			static instances: FakeXHR[] = [];
			status = 204;
			upload: { onprogress?: (event: ProgressEvent) => void } = {};
			onload?: () => void;
			onerror?: () => void;
			onabort?: () => void;
			open = vi.fn();
			setRequestHeader = vi.fn();
			send = vi.fn();
			abort = vi.fn(() => this.onabort?.());
			constructor() { FakeXHR.instances.push(this); }
		}
		vi.stubGlobal('XMLHttpRequest', FakeXHR);
		const progress = vi.fn();
		const file = new File(['abc'], 'x.txt', { type: 'text/plain' });
		const success = putBlob('hash', file, { onProgress: progress });
		const first = FakeXHR.instances[0];
		expect(first.open).toHaveBeenCalledWith('PUT', '/api/blobs/hash');
		expect(first.setRequestHeader).toHaveBeenCalledWith('Content-Type', 'text/plain');
		first.upload.onprogress?.({ lengthComputable: false, loaded: 1, total: 0 } as ProgressEvent);
		first.upload.onprogress?.({ lengthComputable: true, loaded: 1, total: 2 } as ProgressEvent);
		expect(progress).toHaveBeenCalledWith(0.5);
		first.onload?.();
		await expect(success).resolves.toBeUndefined();

		const bad = putBlob('bad', new File(['x'], 'x', { type: '' }));
		const second = FakeXHR.instances[1];
		second.status = 500;
		second.onload?.();
		await expect(bad).rejects.toThrow('Upload failed (500)');

		const network = putBlob('network', file);
		FakeXHR.instances[2].onerror?.();
		await expect(network).rejects.toThrow('Upload failed');

		const preAborted = new AbortController();
		preAborted.abort();
		await expect(putBlob('pre', file, { signal: preAborted.signal })).rejects.toMatchObject({ name: 'AbortError' });

		const controller = new AbortController();
		const pending = putBlob('cancel', file, { signal: controller.signal });
		controller.abort();
		expect(FakeXHR.instances[3].abort).toHaveBeenCalledOnce();
		await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
	});
});
