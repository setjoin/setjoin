import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { loadSession } from './client';

// We will import these after they are created
// import { emailSubmissionQuery, emailSubmissionGet } from './client';

describe('EmailSubmission client helpers', () => {
	beforeEach(() => {
		vi.stubGlobal('fetch', vi.fn());
		vi.stubGlobal('window', { location: { href: '' } });
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	describe('emailSubmissionQuery', () => {
		it('POSTs an EmailSubmission/query method call and returns ids', async () => {
			const mockFetch = vi.fn()
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ apiUrl: '/jmap', accounts: { u1: {} }, primaryAccounts: {} }),
				})
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({
						methodResponses: [
							['EmailSubmission/query', { accountId: 'u1', ids: ['sub1', 'sub2'], total: 2, position: 0 }, '0'],
						],
					}),
				});
			vi.stubGlobal('fetch', mockFetch);

			await loadSession();
			// Dynamic import so the test fails until we add the export
			const { emailSubmissionQuery } = await import('./client');
			const result = await emailSubmissionQuery({});
			expect(result.ids).toEqual(['sub1', 'sub2']);
			expect(result.total).toBe(2);

			const body = JSON.parse(mockFetch.mock.calls[1][1].body);
			const methodCalls = body.methodCalls;
			expect(methodCalls[0][0]).toBe('EmailSubmission/query');
			expect(methodCalls[0][1].accountId).toBe('u1');
			// EmailSubmission/* MUST declare the submission capability or the gateway
			// rejects it 400 (this once broke all sending). All four helpers share
			// SUBMISSION_CAPS, so guarding one guards the send path too.
			expect(body.using).toContain('urn:ietf:params:jmap:submission');
		});

		it('passes filter, position, and limit arguments', async () => {
			const mockFetch = vi.fn()
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ apiUrl: '/jmap', accounts: { u1: {} }, primaryAccounts: {} }),
				})
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({
						methodResponses: [
							['EmailSubmission/query', { accountId: 'u1', ids: ['sub1'], total: 1, position: 5 }, '0'],
						],
					}),
				});
			vi.stubGlobal('fetch', mockFetch);

			await loadSession();
			const { emailSubmissionQuery } = await import('./client');
			const result = await emailSubmissionQuery({ undoStatus: 'pending' }, 5, 10);
			expect(result.ids).toEqual(['sub1']);
			expect(result.position).toBe(5);

			const body = JSON.parse(mockFetch.mock.calls[1][1].body);
			const args = body.methodCalls[0][1];
			expect(args.filter).toEqual({ undoStatus: 'pending' });
			expect(args.position).toBe(5);
			expect(args.limit).toBe(10);
		});
	});

	describe('emailSubmissionGet', () => {
		it('POSTs an EmailSubmission/get method call and returns EmailSubmission[] with sendAt', async () => {
			const submissions = [
				{ id: 'sub1', emailId: 'e1', sendAt: '2026-07-01T09:00:00Z', undoSendBefore: '2026-07-01T09:00:30Z' },
				{ id: 'sub2', emailId: 'e2', sendAt: '2026-07-02T14:30:00Z', undoSendBefore: '2026-07-02T14:30:30Z' },
			];

			const mockFetch = vi.fn()
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({ apiUrl: '/jmap', accounts: { u1: {} }, primaryAccounts: {} }),
				})
				.mockResolvedValueOnce({
					ok: true,
					status: 200,
					json: async () => ({
						methodResponses: [
							['EmailSubmission/get', { accountId: 'u1', list: submissions }, '0'],
						],
					}),
				});
			vi.stubGlobal('fetch', mockFetch);

			await loadSession();
			const { emailSubmissionGet } = await import('./client');
			const result = await emailSubmissionGet(['sub1', 'sub2']);
			expect(result).toHaveLength(2);
			expect(result[0].id).toBe('sub1');
			expect(result[0].emailId).toBe('e1');
			expect(result[0].sendAt).toBe('2026-07-01T09:00:00Z');
			expect(result[0].undoSendBefore).toBe('2026-07-01T09:00:30Z');

			const body = JSON.parse(mockFetch.mock.calls[1][1].body);
			const methodCalls = body.methodCalls;
			expect(methodCalls[0][0]).toBe('EmailSubmission/get');
			expect(methodCalls[0][1].ids).toEqual(['sub1', 'sub2']);
			expect(methodCalls[0][1].accountId).toBe('u1');
		});
	});
});
