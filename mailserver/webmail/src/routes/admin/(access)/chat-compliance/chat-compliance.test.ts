import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render } from '@testing-library/svelte/svelte5';
import { fireEvent, waitFor } from '@testing-library/svelte';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

import ChatCompliancePage from './+page.svelte';
import ConfirmDestructive from '$lib/components/ui/ConfirmDestructive.svelte';
import { computeChatVerdict } from './verdict';
import { channelDisplayName, retentionLabel, channelCache } from './channels.svelte';
import type {
	ChatChannelRow,
	ChatRetentionPolicy,
	ChatAuditVerifyResult,
	ChatEDiscoveryCase,
	ChatCaseHold,
	ChatEDiscoveryHit,
	ChatEDiscoverySearchResult,
	ChatEDiscoveryReadResult,
} from '$lib/admin/client';
import en from '$lib/i18n/en';
import { formatDateTime } from '$lib/i18n';

// ── fixtures ─────────────────────────────────────────────────────────────────

const POLICIES: ChatRetentionPolicy[] = [
	{
		id: 1,
		name: 'Org default',
		appliesTo: 'all',
		durationDays: 365,
		enabled: true,
		effectiveAt: '2026-01-01T00:00:00Z',
		createdAt: '2026-01-01T00:00:00Z',
		updatedAt: '2026-01-01T00:00:00Z',
	},
];

const DM_CHANNEL: ChatChannelRow = {
	id: 10,
	kind: 'dm',
	name: undefined,
	classification: 'regular',
	retentionDays: undefined,
	wormMode: undefined,
	legalHold: false,
	legalHoldReason: undefined,
	lastPurgedSeq: 0,
	effectiveRetentionDays: 90,
	memberCount: 2,
	participants: [
		{ userId: 1, displayName: 'Alice', email: 'alice@test.local' },
		{ userId: 2, displayName: 'Bob', email: 'bob@test.local' },
	],
};

const HELD_CHANNEL: ChatChannelRow = {
	id: 20,
	kind: 'channel',
	name: 'general',
	classification: 'regular',
	retentionDays: 30,
	wormMode: undefined,
	legalHold: true,
	legalHoldReason: 'case-42',
	lastPurgedSeq: 0,
	effectiveRetentionDays: 30,
	memberCount: 5,
	participants: [],
};

const CASES: ChatEDiscoveryCase[] = [
	{ id: 1, name: 'Case Alpha', status: 'active' },
	{ id: 2, name: 'Case Beta', status: 'closed' },
];

// ── generic fetch mock ────────────────────────────────────────────────────────

interface MockState {
	policies: ChatRetentionPolicy[];
	channels: ChatChannelRow[];
	deleteConflict: boolean;
	verifyResult: ChatAuditVerifyResult | null;
	holdCalls: Array<Record<string, unknown>>;
	updateBodies: Array<Record<string, unknown>>;
	deleteUrls: string[];
	cases: ChatEDiscoveryCase[];
	caseHolds: ChatCaseHold[];
	holdPosts: Array<Record<string, unknown>>;
	releasePosts: Array<{ id: number; body: Record<string, unknown> }>;
	searchResult: ChatEDiscoverySearchResult | null;
	searchPosts: Array<Record<string, unknown>>;
	readerResult: ChatEDiscoveryReadResult | null;
	readerCalls: string[];
}

function jsonRes(body: unknown, status = 200) {
	return { ok: status < 400, status, json: async () => body, text: async () => JSON.stringify(body) };
}
const noContent = { ok: true, status: 204, json: async () => ({}), text: async () => '' };

function makeFetchMock(overrides: Partial<MockState> = {}) {
	const state: MockState = {
		policies: overrides.policies ?? [...POLICIES],
		channels: overrides.channels ?? [DM_CHANNEL],
		deleteConflict: overrides.deleteConflict ?? false,
		verifyResult: overrides.verifyResult ?? null,
		holdCalls: [],
		updateBodies: [],
		deleteUrls: [],
		cases: overrides.cases ?? [...CASES],
		caseHolds: overrides.caseHolds ?? [],
		holdPosts: [],
		releasePosts: [],
		searchResult: overrides.searchResult ?? { searchId: 1, hits: [], scheduledHits: [], resultCount: 0 },
		searchPosts: [],
		readerResult:
			overrides.readerResult ?? { channelId: 0, lastPurgedSeq: 0, purgeActs: [], scheduledRows: [], messages: [] },
		readerCalls: [],
	};

	const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = input instanceof Request ? input.url : String(input);
		const method = (init?.method ?? (input instanceof Request ? input.method : 'GET') ?? 'GET').toUpperCase();

		if (url.includes('/admin/chat-retention-policies')) {
			if (method === 'GET') return jsonRes(state.policies);
			if (method === 'POST') {
				const body = JSON.parse((init?.body as string) ?? '{}');
				const id = state.policies.length + 1;
				const effectiveAt = '2026-01-08T00:00:00Z';
				state.policies.push({ id, effectiveAt, createdAt: effectiveAt, updatedAt: effectiveAt, ...body });
				return jsonRes({ id, effectiveAt }, 201);
			}
			if (method === 'PUT') {
				const body = JSON.parse((init?.body as string) ?? '{}');
				state.updateBodies.push(body);
				const id = Number(url.split('/').pop());
				const existing = state.policies.find((p) => p.id === id);
				// Mirrors the server's N4 re-arm: shortening durationDays re-arms
				// effective_at 7 days out; a lengthening edit leaves it unchanged.
				const effectiveAt =
					existing && body.durationDays < existing.durationDays
						? '2026-01-08T00:00:00Z'
						: (existing?.effectiveAt ?? '2020-01-01T00:00:00Z');
				if (existing) Object.assign(existing, body, { effectiveAt });
				return jsonRes({ effectiveAt });
			}
			if (method === 'DELETE') {
				state.deleteUrls.push(url);
				if (state.deleteConflict && !url.includes('confirm=DESTROY')) {
					return jsonRes({ code: 'exposure', exposedChannels: 2 }, 409);
				}
				return noContent;
			}
		}
		if (/\/admin\/chat-channels\/\d+\/hold/.test(url)) {
			state.holdCalls.push(JSON.parse((init?.body as string) ?? '{}'));
			return noContent;
		}
		if (/\/admin\/chat-channels\/\d+\/classification/.test(url)) return noContent;
		if (/\/admin\/chat-channels\/\d+\/retention/.test(url)) return noContent;
		if (/\/admin\/chat-channels\/\d+\/audit\/verify/.test(url)) return jsonRes(state.verifyResult ?? {});
		if (/\/admin\/chat-channels\/\d+\/audit/.test(url)) return jsonRes([]);
		if (/\/admin\/chat-ediscovery\/holds\/\d+\/release/.test(url)) {
			const id = Number(url.match(/holds\/(\d+)\/release/)?.[1]);
			const body = JSON.parse((init?.body as string) ?? '{}');
			state.releasePosts.push({ id, body });
			const hold = state.caseHolds.find((h) => h.id === id);
			if (hold) {
				hold.releasedAt = '2026-01-09T00:00:00Z';
				hold.releasedBy = 1;
			}
			return noContent;
		}
		if (url.includes('/admin/chat-ediscovery/holds')) {
			if (method === 'POST') {
				const body = JSON.parse((init?.body as string) ?? '{}');
				state.holdPosts.push(body);
				const id = state.caseHolds.length + 1;
				state.caseHolds.push({
					id,
					caseId: body.caseId,
					custodianUserId: body.custodianUserId,
					channelId: body.channelId,
					reason: body.reason,
					createdBy: 1,
					createdAt: '2026-01-01T00:00:00Z',
					channels: 1,
				});
				return jsonRes({ holdId: id }, 201);
			}
			const caseId = Number(new URL(url, 'http://x').searchParams.get('caseId'));
			return jsonRes(state.caseHolds.filter((h) => h.caseId === caseId));
		}
		if (url.includes('/admin/chat-ediscovery/search') && method === 'POST') {
			state.searchPosts.push(JSON.parse((init?.body as string) ?? '{}'));
			return jsonRes(state.searchResult ?? { searchId: 1, hits: [], scheduledHits: [], resultCount: 0 });
		}
		if (/\/admin\/chat-ediscovery\/channels\/\d+\/messages/.test(url)) {
			state.readerCalls.push(url);
			return jsonRes(
				state.readerResult ?? { channelId: 0, lastPurgedSeq: 0, purgeActs: [], scheduledRows: [], messages: [] }
			);
		}
		if (url.includes('/admin/chat-ediscovery/cases')) return jsonRes(state.cases);
		if (url.includes('/admin/chat-channels')) return jsonRes(state.channels);
		if (url.includes('/admin/chat-purge/preview')) {
			return jsonRes({ channels: [], totalChannels: 3, totalMessages: 500 });
		}
		if (url.includes('/admin/chat-compliance/overview')) {
			return jsonRes({
				channelsUnderHold: [],
				gxpChannels: [],
				channelsWithOverrides: [],
				lastPurgeRun: null,
				nextRunAt: '2026-01-08T02:50:00Z',
			});
		}
		return jsonRes({});
	});

	return { fn, state };
}

function setPerms(manage: boolean, ediscovery = false) {
	const permissions = manage ? ['chat.compliance_view', 'chat.compliance_manage'] : ['chat.compliance_view'];
	// chat.ediscovery is a DISTINCT permission (D-A's SoD split) — never
	// implied by chat.compliance_manage/_view.
	if (ediscovery) permissions.push('chat.ediscovery');
	jmapSession.set({
		accounts: { a1: { name: 'admin@test.local', isPrimary: true } },
		primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' },
		capabilities: {
			'urn:ietf:params:jmap:core': {},
			'urn:setjoin:params:jmap:mail': {
				admin: {
					consoles: ['access'],
					permissions,
				},
			},
		},
	} as any);
}

/**
 * renderAsUser({isAdmin:true}) itself sets a permission-less admin jmapSession
 * (mirrors approvals-admin.test.ts's "render first, then override" note) — so
 * the chat.compliance perms must be applied AFTER render, not before, or they
 * get clobbered.
 */
async function renderPage(manage: boolean, ediscovery = false) {
	const result = await renderAsUser(ChatCompliancePage, {}, { isAdmin: true });
	setPerms(manage, ediscovery);
	return result;
}

describe('chat compliance admin page', () => {
	beforeEach(() => {
		resetStores();
		channelCache.reset();
	});
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('renders policies from a mocked fetch', async () => {
		const { fn } = makeFetchMock();
		vi.stubGlobal('fetch', fn);
		const { getByText } = await renderPage(true);
		await fireEvent.click(getByText('Retention policies'));
		await waitFor(() => expect(getByText('Org default')).toBeTruthy());
	});

	it('manage-gated buttons are hidden for view-only caps', async () => {
		const { fn } = makeFetchMock();
		vi.stubGlobal('fetch', fn);
		const { getByText, queryByText, container } = await renderPage(false);
		await fireEvent.click(getByText('Retention policies'));
		await waitFor(() => expect(getByText('Org default')).toBeTruthy());
		expect(queryByText('Add policy')).toBeNull();
		expect(container.querySelector('[aria-label="Edit"]')).toBeNull();
	});

	it('a DM row renders participant names, not an empty cell', async () => {
		const { fn } = makeFetchMock({ channels: [DM_CHANNEL] });
		vi.stubGlobal('fetch', fn);
		const { getByText } = await renderPage(true);
		await fireEvent.click(getByText('Channels'));
		await waitFor(() => expect(getByText('Alice ↔ Bob')).toBeTruthy());
	});

	it('a policy edit that shortens retention shows the re-arm warning and re-renders effectiveAt from the response', async () => {
		const { fn } = makeFetchMock();
		vi.stubGlobal('fetch', fn);
		const { getByText, getByLabelText } = await renderPage(true);
		await fireEvent.click(getByText('Retention policies'));
		await waitFor(() => expect(getByText('Org default')).toBeTruthy());

		await fireEvent.click(getByLabelText('Edit'));
		const durationInput = getByLabelText('Duration (days)') as HTMLInputElement;
		await fireEvent.input(durationInput, { target: { value: '30' } }); // shortens 365 -> 30

		expect(getByText(/shortens retention/i)).toBeTruthy();

		// Save is gated on the impact preview having been fetched.
		await fireEvent.click(getByText('Preview impact'));
		await waitFor(() => expect(getByText(/500 messages across 3 channels/)).toBeTruthy());
		await fireEvent.click(getByText('Save'));

		// The purge-impact ConfirmDestructive gate (typed DESTROY).
		const confirmInput = getByLabelText(/type DESTROY to confirm/i);
		await fireEvent.input(confirmInput, { target: { value: 'DESTROY' } });
		await fireEvent.click(getByText('Confirm & save'));

		await waitFor(() => expect(getByText(/Takes effect on 2026-01-08/)).toBeTruthy());
	});

	it('a DELETE returning 409 exposedChannels opens the typed-DESTROY confirm and retries with ?confirm=DESTROY', async () => {
		const { fn, state } = makeFetchMock({ deleteConflict: true });
		vi.stubGlobal('fetch', fn);
		const { getByText, getByLabelText, container } = await renderPage(true);
		await fireEvent.click(getByText('Retention policies'));
		await waitFor(() => expect(getByText('Org default')).toBeTruthy());

		await fireEvent.click(container.querySelector('[aria-label="Delete"]')!);
		await waitFor(() => expect(getByText(/exposes 2 channels/)).toBeTruthy());

		const confirmInput = getByLabelText(/type DESTROY to confirm/i);
		await fireEvent.input(confirmInput, { target: { value: 'DESTROY' } });
		await fireEvent.click(getByText('Delete', { selector: 'button' }));

		await waitFor(() => expect(state.deleteUrls.some((u) => u.includes('confirm=DESTROY'))).toBe(true));
	});

	it('the purge confirm says destruction runs nightly until the backlog is cleared, never implying one night', async () => {
		const { fn } = makeFetchMock();
		vi.stubGlobal('fetch', fn);
		const { getByText, getByLabelText } = await renderPage(true);
		await fireEvent.click(getByText('Retention policies'));
		await waitFor(() => expect(getByText('Org default')).toBeTruthy());

		await fireEvent.click(getByLabelText('Edit'));
		await fireEvent.click(getByText('Preview impact'));
		await waitFor(() => expect(getByText(/500 messages across 3 channels/)).toBeTruthy());
		await fireEvent.click(getByText('Save'));

		expect(getByText(/runs nightly \(02:50\) until the backlog is cleared/)).toBeTruthy();
	});
});

describe('hold toggle posts the right body, including the matter on release', () => {
	beforeEach(() => {
		resetStores();
		channelCache.reset();
	});
	afterEach(() => vi.unstubAllGlobals());

	it('release includes the matter (legalHoldReason) in the request body', async () => {
		const { fn, state } = makeFetchMock({ channels: [HELD_CHANNEL] });
		vi.stubGlobal('fetch', fn);
		const { getByText, getByLabelText, getAllByText } = await renderPage(true);
		await fireEvent.click(getByText('Channels'));
		await waitFor(() => expect(getByText('general')).toBeTruthy());

		await fireEvent.click(getByText('general'));
		await waitFor(() => expect(getAllByText('Release hold', { selector: 'button' }).length).toBeGreaterThan(0));

		// First button = the sheet's own "release" action, opening the confirm.
		await fireEvent.click(getAllByText('Release hold', { selector: 'button' })[0]);
		const confirmInput = getByLabelText(/type DESTROY to confirm/i);
		await fireEvent.input(confirmInput, { target: { value: 'DESTROY' } });
		// The ConfirmDestructive dialog's own danger button — the LAST match
		// once the dialog has mounted (it renders after the sheet's controls).
		const buttons = getAllByText('Release hold', { selector: 'button' });
		await fireEvent.click(buttons[buttons.length - 1]);

		await waitFor(() =>
			expect(state.holdCalls.some((c) => c.on === false && c.reason === 'case-42')).toBe(true)
		);
	});
});

describe('Holds tab — case picker + durable case/custodian hold CRUD (A4b Task 9)', () => {
	beforeEach(() => {
		resetStores();
		channelCache.reset();
	});
	afterEach(() => vi.unstubAllGlobals());

	it('renders the case list, active selectable and closed disabled', async () => {
		const { fn } = makeFetchMock();
		vi.stubGlobal('fetch', fn);
		const { getByText } = await renderPage(true);
		await fireEvent.click(getByText('Holds'));
		await waitFor(() => expect(getByText('Case Alpha')).toBeTruthy());
		expect(getByText('Case Beta', { exact: false })).toBeTruthy();
	});

	it('submitting a custodian hold posts {caseId, custodianUserId, reason}', async () => {
		const { fn, state } = makeFetchMock();
		vi.stubGlobal('fetch', fn);
		const { getByText, getByLabelText } = await renderPage(true);
		await fireEvent.click(getByText('Holds'));
		await waitFor(() => expect(getByText('Case Alpha')).toBeTruthy());

		await fireEvent.input(getByLabelText('Custodian user ID'), { target: { value: '42' } });
		await fireEvent.input(getByLabelText('Reason'), { target: { value: 'litigation hold' } });
		await fireEvent.click(getByText('Place hold', { selector: 'button' }));

		await waitFor(() =>
			expect(
				state.holdPosts.some((c) => c.caseId === 1 && c.custodianUserId === 42 && c.reason === 'litigation hold')
			).toBe(true)
		);
	});

	it('a channel-scoped hold posts {caseId, channelId, reason}', async () => {
		const { fn, state } = makeFetchMock({ channels: [HELD_CHANNEL] });
		vi.stubGlobal('fetch', fn);
		const { getByText, getByLabelText } = await renderPage(true);
		await fireEvent.click(getByText('Holds'));
		await waitFor(() => expect(getByText('Case Alpha')).toBeTruthy());

		await fireEvent.click(getByLabelText('Channel'));
		await fireEvent.input(getByLabelText('Search by channel or participant'), { target: { value: 'general' } });
		await fireEvent.click(getByText('Search', { selector: 'button' }));
		await waitFor(() => expect(getByText('general')).toBeTruthy());
		await fireEvent.click(getByText('general'));

		await fireEvent.input(getByLabelText('Reason'), { target: { value: 'matter-9' } });
		await fireEvent.click(getByText('Place hold', { selector: 'button' }));

		await waitFor(() =>
			expect(
				state.holdPosts.some((c) => c.caseId === 1 && c.channelId === HELD_CHANNEL.id && c.reason === 'matter-9')
			).toBe(true)
		);
	});

	it('release posts to …/{id}/release and a released hold row renders its releasedAt', async () => {
		const ACTIVE_HOLD: ChatCaseHold = {
			id: 9,
			caseId: 1,
			custodianUserId: 7,
			reason: 'active matter',
			createdBy: 1,
			createdAt: '2026-01-01T00:00:00Z',
			channels: 2,
		};
		const { fn, state } = makeFetchMock({ caseHolds: [ACTIVE_HOLD] });
		vi.stubGlobal('fetch', fn);
		const { getByText, getAllByText } = await renderPage(true);
		await fireEvent.click(getByText('Holds'));
		await waitFor(() => expect(getByText('active matter')).toBeTruthy());

		await fireEvent.click(getByText('Release', { selector: 'button' }));
		await waitFor(() => expect(getByText('Release hold')).toBeTruthy()); // plain confirm Dialog title
		const releaseButtons = getAllByText('Release', { selector: 'button' });
		await fireEvent.click(releaseButtons[releaseButtons.length - 1]);

		await waitFor(() => expect(state.releasePosts.some((p) => p.id === 9)).toBe(true));
		await waitFor(() =>
			expect(getByText(formatDateTime('2026-01-09T00:00:00Z'))).toBeTruthy()
		);
	});
});

describe('eDiscovery tab — search → reader → export (A4b Task 10)', () => {
	beforeEach(() => {
		resetStores();
		channelCache.reset();
	});
	afterEach(() => vi.unstubAllGlobals());

	it('renders ONLY when chat.ediscovery is granted (D-A SoD split, not implied by compliance_manage)', async () => {
		const { fn } = makeFetchMock();
		vi.stubGlobal('fetch', fn);
		const { queryByText } = await renderPage(true, false);
		expect(queryByText('eDiscovery')).toBeNull();
	});

	it('shows the tab and case picker when chat.ediscovery is granted', async () => {
		const { fn } = makeFetchMock();
		vi.stubGlobal('fetch', fn);
		const { getByText } = await renderPage(true, true);
		await fireEvent.click(getByText('eDiscovery'));
		await waitFor(() => expect(getByText('Case Alpha')).toBeTruthy());
	});

	it('search posts the named fields {caseId, terms, ...}', async () => {
		const { fn, state } = makeFetchMock();
		vi.stubGlobal('fetch', fn);
		const { getByText, getByLabelText } = await renderPage(true, true);
		await fireEvent.click(getByText('eDiscovery'));
		await waitFor(() => expect(getByText('Case Alpha')).toBeTruthy());

		await fireEvent.input(getByLabelText('Terms'), { target: { value: 'forecast' } });
		await fireEvent.click(getByText('Search', { selector: 'button' }));

		await waitFor(() =>
			expect(state.searchPosts.some((p) => p.caseId === 1 && p.terms === 'forecast')).toBe(true)
		);
	});

	it('a deleted/revision-matched hit renders its badges and a scheduled hit renders its status', async () => {
		const { fn } = makeFetchMock({
			searchResult: {
				searchId: 5,
				hits: [
					{
						messageId: 100,
						channelId: 20,
						authorId: 2,
						createdAt: '2026-01-01T00:00:00Z',
						deleted: true,
						matchedIn: ['body'],
						excerpt: 'shred the memo',
					},
					{
						messageId: 101,
						channelId: 20,
						authorId: 3,
						createdAt: '2026-01-02T00:00:00Z',
						deleted: false,
						matchedIn: ['revision'],
						excerpt: 'insider price target',
					},
				],
				scheduledHits: [
					{
						scheduledActionId: 'sa-1',
						channelId: 20,
						authorId: 4,
						status: 'failed',
						fireAt: '2026-01-03T00:00:00Z',
						excerpt: 'delayed bombshell',
					},
				],
				resultCount: 3,
			},
		});
		vi.stubGlobal('fetch', fn);
		const { getByText, getByLabelText } = await renderPage(true, true);
		await fireEvent.click(getByText('eDiscovery'));
		await waitFor(() => expect(getByText('Case Alpha')).toBeTruthy());
		await fireEvent.input(getByLabelText('Terms'), { target: { value: 'x' } });
		await fireEvent.click(getByText('Search', { selector: 'button' }));

		await waitFor(() => expect(getByText(/shred the memo/)).toBeTruthy());
		expect(getByText('Deleted')).toBeTruthy();
		expect(getByText('Revision')).toBeTruthy();
		expect(getByText(/delayed bombshell/)).toBeTruthy();
		expect(getByText(/Scheduled \(Failed\)/)).toBeTruthy();
	});

	it('opening a hit loads the reader panel', async () => {
		const { fn, state } = makeFetchMock({
			searchResult: {
				searchId: 1,
				hits: [
					{
						messageId: 100,
						channelId: 20,
						authorId: 2,
						createdAt: '2026-01-01T00:00:00Z',
						deleted: false,
						matchedIn: ['body'],
						excerpt: 'quarterly forecast',
					},
				],
				scheduledHits: [],
				resultCount: 1,
			},
			readerResult: {
				channelId: 20,
				lastPurgedSeq: 0,
				purgeActs: [],
				scheduledRows: [],
				messages: [
					{
						messageId: 100,
						channelId: 20,
						authorId: 2,
						seq: 5,
						createdAt: '2026-01-01T00:00:00Z',
						msgType: 'text',
						body: 'quarterly forecast body',
						revisions: [],
						reactions: [],
						attachments: [],
						poll: null,
					},
				],
			},
		});
		vi.stubGlobal('fetch', fn);
		const { getByText, getByLabelText } = await renderPage(true, true);
		await fireEvent.click(getByText('eDiscovery'));
		await waitFor(() => expect(getByText('Case Alpha')).toBeTruthy());
		await fireEvent.input(getByLabelText('Terms'), { target: { value: 'forecast' } });
		await fireEvent.click(getByText('Search', { selector: 'button' }));
		await waitFor(() => expect(getByText(/quarterly forecast/)).toBeTruthy());

		await fireEvent.click(getByText(/quarterly forecast$/));
		await waitFor(() => expect(state.readerCalls.length).toBeGreaterThan(0));
		await waitFor(() => expect(getByText('quarterly forecast body')).toBeTruthy());
	});

	it('a reader response with purgeActs renders the record-floor banner verbatim from i18n', async () => {
		const { fn } = makeFetchMock({
			searchResult: {
				searchId: 1,
				hits: [
					{
						messageId: 100,
						channelId: 20,
						authorId: 2,
						createdAt: '2026-01-01T00:00:00Z',
						deleted: false,
						matchedIn: ['body'],
						excerpt: 'hit',
					},
				],
				scheduledHits: [],
				resultCount: 1,
			},
			readerResult: {
				channelId: 20,
				lastPurgedSeq: 7,
				purgeActs: [{ actId: 1, idFrom: 1, idTo: 3, purgedCount: 3 }],
				scheduledRows: [],
				messages: [],
			},
		});
		vi.stubGlobal('fetch', fn);
		const { getByText, getByLabelText } = await renderPage(true, true);
		await fireEvent.click(getByText('eDiscovery'));
		await waitFor(() => expect(getByText('Case Alpha')).toBeTruthy());
		await fireEvent.input(getByLabelText('Terms'), { target: { value: 'x' } });
		await fireEvent.click(getByText('Search', { selector: 'button' }));
		await waitFor(() => expect(getByText('hit', { exact: false })).toBeTruthy());

		await fireEvent.click(getByText('hit', { exact: false }));
		await waitFor(() =>
			expect(getByText(en['admin.chatCompliance.ediscovery.recordFloorDisclaimer'])).toBeTruthy()
		);
	});

	// m2: the export control is an M1 Button (the ChannelComplianceSheet
	// downloadEvidence / chatChannelAuditCsvUrl genre — a plain window.open on
	// a cookie-authed same-origin URL), not an <a download> anymore.
	it('the export URL opened via window.open carries includeAttachments=1 only once the checkbox is toggled', async () => {
		const { fn } = makeFetchMock({
			searchResult: {
				searchId: 1,
				hits: [
					{
						messageId: 100,
						channelId: 20,
						authorId: 2,
						createdAt: '2026-01-01T00:00:00Z',
						deleted: false,
						matchedIn: ['body'],
						excerpt: 'hit',
					},
				],
				scheduledHits: [],
				resultCount: 1,
			},
		});
		vi.stubGlobal('fetch', fn);
		const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null);
		const { getByText, getByLabelText } = await renderPage(true, true);
		await fireEvent.click(getByText('eDiscovery'));
		await waitFor(() => expect(getByText('Case Alpha')).toBeTruthy());
		await fireEvent.input(getByLabelText('Terms'), { target: { value: 'x' } });
		await fireEvent.click(getByText('Search', { selector: 'button' }));
		await waitFor(() => expect(getByText('hit', { exact: false })).toBeTruthy());

		await fireEvent.click(getByText('Export', { selector: 'button' }));
		await waitFor(() => expect(openSpy).toHaveBeenCalledTimes(1));
		expect(openSpy.mock.calls[0][0]).not.toContain('includeAttachments=1');
		expect(openSpy.mock.calls[0][0]).toContain('caseId=1');
		expect(openSpy.mock.calls[0][0]).toContain('channels=20');

		await fireEvent.click(getByLabelText('Include attachments'));
		await fireEvent.click(getByText('Export', { selector: 'button' }));
		await waitFor(() => expect(openSpy).toHaveBeenCalledTimes(2));
		expect(openSpy.mock.calls[1][0]).toContain('includeAttachments=1');

		openSpy.mockRestore();
	});

	// C1: nothing reset selectedCaseId — a stale Case-A hit list + export
	// channel selection survived into Case B (cross-case export
	// contamination).
	it('C1 — switching cases clears the hit list, reader, and export selection', async () => {
		const CASE_B: ChatEDiscoveryCase = { id: 3, name: 'Case Gamma', status: 'active' };
		const { fn } = makeFetchMock({
			cases: [...CASES, CASE_B],
			searchResult: {
				searchId: 1,
				hits: [
					{
						messageId: 100,
						channelId: 20,
						authorId: 2,
						createdAt: '2026-01-01T00:00:00Z',
						deleted: false,
						matchedIn: ['body'],
						excerpt: 'case-a-only hit',
					},
				],
				scheduledHits: [],
				resultCount: 1,
			},
		});
		vi.stubGlobal('fetch', fn);
		const { getByText, getByLabelText, queryByText } = await renderPage(true, true);
		await fireEvent.click(getByText('eDiscovery'));
		await waitFor(() => expect(getByText('Case Alpha')).toBeTruthy());
		await fireEvent.input(getByLabelText('Terms'), { target: { value: 'x' } });
		await fireEvent.click(getByText('Search', { selector: 'button' }));
		await waitFor(() => expect(getByText(/case-a-only hit/)).toBeTruthy());

		// Switch to Case Gamma — the Case Alpha hit must not survive.
		await fireEvent.change(getByLabelText('Case'), { target: { value: String(CASE_B.id) } });
		await waitFor(() => expect(queryByText(/case-a-only hit/)).toBeNull());
		// The export section (keyed off hits/reader) must be gone too — no
		// stale channel 20 selection to leak into a Case Gamma export.
		expect(queryByText('Export', { selector: 'button' })).toBeNull();
	});

	// C2 + I9: a hit click must land the reader ON that hit (anchored via
	// beforeId = messageId + 1), not just open the channel's latest window,
	// and highlight the anchor row.
	it('C2 — clicking a hit opens the reader anchored past that hit and highlights it', async () => {
		const HIT: ChatEDiscoveryHit = {
			messageId: 100,
			channelId: 20,
			authorId: 2,
			createdAt: '2026-01-01T00:00:00Z',
			deleted: false,
			matchedIn: ['body'],
			excerpt: 'anchor me',
		};
		const { fn, state } = makeFetchMock({
			searchResult: { searchId: 1, hits: [HIT], scheduledHits: [], resultCount: 1 },
			readerResult: {
				channelId: 20,
				lastPurgedSeq: 0,
				purgeActs: [],
				scheduledRows: [],
				messages: [
					{
						messageId: 100,
						channelId: 20,
						authorId: 2,
						seq: 5,
						createdAt: '2026-01-01T00:00:00Z',
						msgType: 'text',
						body: 'anchored message body',
						revisions: [],
						reactions: [],
						attachments: [],
						poll: null,
					},
				],
			},
		});
		vi.stubGlobal('fetch', fn);
		const { getByText, getByLabelText, container } = await renderPage(true, true);
		await fireEvent.click(getByText('eDiscovery'));
		await waitFor(() => expect(getByText('Case Alpha')).toBeTruthy());
		await fireEvent.input(getByLabelText('Terms'), { target: { value: 'x' } });
		await fireEvent.click(getByText('Search', { selector: 'button' }));
		await waitFor(() => expect(getByText(/anchor me/)).toBeTruthy());

		await fireEvent.click(getByText(/anchor me$/));
		await waitFor(() => expect(state.readerCalls.length).toBeGreaterThan(0));
		// beforeId = messageId + 1 (101) — lands the reader page ON the hit,
		// not just the channel's unqualified latest window.
		expect(state.readerCalls[0]).toContain('beforeId=101');

		await waitFor(() => expect(getByText('anchored message body')).toBeTruthy());
		const hitRow = container.querySelector('.edp-message--hit');
		expect(hitRow).toBeTruthy();
		expect(hitRow?.textContent).toContain('anchored message body');
	});

	// I4: the zero-hit state has its own copy, not the reused channels.empty.
	it('I4 — a search with zero hits shows the noHits copy, not channels.empty', async () => {
		const { fn } = makeFetchMock({
			searchResult: { searchId: 1, hits: [], scheduledHits: [], resultCount: 0 },
		});
		vi.stubGlobal('fetch', fn);
		const { getByText, getByLabelText, queryByText } = await renderPage(true, true);
		await fireEvent.click(getByText('eDiscovery'));
		await waitFor(() => expect(getByText('Case Alpha')).toBeTruthy());
		await fireEvent.input(getByLabelText('Terms'), { target: { value: 'nothing' } });
		await fireEvent.click(getByText('Search', { selector: 'button' }));

		await waitFor(() => expect(getByText(en['admin.chatCompliance.ediscovery.noHits'])).toBeTruthy());
		expect(queryByText(en['admin.chatCompliance.channels.empty'])).toBeNull();
	});

	// I8: the raw scheduled_actions.status enum is mapped through copy.
	it('I8 — a scheduled hit renders its status through the mapped copy, not the raw enum', async () => {
		const { fn } = makeFetchMock({
			searchResult: {
				searchId: 1,
				hits: [],
				scheduledHits: [
					{
						scheduledActionId: 'sa-1',
						channelId: 20,
						authorId: 4,
						status: 'failed',
						fireAt: '2026-01-03T00:00:00Z',
						excerpt: 'delayed bombshell',
					},
				],
				resultCount: 1,
			},
		});
		vi.stubGlobal('fetch', fn);
		const { getByText, getByLabelText } = await renderPage(true, true);
		await fireEvent.click(getByText('eDiscovery'));
		await waitFor(() => expect(getByText('Case Alpha')).toBeTruthy());
		await fireEvent.input(getByLabelText('Terms'), { target: { value: 'x' } });
		await fireEvent.click(getByText('Search', { selector: 'button' }));

		await waitFor(() => expect(getByText(/Scheduled \(Failed\)/)).toBeTruthy());
	});

	// m1: a page shorter than the server's page-size default means there is
	// no next page — the Load-more button hides and an end-of-results line
	// takes its place, instead of an always-on button that 404s past the end.
	it('m1 — a short hit page hides Load more and shows the end-of-results line', async () => {
		const { fn } = makeFetchMock({
			searchResult: {
				searchId: 1,
				hits: [
					{
						messageId: 100,
						channelId: 20,
						authorId: 2,
						createdAt: '2026-01-01T00:00:00Z',
						deleted: false,
						matchedIn: ['body'],
						excerpt: 'only one hit',
					},
				],
				scheduledHits: [],
				resultCount: 1,
			},
		});
		vi.stubGlobal('fetch', fn);
		const { getByText, getByLabelText, queryByText } = await renderPage(true, true);
		await fireEvent.click(getByText('eDiscovery'));
		await waitFor(() => expect(getByText('Case Alpha')).toBeTruthy());
		await fireEvent.input(getByLabelText('Terms'), { target: { value: 'x' } });
		await fireEvent.click(getByText('Search', { selector: 'button' }));

		await waitFor(() => expect(getByText(/only one hit/)).toBeTruthy());
		expect(queryByText(en['admin.chatCompliance.ediscovery.loadMore'])).toBeNull();
		expect(getByText(en['admin.chatCompliance.ediscovery.endOfResults'])).toBeTruthy();
	});
});

describe('ConfirmDestructive', () => {
	it('keeps the button disabled until the name is typed', async () => {
		const onConfirm = vi.fn();
		const { getByLabelText, getByText } = render(ConfirmDestructive, {
			props: {
				open: true,
				title: 'Destroy it',
				message: 'This destroys 5 things.',
				confirmWord: 'my-channel',
				confirmLabel: 'Destroy',
				onConfirm,
				onCancel: () => {},
			},
		});
		const confirmBtn = getByText('Destroy', { selector: 'button' }) as HTMLButtonElement;
		expect(confirmBtn.disabled).toBe(true);

		await fireEvent.input(getByLabelText(/type my-channel to confirm/i), { target: { value: 'wrong' } });
		expect(confirmBtn.disabled).toBe(true);

		await fireEvent.input(getByLabelText(/type my-channel to confirm/i), { target: { value: 'my-channel' } });
		expect(confirmBtn.disabled).toBe(false);

		await fireEvent.click(confirmBtn);
		expect(onConfirm).toHaveBeenCalled();
	});
});

describe('computeChatVerdict — the three verdict outcomes, no fourth ⚠ state', () => {
	const base: ChatAuditVerifyResult = {
		channelId: 1,
		checked: 10,
		fromId: 1,
		toId: 10,
		chainValid: true,
		firstInvalid: null,
		verifiedAt: '2026-01-01T00:00:00Z',
		keyVersion: 'v3',
		truncationDetected: false,
	};

	it('PASS — clean chain, no anchor problems, reconciled-from-purge is a neutral sub-line', () => {
		const result: ChatAuditVerifyResult = {
			...base,
			anchors: [{ anchorId: 1, idFrom: 1, idTo: 10, valid: true, reconciledFromPurge: 3, revisionsUnchained: 0 }],
		};
		const v = computeChatVerdict(result);
		expect(v.kind).toBe('pass');
	});

	it('CHAIN BROKEN — a mid-chain break', () => {
		const result: ChatAuditVerifyResult = { ...base, chainValid: false, firstInvalid: 5 };
		const v = computeChatVerdict(result);
		expect(v.kind).toBe('broken');
		expect(v.truncated).toBe(false);
	});

	it('CHAIN BROKEN / TRUNCATED — a tail-truncated chain (FIX 1), never a fourth state', () => {
		const result: ChatAuditVerifyResult = {
			...base,
			truncationDetected: true,
			liveHead: { id: 5, checksum: 'a' },
			notarizedHead: { id: 10, checksum: 'b' },
		};
		const v = computeChatVerdict(result);
		expect(v.kind).toBe('broken');
		expect(v.truncated).toBe(true);
	});

	it('RECORD ALTERED — chain intact but an anchor does not reconcile', () => {
		const result: ChatAuditVerifyResult = {
			...base,
			anchors: [{ anchorId: 1, idFrom: 1, idTo: 10, valid: false, reconciledFromPurge: 0, revisionsUnchained: 0 }],
		};
		const v = computeChatVerdict(result);
		expect(v.kind).toBe('altered');
	});

	it('RECORD ALTERED — chain intact but a revision rides no chained edit', () => {
		const result: ChatAuditVerifyResult = {
			...base,
			anchors: [{ anchorId: 1, idFrom: 1, idTo: 10, valid: true, reconciledFromPurge: 0, revisionsUnchained: 3 }],
		};
		const v = computeChatVerdict(result);
		expect(v.kind).toBe('altered');
	});
});

describe('the verdict card renders all three outcomes end to end', () => {
	beforeEach(() => {
		resetStores();
		channelCache.reset();
	});
	afterEach(() => vi.unstubAllGlobals());

	async function openSheetAndVerify(verifyResult: ChatAuditVerifyResult) {
		const { fn } = makeFetchMock({ channels: [HELD_CHANNEL], verifyResult });
		vi.stubGlobal('fetch', fn);
		const { getByText } = await renderPage(true);
		await fireEvent.click(getByText('Channels'));
		await waitFor(() => expect(getByText('general')).toBeTruthy());
		await fireEvent.click(getByText('general'));
		await waitFor(() => expect(getByText('Verify chain')).toBeTruthy());
		await fireEvent.click(getByText('Verify chain'));
		return getByText;
	}

	const base: ChatAuditVerifyResult = {
		channelId: 20,
		checked: 4,
		fromId: 1,
		toId: 4,
		chainValid: true,
		firstInvalid: null,
		verifiedAt: '2026-01-01T00:00:00Z',
		keyVersion: 'v3',
		truncationDetected: false,
		anchors: [],
	};

	it('PASS renders ✓ PASS and the reconciled neutral sub-line', async () => {
		const getByText = await openSheetAndVerify({
			...base,
			anchors: [{ anchorId: 1, idFrom: 1, idTo: 4, valid: true, reconciledFromPurge: 2, revisionsUnchained: 0 }],
		});
		await waitFor(() => expect(getByText(/PASS/)).toBeTruthy());
		expect(getByText(/reconciled from the purge record/)).toBeTruthy();
	});

	it('CHAIN BROKEN / TRUNCATED renders the live/notarized head ids', async () => {
		const getByText = await openSheetAndVerify({
			...base,
			truncationDetected: true,
			liveHead: { id: 900, checksum: 'x' },
			notarizedHead: { id: 1284, checksum: 'y' },
			anchors: undefined,
		});
		await waitFor(() => expect(getByText(/TRUNCATED/)).toBeTruthy());
		expect(getByText(/#900/)).toBeTruthy();
		expect(getByText(/#1284/)).toBeTruthy();
	});

	it('RECORD ALTERED renders the non-reconciling anchor', async () => {
		const getByText = await openSheetAndVerify({
			...base,
			anchors: [{ anchorId: 91, idFrom: 1, idTo: 640, valid: false, reconciledFromPurge: 0, revisionsUnchained: 0 }],
		});
		await waitFor(() => expect(getByText(/RECORD ALTERED/)).toBeTruthy());
		expect(getByText(/anchor #91/)).toBeTruthy();
	});

	it('there is no ⚠ warning glyph anywhere in the verdict card', async () => {
		const getByText = await openSheetAndVerify({
			...base,
			anchors: [{ anchorId: 1, idFrom: 1, idTo: 4, valid: true, reconciledFromPurge: 2, revisionsUnchained: 0 }],
		});
		await waitFor(() => expect(getByText(/PASS/)).toBeTruthy());
		expect(document.body.textContent).not.toContain('⚠');
	});
});

describe('a shortening per-channel retention override opens ConfirmDestructive; a lengthening one does not', () => {
	beforeEach(() => {
		resetStores();
		channelCache.reset();
	});
	afterEach(() => vi.unstubAllGlobals());

	it('shortening (below effectiveRetentionDays) requires the typed confirm', async () => {
		const { fn } = makeFetchMock({ channels: [DM_CHANNEL] }); // effectiveRetentionDays: 90
		vi.stubGlobal('fetch', fn);
		const { getByText, getAllByLabelText, queryByText } = await renderPage(true);
		await fireEvent.click(getByText('Channels'));
		await waitFor(() => expect(getByText('Alice ↔ Bob')).toBeTruthy());
		await fireEvent.click(getByText('Alice ↔ Bob'));
		await waitFor(() => expect(getAllByLabelText('Retention override (days)').length).toBeGreaterThan(0));

		const input = getAllByLabelText('Retention override (days)')[0] as HTMLInputElement;
		await fireEvent.input(input, { target: { value: '10' } }); // 10 < 90 -> shortening
		await fireEvent.click(getByText('Save override'));

		await waitFor(() => expect(queryByText(/no grace on a per-channel override/)).toBeTruthy());
	});

	it('lengthening does not open a confirm — it saves directly', async () => {
		const { fn, state: _state } = makeFetchMock({ channels: [DM_CHANNEL] });
		vi.stubGlobal('fetch', fn);
		const { getByText, getAllByLabelText, queryByText } = await renderPage(true);
		await fireEvent.click(getByText('Channels'));
		await waitFor(() => expect(getByText('Alice ↔ Bob')).toBeTruthy());
		await fireEvent.click(getByText('Alice ↔ Bob'));
		await waitFor(() => expect(getAllByLabelText('Retention override (days)').length).toBeGreaterThan(0));

		const input = getAllByLabelText('Retention override (days)')[0] as HTMLInputElement;
		await fireEvent.input(input, { target: { value: '200' } }); // 200 > 90 -> lengthening
		await fireEvent.click(getByText('Save override'));

		// No confirm dialog copy should appear.
		expect(queryByText(/no grace on a per-channel override/)).toBeNull();
	});
});

describe('pure helpers', () => {
	it('channelDisplayName falls back to participants for a nameless DM', () => {
		expect(channelDisplayName(DM_CHANNEL)).toBe('Alice ↔ Bob');
	});

	it('retentionLabel uses the destroy-ceiling copy for a regular channel', () => {
		expect(retentionLabel(DM_CHANNEL)).toContain('Permanently delete');
	});

	it('retentionLabel uses the WORM-floor copy for a gxp channel', () => {
		expect(retentionLabel({ classification: 'gxp', effectiveRetentionDays: 3650 })).toContain('cannot be edited or deleted');
	});
});
