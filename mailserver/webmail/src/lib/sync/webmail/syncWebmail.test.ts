import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createWebSocketHub } from '$lib/jmap/websocket';
import {
	createGuestEventSourceHub,
	disconnectGuestEventSource,
	subscribeGuestChatEvents,
	subscribeGuestMeetEvents,
	subscribeGuestScopeRevoked,
	subscribeGuestSyncWakeup,
} from '$lib/chat/guestEventSource';
import { InboxStore } from '$lib/stores/inboxStore.svelte';
import { ChatStore } from '$lib/chat/store.svelte';
import type { ChatMessage, ChatReplay } from '$lib/chat/api';
import {
	__resetBootForTests,
	composeOfflineCoordinatorForSession,
	getSharedCriticalActivity,
	hasActiveOfflineCoordinator,
} from '$lib/offline/boot';
import { MailPageCapacityError } from '$lib/offline/mailPagePersistence';
import { SyncCoordinator } from '../core/coordinator.js';
import { WebmailWakeupTransport } from './transport';
import { getWebmailSyncCoordinator, resetWebmailSyncRuntimeForTests } from './runtime.svelte';
import { createInboxSyncAdapter, createJmapRefreshAdapter } from './adapters/jmapOnline';
import { createOfflineMailSyncAdapter, executeSecurityOfflineWipe } from './adapters/offlineMail';
import { createChatChannelSyncAdapter } from './adapters/chatOnline';
import { createDriveOnlineSyncAdapter } from './adapters/driveOnline';

class FakeWebSocket {
	static readonly CONNECTING = 0;
	static readonly OPEN = 1;
	static readonly CLOSED = 3;
	static instances: FakeWebSocket[] = [];
	readyState = FakeWebSocket.CONNECTING;
	sent: string[] = [];
	onopen: (() => void) | null = null;
	onmessage: ((ev: { data: string }) => void) | null = null;
	onclose: (() => void) | null = null;
	onerror: (() => void) | null = null;
	constructor(_url: string) {
		FakeWebSocket.instances.push(this);
	}
	open(): void {
		this.readyState = FakeWebSocket.OPEN;
		this.onopen?.();
	}
	send(data: string): void {
		this.sent.push(data);
	}
	close(): void {
		this.readyState = FakeWebSocket.CLOSED;
		this.onclose?.();
	}
}

type FakeListener = EventListenerOrEventListenerObject;

class FakeEventSource {
	static instances: FakeEventSource[] = [];
	readonly url: string;
	closed = false;
	#listeners = new Map<string, Set<FakeListener>>();
	constructor(url: string | URL) {
		this.url = String(url);
		FakeEventSource.instances.push(this);
	}
	addEventListener(type: string, listener: FakeListener): void {
		let set = this.#listeners.get(type);
		if (!set) {
			set = new Set();
			this.#listeners.set(type, set);
		}
		set.add(listener);
	}
	removeEventListener(type: string, listener: FakeListener): void {
		this.#listeners.get(type)?.delete(listener);
	}
	emit(type: string, data: unknown): void {
		const event = { data } as MessageEvent<unknown>;
		for (const listener of this.#listeners.get(type) ?? []) {
			if (typeof listener === 'function') listener(event);
			else listener.handleEvent(event);
		}
	}
	close(): void {
		this.closed = true;
	}
}

function makeChatMsg(id: number, seq: number, body = `msg-${id}`, payload?: Record<string, unknown>): ChatMessage {
	return {
		messageId: id,
		channelId: 50,
		seq,
		authorId: 1,
		authorExternal: false,
		authorRemoved: false,
		parentMessageId: null,
		msgType: 'text',
		broadcast: null,
		body,
		editedAt: null,
		deletedAt: null,
		createdAt: '2026-01-01T00:00:00Z',
		reactions: [],
		mentionsMe: false,
		replyCount: 0,
		lastReplyAt: null,
		payload: payload ?? null,
	};
}

describe('Webmail SyncCoordinator integration (#555)', () => {
	beforeEach(() => {
		FakeWebSocket.instances = [];
		FakeEventSource.instances = [];
		vi.stubGlobal('WebSocket', FakeWebSocket as unknown as typeof WebSocket);
		vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
		vi.spyOn(console, 'warn').mockImplementation(() => {});
		vi.spyOn(console, 'error').mockImplementation(() => {});
		__resetBootForTests();
		resetWebmailSyncRuntimeForTests();
		disconnectGuestEventSource();
	});

	afterEach(() => {
		disconnectGuestEventSource();
		resetWebmailSyncRuntimeForTests();
		__resetBootForTests();
		vi.restoreAllMocks();
		vi.unstubAllGlobals();
	});

	it('member WebSocket hub attaches/detaches scopes, re-sends on reconnect, and disconnect() clears atTypeHandlers & scopes', async () => {
		vi.useFakeTimers();
		try {
			const hub = createWebSocketHub({
				backoff: { baseDelayMs: 100, random: () => 1 },
				scopeAttachSupported: true,
			});
			const transport = new WebmailWakeupTransport({ mode: 'member', wsHub: hub });
			const coord = new SyncCoordinator({ transport });

			const calRefresh = vi.fn();
			const unsubCal = coord.register(
				createJmapRefreshAdapter({
					consumerId: 'cal',
					mailboxScopeId: 'primary',
					dataTypes: ['Calendar'],
					refresh: calRefresh,
				}),
			);

			expect(FakeWebSocket.instances).toHaveLength(1);
			const sock1 = FakeWebSocket.instances[0];
			sock1.open();

			// Initial open sends ScopeAttach for live union.
			const attachFrames = sock1.sent.map((s) => JSON.parse(s)).filter((f) => f['@type'] === 'ScopeAttach');
			expect(attachFrames).toHaveLength(1);
			expect(attachFrames[0].scopes).toEqual([{ scopeKind: 'mailbox', scopeId: 'primary' }]);

			// Dynamic ScopeAttach when second scope registers.
			const unsubSpace = coord.register({
				consumerId: 'drive-3',
				scope: { kind: 'space', id: '3' },
				runDeltaStep: async () => ({ kind: 'complete' }),
			});
			const attach2 = sock1.sent.map((s) => JSON.parse(s)).filter((f) => f['@type'] === 'ScopeAttach');
			expect(attach2[attach2.length - 1].scopes).toEqual([{ scopeKind: 'space', scopeId: '3' }]);

			// Dynamic ScopeDetach on unregister.
			unsubSpace();
			const detachFrames = sock1.sent.map((s) => JSON.parse(s)).filter((f) => f['@type'] === 'ScopeDetach');
			expect(detachFrames[0].scopes).toEqual([{ scopeKind: 'space', scopeId: '3' }]);

			// Reconnect re-attaches remaining scopes and triggers reconnect catch-up.
			sock1.close();
			vi.advanceTimersByTime(100);
			expect(FakeWebSocket.instances).toHaveLength(2);
			const sock2 = FakeWebSocket.instances[1];
			sock2.open();
			await coord.flush();
			expect(calRefresh).toHaveBeenCalledOnce();
			expect(
				sock2.sent.map((s) => JSON.parse(s)).some(
					(f) => f['@type'] === 'ScopeAttach' && f.scopes.length === 1 && f.scopes[0].scopeId === 'primary',
				),
			).toBe(true);

			// disconnect() clears atTypeHandlers + attached scopes so late frames never fire.
			const atTypeSpy = vi.fn();
			hub.subscribeType('SyncWakeup', atTypeSpy);
			hub.disconnect();
			hub.handleRawMessage(
				JSON.stringify({ '@type': 'SyncWakeup', event: { scopeKind: 'mailbox', scopeId: 'primary', seq: 9 } }),
			);
			expect(atTypeSpy).not.toHaveBeenCalled();

			unsubCal();
			coord.dispose();
		} finally {
			vi.useRealTimers();
		}
	});

	it('guest shared ref-counted EventSource serves ChatApp + MeetApp + MeetChatPanel + sync_wakeup + scope_revoked with deterministic late-subscriber onOpen', async () => {
		vi.useFakeTimers();
		try {
			const chatHits: unknown[] = [];
			const meetHits: unknown[] = [];
			const panelHits: unknown[] = [];
			const wakeups: unknown[] = [];
			const revokes: unknown[] = [];
			const open1 = vi.fn();
			const open2 = vi.fn();
			const lateOpen = vi.fn();

			// Three guest consumers share ONE EventSource instance.
			const offChat = subscribeGuestChatEvents((e) => chatHits.push(e), open1);
			const offMeet = subscribeGuestMeetEvents((e) => meetHits.push(e), open2);
			const offPanel = subscribeGuestChatEvents((e) => panelHits.push(e));
			const offWakeup = subscribeGuestSyncWakeup((e) => wakeups.push(e));
			const offRevoke = subscribeGuestScopeRevoked((e) => revokes.push(e));

			expect(FakeEventSource.instances).toHaveLength(1);
			const src1 = FakeEventSource.instances[0];
			src1.emit('open', undefined);
			expect(open1).toHaveBeenCalledTimes(1);
			expect(open2).toHaveBeenCalledTimes(1);

			// Late subscriber joining an already-open stream does NOT open a second EventSource
			// and receives its onOpen catch-up microtask immediately.
			const offLate = subscribeGuestChatEvents(() => {}, lateOpen);
			expect(FakeEventSource.instances).toHaveLength(1);
			await Promise.resolve();
			expect(lateOpen).toHaveBeenCalledTimes(1);

			// Named events route cleanly to their subscribers.
			src1.emit('chat', JSON.stringify({ event: 'message_created', channelId: 4, seq: 2 }));
			src1.emit('meet', JSON.stringify({ event: 'recording_state', meetingId: 8 }));
			src1.emit('sync_wakeup', JSON.stringify({ scopeKind: 'channel', scopeId: '4', seq: 3 }));
			src1.emit('scope_revoked', JSON.stringify({ scopeKind: 'channel', scopeId: '4' }));
			expect(chatHits).toHaveLength(1);
			expect(panelHits).toHaveLength(1);
			expect(meetHits).toHaveLength(1);
			expect(wakeups).toEqual([{ scopeKind: 'channel', scopeId: '4', seq: 3 }]);
			expect(revokes).toEqual([{ scopeKind: 'channel', scopeId: '4' }]);

			// Reconnect invokes ALL active subscribers' onOpen.
			src1.emit('error', undefined);
			expect(src1.closed).toBe(true);
			vi.advanceTimersByTime(1_000);
			expect(FakeEventSource.instances).toHaveLength(2);
			FakeEventSource.instances[1].emit('open', undefined);
			expect(open1).toHaveBeenCalledTimes(2);
			expect(open2).toHaveBeenCalledTimes(2);
			expect(lateOpen).toHaveBeenCalledTimes(2);

			// Partial unsubscribes keep the shared stream open; last unsubscribe closes it.
			offChat();
			offMeet();
			offPanel();
			offWakeup();
			offRevoke();
			expect(FakeEventSource.instances[1].closed).toBe(false);
			offLate();
			expect(FakeEventSource.instances[1].closed).toBe(true);
		} finally {
			vi.useRealTimers();
		}
	});

	it('shared-mailbox scope_revoked evicts ONLY InboxStore memory + sets accessRevoked=true without calling db.wipe("mail")', async () => {
		const dbWipe = vi.fn();
		window.setjoinNative = {
			version: 1,
			capabilities: ['mailDb'],
			db: { open: vi.fn(), isOpen: vi.fn(), exec: vi.fn(), query: vi.fn(), wipe: dbWipe },
		} as unknown as import('$lib/native/types').SetjoinNativeBridge;

		const inbox = new InboxStore();
		inbox.accountOverride = 'shared-42';
		inbox.emails = [{ id: 'e1', mailboxIds: { m1: true }, receivedAt: '2026-01-01T00:00:00Z' } as never];
		inbox.accessRevoked = false;

		const coord = new SyncCoordinator();
		coord.register(createInboxSyncAdapter({ store: inbox, mailboxScopeId: 'shared-42', isSharedMailbox: true }));

		await coord.handleScopeRevoked({ scopeKind: 'mailbox', scopeId: 'shared-42', reason: 'grant_revoked' });

		expect(inbox.emails).toEqual([]);
		expect(inbox.selectedEmail).toBeNull();
		expect(inbox.accessRevoked).toBe(true);
		expect(dbWipe).not.toHaveBeenCalled();

		coord.dispose();
		delete (window as { setjoinNative?: unknown }).setjoinNative;
	});

	it('Chat non-additive resync / tombstoneFloorExceeded removes vanished messages and scope_revoked clears all 7 slices', async () => {
		const store = new ChatStore();
		store.conversations = [
			{
				channelId: 50,
				kind: 'channel',
				name: 'general',
				topic: null,
				changeSeq: 5,
				lastReadSeq: 1,
				unreadCount: 2,
				hasMention: false,
				hasExternalMembers: false,
				lastMessagePreview: null,
				memberIds: [1, 2],
			},
		];
		store.activeChannelId = 50;
		store.messagesByChannel[50] = [
			{ ...makeChatMsg(101, 1, 'old-deleted', { pollId: 900 }), status: 'sent' },
			{ ...makeChatMsg(102, 2, 'kept'), status: 'sent' },
		];
		store.typingUsers = [{ channelId: 50, userId: 2, expiresAt: Date.now() + 4000 }];
		store.peerReadSeq[50] = 2;
		store.pollResultsByPollId[900] = {
			pollId: 900,
			question: 'Q?',
			multi: false,
			closesAt: null,
			closed: false,
			options: [],
		};
		store.pendingAttachments['50:root'] = [
			{
				clientId: 'att-1',
				file: new File(['x'], 'a.txt'),
				status: 'ready',
				progress: 1,
				size: 1,
				name: 'a.txt',
				contentType: 'text/plain',
			},
		];

		// #553 resync sentinel triggers non-additive snapshot replacement (vanished msg 101 removed!).
		const sinceMessages = vi.fn(async (): Promise<ChatReplay> => ({
			messages: [],
			cursor: 10,
			resync: true,
		}));
		// Server returns newest-first (DESC): [msg 103 (seq 10), msg 102 (seq 2)]
		const listMessages = vi.fn(async (): Promise<ChatMessage[]> => [
			makeChatMsg(103, 10, 'fresh', { pollId: 900 }),
			makeChatMsg(102, 2, 'kept'),
		]);

		const coord = new SyncCoordinator();
		coord.register(
			createChatChannelSyncAdapter({
				store,
				channelId: 50,
				sinceMessages,
				listMessages,
				refreshConversations: false,
			}),
		);

		coord.handleWakeup({ scopeKind: 'channel', scopeId: '50', seq: 10 });
		await coord.flush();

		expect(store.messagesByChannel[50].map((m) => m.messageId)).toEqual([102, 103]);
		expect(store.getReplayCursor(50)).toBe(10);

		// scope_revoked evicts ALL 7 slices!
		await coord.handleScopeRevoked({ scopeKind: 'channel', scopeId: '50', reason: 'kicked' });
		expect(store.messagesByChannel[50]).toBeUndefined();
		expect(store.conversations).toEqual([]);
		expect(store.activeChannelId).toBeNull();
		expect(store.typingUsers).toEqual([]);
		expect(store.peerReadSeq[50]).toBeUndefined();
		expect(store.pollResultsByPollId[900]).toBeUndefined();
		expect(store.pendingAttachments['50:root']).toBeUndefined();
		expect(store.getReplayCursor(50)).toBe(0);

		coord.dispose();
	});

	it('preserves E4-I default-inertness (syncQoS absent/off) + shared CriticalActivityCounter + offline.wipe fail-closed deviceId targeting', async () => {
		// syncQoS absent → offline coordinator stays completely inert.
		const cleanup = composeOfflineCoordinatorForSession(
			{ effectiveCapabilities: {} },
			{ email: 'a@example.com', isAdmin: false, hasMailbox: true, userId: 1 },
		);
		expect(cleanup).toBeUndefined();
		expect(hasActiveOfflineCoordinator()).toBe(false);

		// Runtime shares the exact same CriticalActivityCounter instance as offline/boot.ts.
		const sharedCritical = getSharedCriticalActivity();
		const runtimeCoord = getWebmailSyncCoordinator('member');
		expect(runtimeCoord).toBeDefined();

		// Default adapter path stays inert when boot has no composition (zero jobs enqueued).
		runtimeCoord.register(createOfflineMailSyncAdapter({ mailboxScopeId: 'primary' }));
		runtimeCoord.handleWakeup({ scopeKind: 'mailbox', scopeId: 'primary', seq: 1 });
		await runtimeCoord.flush();
		expect(hasActiveOfflineCoordinator()).toBe(false);

		// When an ingest seam is supplied (composed coordinator), wakeups route through it.
		const ingestSpy = vi.fn();
		const activeCoord = new SyncCoordinator({ critical: sharedCritical });
		activeCoord.register(
			createOfflineMailSyncAdapter({
				mailboxScopeId: 'primary',
				ingestPushTrigger: ingestSpy,
			}),
		);
		activeCoord.handleWakeup({ scopeKind: 'mailbox', scopeId: 'primary', seq: 2 });
		await activeCoord.flush();
		expect(ingestSpy).toHaveBeenCalledTimes(1);
		activeCoord.dispose();

		// MailPageCapacityError does not retry-loop.
		const onCap = vi.fn();
		const capCoord = new SyncCoordinator({ critical: sharedCritical });
		const capIngest = vi.fn(() => {
			throw new MailPageCapacityError(false);
		});
		capCoord.register(
			createOfflineMailSyncAdapter({
				mailboxScopeId: 'primary',
				ingestPushTrigger: capIngest,
				onCapacityExceeded: onCap,
			}),
		);
		capCoord.trigger({ kind: 'mailbox', id: 'primary' });
		await capCoord.flush();
		expect(capIngest).toHaveBeenCalledTimes(1);
		expect(onCap).toHaveBeenCalledOnce();
		expect(capCoord.getState('offline-mail:primary', { kind: 'mailbox', id: 'primary' })?.storageFull).toBe(true);

		// offline.wipe fail-closed deviceId targeting:
		// 1. Sibling device no-ops.
		const wipeDb = vi.fn(async () => {});
		const abortSync = vi.fn(async () => {});
		const logout = vi.fn();
		const siblingApplied = await executeSecurityOfflineWipe({
			event: { appKey: 'mail', deviceId: 1 },
			readDeviceId: async () => '2',
			abortSyncCoordinator: abortSync,
			wipeDb,
			logout,
		});
		expect(siblingApplied).toBe(false);
		expect(abortSync).not.toHaveBeenCalled();
		expect(wipeDb).not.toHaveBeenCalled();

		// 2. Missing ownDeviceId no-ops on targeted wipe.
		const missingApplied = await executeSecurityOfflineWipe({
			event: { appKey: 'mail', deviceId: 1 },
			readDeviceId: async () => null,
			abortSyncCoordinator: abortSync,
			wipeDb,
			logout,
		});
		expect(missingApplied).toBe(false);
		expect(wipeDb).not.toHaveBeenCalled();

		// 3. Matching device aborts in-flight sync BEFORE db.wipe('mail') even while criticalActivity > 0!
		const order: string[] = [];
		const critHandle = sharedCritical.begin('send');
		const matched = await executeSecurityOfflineWipe({
			event: { appKey: 'mail', deviceId: 7 },
			readDeviceId: async () => '7',
			abortSyncCoordinator: async () => {
				order.push('abort');
			},
			wipeDb: async (key) => {
				order.push(`wipe:${key}`);
			},
			logout: () => {
				order.push('logout');
			},
		});
		critHandle.end();
		expect(matched).toBe(true);
		expect(order).toEqual(['abort', 'wipe:mail', 'logout']);

		capCoord.dispose();
	});

	it('Drive online adapter handles HTTP 409 full resync, subtreeAnchorId reload, and full-space revoke eviction', async () => {
		let sinceSeq = 12;
		const cleared = vi.fn();
		const reloaded = vi.fn(async () => {});
		let fail409 = true;

		const coord = new SyncCoordinator();
		coord.register(
			createDriveOnlineSyncAdapter({
				spaceId: 8,
				getSinceSeq: () => sinceSeq,
				setSinceSeq: (s) => {
					sinceSeq = s;
				},
				fetchChanges: async () => {
					if (fail409) {
						fail409 = false;
						throw Object.assign(new Error('conflict'), { status: 409 });
					}
					return { changed: [] };
				},
				reloadListing: reloaded,
				clearSpaceView: cleared,
			}),
		);

		// HTTP 409 triggers runFullResyncStep resetting sinceSeq to 0 and reloading.
		coord.trigger({ kind: 'space', id: '8' });
		await coord.flush();
		expect(sinceSeq).toBe(0);
		expect(reloaded).toHaveBeenCalledTimes(1);

		// Subtree revoke reloads server-authoritative view (does not clear entire space).
		await coord.handleScopeRevoked({ scopeKind: 'space', scopeId: '8', subtreeAnchorId: '44' });
		expect(reloaded).toHaveBeenCalledTimes(2);
		expect(cleared).not.toHaveBeenCalled();

		// Full space revoke clears view state.
		await coord.handleScopeRevoked({ scopeKind: 'space', scopeId: '8' });
		expect(cleared).toHaveBeenCalledOnce();

		coord.dispose();
	});

	it('guest WebmailWakeupTransport validates sync_wakeup/scope_revoked and ignores malformed frames', async () => {
		const guestHub = createGuestEventSourceHub();
		const transport = new WebmailWakeupTransport({ mode: 'guest', guestHub });
		const coord = new SyncCoordinator({ transport });

		const delta = vi.fn(async () => ({ kind: 'complete' as const, appliedSeq: 5 }));
		const purge = vi.fn();
		coord.register({
			consumerId: 'guest-chat-7',
			scope: { kind: 'channel', id: '7' },
			runDeltaStep: delta,
			purgeScopeCache: purge,
		});

		const src = FakeEventSource.instances[0];
		src.emit('open', undefined);
		// Malformed wakeup dropped fail-closed.
		src.emit('sync_wakeup', JSON.stringify({ scopeKind: 'bogus', scopeId: '7', seq: -1 }));
		await coord.flush();
		expect(delta).not.toHaveBeenCalled();

		// Valid wakeup & revoke processed.
		src.emit('sync_wakeup', JSON.stringify({ scopeKind: 'channel', scopeId: '7', seq: 5 }));
		await coord.flush();
		expect(delta).toHaveBeenCalledTimes(1);

		src.emit('scope_revoked', JSON.stringify({ scopeKind: 'channel', scopeId: '7' }));
		await coord.flush();
		expect(purge).toHaveBeenCalledWith({ scopeKind: 'channel', scopeId: '7' });

		coord.dispose();
		transport.disconnect();
		guestHub.disconnect();
	});

	it('logout + re-login reconstructs a live transport/coordinator pair that receives wakeups, reconnects, and scope_revoked (#555 fix #3)', async () => {
		const { __handleRawMessage, disconnect } = await import('$lib/jmap/websocket');
		const coord1 = getWebmailSyncCoordinator('member');
		const hits1 = vi.fn(async () => ({ kind: 'complete' as const }));
		coord1.register({
			consumerId: 'session1-chat',
			scope: { kind: 'channel', id: '10' },
			runDeltaStep: hits1,
		});

		// Simulate logout teardown (runtime resets via teardown).
		resetWebmailSyncRuntimeForTests();
		disconnect();
		expect(coord1.disposed).toBe(true);

		// Re-login gets a brand-new live coordinator + connected transport!
		const coord2 = getWebmailSyncCoordinator('member');
		expect(coord2).not.toBe(coord1);
		expect(coord2.disposed).toBe(false);

		const hits2 = vi.fn(async () => ({ kind: 'complete' as const }));
		const purged2 = vi.fn();
		coord2.register({
			consumerId: 'session2-chat',
			scope: { kind: 'channel', id: '10' },
			runDeltaStep: hits2,
			purgeScopeCache: purged2,
		});

		__handleRawMessage(
			JSON.stringify({ '@type': 'SyncWakeup', event: { scopeKind: 'channel', scopeId: '10', seq: 4 } }),
		);
		await coord2.flush();
		expect(hits2).toHaveBeenCalledTimes(1);
		expect(hits1).not.toHaveBeenCalled();

		__handleRawMessage(
			JSON.stringify({ '@type': 'ScopeRevoked', event: { scopeKind: 'channel', scopeId: '10' } }),
		);
		await coord2.flush();
		expect(purged2).toHaveBeenCalledWith({ scopeKind: 'channel', scopeId: '10' });
	});

	it('sibling-device offline.wipe frame on WebSocket does NOT abort this device via WebmailWakeupTransport (4e)', async () => {
		const hub = createWebSocketHub();
		const transport = new WebmailWakeupTransport({ mode: 'member', wsHub: hub });
		const coord = new SyncCoordinator({ transport });

		let aborted = false;
		let finishStep!: () => void;
		const stepGate = new Promise<void>((r) => {
			finishStep = r;
		});

		coord.register({
			consumerId: 'mail-live',
			scope: { kind: 'mailbox', id: 'primary' },
			runDeltaStep: async (ctx) => {
				ctx.signal.addEventListener('abort', () => {
					aborted = true;
				});
				await stepGate;
				ctx.fence.assertCommitAllowed();
				return { kind: 'complete' };
			},
		});

		coord.trigger({ kind: 'mailbox', id: 'primary' });
		await Promise.resolve();

		// Unverified sibling-device offline.wipe arrives on WS — must NOT abort before ownDeviceId check!
		hub.handleRawMessage(JSON.stringify({ type: 'offline.wipe', deviceId: 999 }));
		expect(aborted).toBe(false);

		finishStep();
		await coord.flush();
		expect(aborted).toBe(false);
		coord.dispose();
		transport.disconnect();
	});

	it('ChatStore fences late-settling openChannel and loadConversations after revokeChannelScope (4c)', async () => {
		const chatApi = await import('$lib/chat/api');
		const store = new ChatStore();

		let resolveMsgs!: (rows: ChatMessage[]) => void;
		const listSpy = vi.spyOn(chatApi, 'listMessages').mockImplementation(
			() =>
				new Promise<ChatMessage[]>((resolve) => {
					resolveMsgs = resolve;
				}),
		);
		let resolveConvs!: (env: { conversations: typeof store.conversations; attachmentsEnabled: boolean }) => void;
		const convSpy = vi.spyOn(chatApi, 'listConversations').mockImplementation(
			() =>
				new Promise((resolve) => {
					resolveConvs = resolve;
				}),
		);

		const openP = store.openChannel(50);
		const convP = store.loadConversations();

		// Revoke channel 50 mid-flight!
		store.revokeChannelScope(50);

		resolveMsgs([makeChatMsg(1, 1, 'leaked')]);
		resolveConvs({
			conversations: [
				{
					channelId: 50,
					kind: 'channel',
					name: 'revoked',
					topic: null,
					changeSeq: 1,
					lastReadSeq: 0,
					unreadCount: 1,
					hasMention: false,
					hasExternalMembers: false,
					lastMessagePreview: null,
					memberIds: [1],
				},
			],
			attachmentsEnabled: true,
		});
		await Promise.all([openP, convP]);

		expect(store.messagesByChannel[50]).toBeUndefined();
		expect(store.conversations).toEqual([]);
		listSpy.mockRestore();
		convSpy.mockRestore();
	});

	it('mixed-version WS hub suppresses ScopeAttach by default and silently latches off on unknownType (Finding #12)', () => {
		const hubDefault = createWebSocketHub();
		const unsub1 = hubDefault.subscribe(['Email'], () => {});
		const sock1 = FakeWebSocket.instances[0];
		sock1.open();
		hubDefault.setAttachedScopes([{ kind: 'mailbox', id: 'primary' }]);
		expect(sock1.sent.map((s) => JSON.parse(s)).filter((f) => f['@type'] === 'ScopeAttach')).toHaveLength(0);
		unsub1();
		hubDefault.disconnect();

		// When enabled and server replies unknownType, latches off silently without erroring or closing.
		const hubOptIn = createWebSocketHub({ scopeAttachSupported: true });
		const unsub2 = hubOptIn.subscribe(['Email'], () => {});
		const sock2 = FakeWebSocket.instances[1];
		sock2.open();
		hubOptIn.setAttachedScopes([{ kind: 'mailbox', id: 'primary' }]);
		expect(sock2.sent.map((s) => JSON.parse(s)).filter((f) => f['@type'] === 'ScopeAttach')).toHaveLength(1);
		hubOptIn.handleRawMessage(JSON.stringify({ '@type': 'RequestError', type: 'urn:ietf:params:jmap:error:unknownType' }));
		hubOptIn.setAttachedScopes([
			{ kind: 'mailbox', id: 'primary' },
			{ kind: 'channel', id: '9' },
		]);
		// No second ScopeAttach frame emitted after unknownType latched off.
		expect(sock2.sent.map((s) => JSON.parse(s)).filter((f) => f['@type'] === 'ScopeAttach')).toHaveLength(1);
		expect(sock2.readyState).toBe(FakeWebSocket.OPEN);
		unsub2();
		hubOptIn.disconnect();
	});

	it('Chat incremental replay & replaceChannelSnapshot preserve optimistic rows and NEVER advance cursor to MAX_SAFE_INTEGER (Finding #8)', async () => {
		const store = new ChatStore();
		store.messagesByChannel = {
			50: [
				{ ...makeChatMsg(1, 10, 'confirmed'), status: 'sent' },
				{
					...makeChatMsg(-100, Number.MAX_SAFE_INTEGER, 'in-flight'),
					clientId: 'cid-sending',
					status: 'sending',
				},
				{
					...makeChatMsg(-101, Number.MAX_SAFE_INTEGER, 'failed-local'),
					clientId: 'cid-failed',
					status: 'failed',
				},
			],
		};

		const coord = new SyncCoordinator();
		coord.register(
			createChatChannelSyncAdapter({
				store,
				channelId: 50,
				refreshConversations: false,
				sinceMessages: async () => ({
					messages: [makeChatMsg(2, 11, 'remote-new')],
					cursor: 11,
				}),
				listMessages: async () => [makeChatMsg(2, 11, 'remote-new'), makeChatMsg(1, 10, 'confirmed')],
			}),
		);

		// 1. Incremental replay MUST keep sending/failed rows untouched and cursor at 11 (NOT MAX_SAFE_INTEGER!).
		coord.handleWakeup({ scopeKind: 'channel', scopeId: '50', seq: 11 });
		await coord.flush();
		expect(store.getReplayCursor(50)).toBe(11);
		const sendingRow = store.messagesByChannel[50].find((m) => m.clientId === 'cid-sending');
		const failedRow = store.messagesByChannel[50].find((m) => m.clientId === 'cid-failed');
		expect(sendingRow?.status).toBe('sending');
		expect(failedRow?.status).toBe('failed');

		// 2. Non-additive replaceChannelSnapshot ALSO preserves pending/failed optimistic rows & real cursor!
		store.replaceChannelSnapshot(50, [makeChatMsg(1, 10, 'confirmed'), makeChatMsg(2, 11, 'remote-new')], 12);
		expect(store.getReplayCursor(50)).toBe(12);
		expect(store.messagesByChannel[50].find((m) => m.clientId === 'cid-sending')?.status).toBe('sending');
		expect(store.messagesByChannel[50].find((m) => m.clientId === 'cid-failed')?.status).toBe('failed');

		coord.dispose();
	});

	it('evicts inactive cached Chat channel via session observer & fences late-settling loadPollResults (Finding #9)', async () => {
		const chatApi = await import('$lib/chat/api');
		const store = new ChatStore();
		store.messagesByChannel = {
			77: [{ ...makeChatMsg(5, 5, 'poll-msg', { pollId: 901 }), channelId: 77, status: 'sent' }],
		};

		let resolvePoll!: (res: import('$lib/chat/api').ChatPollResults) => void;
		const pollSpy = vi.spyOn(chatApi, 'pollResults').mockImplementation(
			() =>
				new Promise((resolve) => {
					resolvePoll = resolve;
				}),
		);

		const coord = new SyncCoordinator();
		const off = coord.onScopeRevoked((event) => {
			if (event.scopeKind === 'channel') {
				const cid = Number(event.scopeId);
				if (Number.isSafeInteger(cid) && cid > 0) store.revokeChannelScope(cid);
			}
		});

		const pollP = store.loadPollResults(901);
		// Channel 77 is NOT registered as active consumer on coord — observer still evicts it!
		await coord.handleScopeRevoked({ scopeKind: 'channel', scopeId: '77' });
		expect(store.messagesByChannel[77]).toBeUndefined();

		// Late pollResults response MUST be discarded by channel revocation fence!
		resolvePoll({ pollId: 901, question: 'Q?', multi: false, closesAt: null, closed: false, options: [] });
		await pollP;
		expect(store.pollResultsByPollId[901]).toBeUndefined();

		off();
		coord.dispose();
		pollSpy.mockRestore();
	});

	it('purges cached poll tallies on revokeChannelScope even after replaceChannelSnapshot drops the poll message (Delta #6)', async () => {
		const chatApi = await import('$lib/chat/api');
		const store = new ChatStore();
		const pollSpy = vi.spyOn(chatApi, 'pollResults').mockResolvedValue({
			pollId: 902,
			question: 'Lunch?',
			multi: false,
			closesAt: null,
			closed: false,
			options: [],
		});

		store.messagesByChannel = {
			88: [{ ...makeChatMsg(6, 6, 'poll-msg', { pollId: 902 }), channelId: 88, status: 'sent' }],
		};
		await store.loadPollResults(902);
		expect(store.pollResultsByPollId[902]).toBeDefined();

		// Earlier non-additive snapshot replacement drops the poll message from the timeline.
		store.replaceChannelSnapshot(88, [makeChatMsg(7, 7, 'newer-msg')]);
		// Revoking channel 88 MUST STILL purge pollResultsByPollId[902] via persistent ownership map!
		store.revokeChannelScope(88);
		expect(store.pollResultsByPollId[902]).toBeUndefined();
		pollSpy.mockRestore();
	});

	it('real installWipeHandler honors appKey, enforces fail-closed deviceId targeting, and works after logout -> re-login (Finding #10)', async () => {
		const { installWipeHandler } = await import('$lib/offline/wipe');
		const { __handleRawMessage, disconnect } = await import('$lib/jmap/websocket');
		const wipeSpy = vi.fn(async () => {});
		window.setjoinNative = {
			version: 1,
			capabilities: ['mailDb', 'drive', 'secureStore'],
			secureStore: {
				get: async (k: string) => (k === 'device_id' ? '42' : null),
				set: async () => {},
				remove: async () => {},
			},
			db: {
				open: async () => {},
				isOpen: async () => true,
				exec: async () => 0,
				query: async () => [],
				wipe: wipeSpy,
			},
		} as unknown as import('$lib/native/types').SetjoinNativeBridge;

		const logout1 = vi.fn();
		const postAck = vi.fn(async () => {});
		const off1 = installWipeHandler({ logout: logout1, postAck });

		// Simulate SPA logout (disconnect clears WS controlHandlers) + re-login reinstalling handler!
		off1();
		disconnect();

		const logout2 = vi.fn();
		const off2 = installWipeHandler({ logout: logout2, postAck });

		// 1. Sibling device wipe is ignored fail-closed.
		__handleRawMessage(JSON.stringify({ type: 'offline.wipe', deviceId: 99, appKey: 'drive' }));
		for (let i = 0; i < 6; i++) await Promise.resolve();
		expect(wipeSpy).not.toHaveBeenCalled();
		expect(logout2).not.toHaveBeenCalled();

		// 2. Invalid appKey is rejected fail-closed.
		__handleRawMessage(JSON.stringify({ type: 'offline.wipe', deviceId: 42, appKey: '../evil' }));
		for (let i = 0; i < 6; i++) await Promise.resolve();
		expect(wipeSpy).not.toHaveBeenCalled();

		// 3. Targeted 'drive' wipe after re-login wipes 'drive' (not hardcoded 'mail') and logs out!
		__handleRawMessage(JSON.stringify({ type: 'offline.wipe', deviceId: 42, appKey: 'drive' }));
		await vi.waitFor(() => expect(wipeSpy).toHaveBeenCalledWith('drive'));
		expect(logout2).toHaveBeenCalledOnce();

		off2();
		delete (window as { setjoinNative?: unknown }).setjoinNative;
	});
});
