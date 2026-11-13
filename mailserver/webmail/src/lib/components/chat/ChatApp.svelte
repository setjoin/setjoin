<svelte:options runes={true} />

<script lang="ts">
	// ChatApp — Task 13 shell + layout + ChannelList; Task 15 wires
	// MessageList/Composer/ThreadPane into the main pane (SplitPane's 3rd
	// region — ThreadPane slides in beside the main pane exactly like the
	// main pane slides in beside ChannelList; mobile push-view CSS lives here
	// too, matching MessageList's own mobile treatment convention).
	import { goto } from '$app/navigation';
	import { chatStore, retentionNotice } from '$lib/chat/store.svelte';
	import * as chatApi from '$lib/chat/api';
	import type { BrowseChannel, ChatWireEvent, RosterMember } from '$lib/chat/api';
	import * as meetApi from '$lib/meet/api';
	import { user } from '$lib/stores/auth';
	import { effectiveCaps, isGuestSession } from '$lib/stores/session';
	import { subscribeEvent } from '$lib/jmap/websocket';
	import { subscribeGuestChatEvents } from '$lib/chat/guestEventSource';
	import { Button, Dialog, Input, Select, EmptyState, Spinner, IconButton, Badge, showToast } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import ChannelList from './ChannelList.svelte';
	import MessageList from './MessageList.svelte';
	import Composer from './Composer.svelte';
	import ThreadPane from './ThreadPane.svelte';
	import PinsPanel from './PinsPanel.svelte';
	import SavedView from './SavedView.svelte';
	import MyThreadsView from './MyThreadsView.svelte';
	import SearchView from './SearchView.svelte';
	import ChannelSettingsSheet from './ChannelSettingsSheet.svelte';
	import FederationRosterSheet from './FederationRosterSheet.svelte';

	// A3.5 Task 4: deep-link target resolved by the route (src/routes/chat/
	// +page.svelte) from a chat push notification's click-through
	// (`?channel=&seq=`, service-worker.ts's chatNotificationUrl). Both null
	// on a plain mount — the effect below is then a no-op.
	let { deepLinkChannel = null, deepLinkSeq = null }: { deepLinkChannel?: number | null; deepLinkSeq?: number | null } = $props();

	let loading = $state(true);
	let bannerError = $state('');

	function errorMessage(e: unknown): string {
		if (e instanceof chatApi.ChatError && e.detail) return e.detail;
		return t('common.error');
	}

	async function loadConversations() {
		loading = true;
		try {
			await chatStore.loadConversations();
			bannerError = '';
		} catch (e) {
			bannerError = errorMessage(e);
		} finally {
			loading = false;
		}
	}

	// [UX #17, whole-pipeline review] /auth/me now exposes the caller's own
	// numeric user id (`user_id`, straight from the validated JWT claims —
	// see authserver's session.go:Me) — chat's reducers always took p_user_id
	// from the AUTHENTICATED SESSION regardless, so server-side truth was
	// never affected by the old resolution method, but the CLIENT needs a
	// numeric id to filter itself out of a DM's roster-resolved title /
	// typing list / optimistic authorId (Task 12/15). Root fix: read it
	// straight off the session. The displayName-matching fallback below is
	// kept ONLY for an old gateway that hasn't shipped the `user_id` field
	// yet — a rare duplicate-displayName org would otherwise get a wrong
	// (cosmetic-only) match on THAT path, same as before this fix.
	async function resolveSelfUserId() {
		if (chatStore.selfUserId != null) return;
		if ($user?.userId != null) {
			chatStore.selfUserId = $user.userId;
			return;
		}
		const dm = chatStore.conversations.find((c) => c.kind !== 'channel' && c.memberIds.length > 0);
		if (!dm) return;
		try {
			const roster = await chatApi.listMembers(dm.channelId);
			const me = roster.find((m) => m.displayName === $user?.displayName);
			if (me) chatStore.selfUserId = me.userId;
		} catch {
			// best-effort — leave null, retried next time conversations change
		}
	}

	function handleChatEvent(evt: ChatWireEvent) {
		void chatStore.applyEvent(evt).then((outcome) => {
			if (outcome?.refreshFederationRosterChannelId === chatStore.activeChannelId) refreshFedRoom();
		});
	}

	function handleGuestStreamOpen(): void {
		// Native EventSource emits `open` after the initial connect AND every
		// automatic reconnect. Reconcile the active channel before refreshing the
		// rail so events missed during the gap cannot disappear for this session.
		void chatStore.onSocketOpen().catch((e) => {
			bannerError = errorMessage(e);
		});
	}

	$effect(() => {
		void loadConversations();
		// Guests use the read-only named-event SSE rail. Members retain the
		// established JMAP WebSocket hub, including its Request-frame protocol.
		// Never open that bidirectional socket for a mailbox-less guest.
		if ($user?.accountType === 'guest' || $isGuestSession) {
			return subscribeGuestChatEvents<ChatWireEvent>(handleChatEvent, handleGuestStreamOpen);
		}
		return subscribeEvent<ChatWireEvent>('ChatEvent', handleChatEvent);
	});

	$effect(() => {
		chatStore.conversations;
		void resolveSelfUserId();
	});

	function selectChannel(channelId: number) {
		mainView = 'conversation';
		showPinsPanel = false;
		chatStore.openChannel(channelId).catch((e) => {
			bannerError = errorMessage(e);
		});
	}

	// ── active-channel roster (Task 15: author names/avatars, edit/delete
	// role gating, @channel/@all gating) — fetched ONCE per channel-open here
	// and threaded down to MessageList/Composer/ThreadPane, rather than each
	// of those re-fetching its own copy. ─────────────────────────────────────
	let activeRoster = $state<RosterMember[]>([]);
	let openThreadId = $state<number | null>(null);

	// ── Pillar C2 Task 7: room-federation roster, fetched the SAME way
	// activeRoster is above (once per channel-open, threaded to the header
	// badge + roster sheet) — never on every render, only when the active
	// channel is actually room-bound (federatedRoomId set). ───────────────
	let fedRoom = $state<chatApi.FederationRoomRoster | null>(null);
	let showFederationSheet = $state(false);

	/** Stale-response-guarded (Pillar C2 Task 7 review, MINOR): the channelId
	 *  is captured before the await and the response is discarded if the
	 *  active channel has since changed — a slow roster fetch for a channel
	 *  the user has already navigated away from must never clobber the NEW
	 *  active channel's fedRoom. */
	function refreshFedRoom(): void {
		const cid = chatStore.activeChannelId;
		const conv = chatStore.conversations.find((c) => c.channelId === cid);
		if (!conv?.federatedRoomId) {
			fedRoom = null;
			return;
		}
		chatApi
			.getFederationRoomRoster(conv.channelId)
			.then((r) => {
				if (chatStore.activeChannelId === cid) fedRoom = r;
			})
			.catch(() => {
				if (chatStore.activeChannelId === cid) fedRoom = null;
			});
	}
	// Pillar C2 Task 7 review (MINOR): narrowed to a (channelId, roomId) key,
	// reseed-guarded the SAME way ChannelSettingsSheet's fedKey/lastKey and
	// FederationRosterSheet's lastKey already are in this codebase — a plain
	// (non-reactive) lastFedKey compared inline, NOT a bare $derived read
	// (Svelte's effect-rerun-on-dependency-change does not itself dedupe on
	// the derived's output value here — measured, not assumed): this effect
	// still reacts to every chatStore.conversations mutation (it must, to
	// notice a genuine binding change), but refreshFedRoom() itself only
	// runs when the (channelId, roomId) pair actually differs from the last
	// run — an unrelated reload (e.g. a message send bumping unreadCount)
	// that leaves this pair unchanged is a no-op.
	let lastFedKey: string | null = null;
	$effect(() => {
		const conv = chatStore.conversations.find((c) => c.channelId === chatStore.activeChannelId);
		const key = conv?.federatedRoomId ? `${conv.channelId}:${conv.federatedRoomId}` : `${chatStore.activeChannelId}:`;
		if (key === lastFedKey) return;
		lastFedKey = key;
		refreshFedRoom();
	});
	let fedActiveOrgCount = $derived(
		fedRoom?.members.filter((m) => m.state === 'active' || m.state === 'parked').length ?? 0,
	);

	// ── panels/views/settings — A3 QoL Task 16 ──────────────────────────────
	// mainView drives what the main pane renders BESIDE the ChannelList: a
	// real conversation (default) or one of the three fixed-entry/search
	// pseudo-views. Selecting a real channel always resets it to
	// 'conversation' (selectChannel below); the pins panel is a separate,
	// mutually-exclusive-with-ThreadPane SIDE panel (not a main-view swap —
	// it reuses the SAME `.chat-app__thread-region` slide-in ThreadPane uses).
	type MainView = 'conversation' | 'saved' | 'threads' | 'search';
	let mainView = $state<MainView>('conversation');
	let searchInitialQuery = $state('');
	let searchInitialChannelId = $state<number | null>(null);
	let showPinsPanel = $state(false);
	let showSettingsSheet = $state(false);

	function openSaved(): void {
		mainView = 'saved';
		showPinsPanel = false;
		openThreadId = null;
		chatStore.activeChannelId = null;
	}
	function openThreads(): void {
		mainView = 'threads';
		showPinsPanel = false;
		openThreadId = null;
		chatStore.activeChannelId = null;
	}
	function openSearch(scopeChannelId: number | null, query = ''): void {
		mainView = 'search';
		searchInitialChannelId = scopeChannelId;
		searchInitialQuery = query;
		showPinsPanel = false;
		openThreadId = null;
		chatStore.activeChannelId = null;
	}
	/** The click-through every pin/save/thread/search-hit row shares (plan's
	 *  "all click-throughs → openChannelAt"): returns to the conversation view
	 *  and jumps to the target message. */
	function jumpTo(channelId: number, seq: number): void {
		mainView = 'conversation';
		showPinsPanel = false;
		chatStore.openChannelAt(channelId, seq).catch((e) => {
			bannerError = errorMessage(e);
		});
	}
	function togglePinsPanel(): void {
		showPinsPanel = !showPinsPanel;
		if (showPinsPanel) openThreadId = null;
	}

	// [UX #3, pipeline review] the chat→meet huddle bridge (spec §3.3's
	// "no-ring launch") had no SENDER anywhere in webmail — meeting_create
	// accepts chatChannelId and MessageRow already renders the receiver-side
	// call card, but nothing ever posted one. Same enabledApps gate MeetApp
	// itself reads; createMeeting's own narrower CreateMeetingResult carries
	// `slug`, so navigation reuses design #14's ONE canonical deep-link shape
	// (`/meet?slug=…`) rather than duplicating MeetApp's in-room state here.
	let meetEnabled = $derived($effectiveCaps.enabledApps.includes('meet'));
	let guestSession = $derived($user?.accountType === 'guest' || $isGuestSession);
	let startingCall = $state(false);
	async function startCall(channelId: number, title: string): Promise<void> {
		if (startingCall) return;
		startingCall = true;
		try {
			const created = await meetApi.createMeeting({ title, chatChannelId: channelId });
			await goto(`/meet?slug=${encodeURIComponent(created.slug)}`);
		} catch (e) {
			showToast(e instanceof meetApi.MeetError ? e.detail : t('common.error'));
		} finally {
			startingCall = false;
		}
	}

	// A3.5 Task 4: consume the route's deep-link props exactly once — reuses
	// the SAME jumpTo() every pin/save/thread/search-hit click-through already
	// uses, no separate code path. Self-limiting: the route strips the URL
	// params after resolving them, so these props never flip back to
	// non-null on their own (a real re-navigation to a fresh /chat?channel=…
	// remounts this component with new prop values, which is the intended
	// re-fire).
	$effect(() => {
		if (deepLinkChannel != null && deepLinkSeq != null) {
			jumpTo(deepLinkChannel, deepLinkSeq);
		}
	});
	/** Mobile back button: a Saved/Threads/Search view returns to the plain
	 *  conversation-selection state (matching the fixed rows' own "not a real
	 *  channel" semantics); a real open conversation deselects as before. */
	function handleBack(): void {
		if (mainView !== 'conversation') {
			mainView = 'conversation';
			return;
		}
		chatStore.activeChannelId = null;
	}

	// ── whole-pane drag-drop (Chat A2 Task 8 fix) ───────────────────────────
	// The composer strip alone used to be the only drop target: a file dropped
	// over MessageList hit no preventDefault and the browser navigated away to
	// the file, destroying draft/app state. The main pane (MessageList +
	// Composer) is now the drop target; a drop routes into the active
	// composer's own intake via bind:this — cap/accept logic stays
	// single-homed in Composer.acceptDroppedFiles, not duplicated here.
	let composerRef = $state<Composer | null>(null);
	let paneDragCounter = $state(0);

	function hasFileDrag(e: DragEvent): boolean {
		return !!e.dataTransfer?.types.includes('Files');
	}
	function handlePaneDragEnter(e: DragEvent): void {
		if (!chatStore.attachmentsEnabled || !hasFileDrag(e)) return;
		e.preventDefault();
		paneDragCounter++;
	}
	function handlePaneDragOver(e: DragEvent): void {
		if (!chatStore.attachmentsEnabled || !hasFileDrag(e)) return;
		e.preventDefault(); // required for drop to fire
	}
	function handlePaneDragLeave(e: DragEvent): void {
		if (!chatStore.attachmentsEnabled || !hasFileDrag(e)) return;
		paneDragCounter = Math.max(0, paneDragCounter - 1);
	}
	function handlePaneDrop(e: DragEvent): void {
		if (!chatStore.attachmentsEnabled) return;
		e.preventDefault();
		paneDragCounter = 0;
		composerRef?.acceptDroppedFiles(Array.from(e.dataTransfer?.files ?? []));
	}

	$effect(() => {
		const cid = chatStore.activeChannelId;
		openThreadId = null;
		if (cid == null) {
			activeRoster = [];
			return;
		}
		chatApi
			.listMembers(cid)
			.then((roster) => (activeRoster = roster))
			.catch(() => (activeRoster = []));
	});

	let selfRole = $derived(activeRoster.find((m) => m.userId === chatStore.selfUserId)?.role);
	let canBroadcast = $derived(selfRole === 'owner' || selfRole === 'admin');
	// Task 16 makes this live: chat_conversation_list has carried postPermission
	// since Task 7/8 (api.ts's Conversation type only gained it in this task) —
	// a channel gated to admins-only posting disables the composer for anyone
	// who isn't owner/admin (BZ164 is the server-side gate this only avoids
	// bait-clicking). DMs/group_dm never carry 'admins' in practice (no route
	// ever sets post_permission there), so this is a no-op for them either way.
	let composerDisabled = $derived.by(() => {
		if (!activeConversation) return false;
		// Pillar C2 Task 7 — a kicked/scope-revoked room mirror is archive-
		// read-only (BZ213 remains the send-time enforcement; this is the
		// same honesty-affordance posture the attach-disable below uses).
		if (activeConversation.federatedRoomRemoved) return true;
		if (activeConversation.kind !== 'channel') return false;
		return (activeConversation.postPermission ?? 'all') === 'admins' && !canBroadcast;
	});

	let activeTitle = $derived.by(() => {
		if (!activeConversation) return '';
		if (activeConversation.name) return activeConversation.name;
		// Pillar C1 Task 3: a federated DM's roster has ONLY the local user
		// (the remote party is metadata, never a member row) — the normal
		// memberIds/roster resolution below would always find zero
		// counterpart names and fall back to "Direct message". Special-case
		// it BEFORE that resolution, straight off federatedRemoteId.
		if (activeConversation.federatedRemoteId) return activeConversation.federatedRemoteId;
		const names = activeConversation.memberIds
			.filter((id) => id !== chatStore.selfUserId)
			.map((id) => activeRoster.find((m) => m.userId === id)?.displayName)
			.filter((n): n is string => !!n);
		return names.length > 0 ? names.join(', ') : t('chat.list.unknownDm');
	});

	// Guest G2: container-level External state comes from the conversation
	// projection. The active roster remains person-level data for names, roles,
	// and lifecycle badges; it must not be re-derived into channel state here.
	// ── DM "Add people…" (grill Q5): a NEW conversation with the enlarged
	// member set — chat_dm_open's own dedup/ON CONFLICT handles "already
	// exists" server-side; this dialog never mutates the current DM. ────────
	let showAddPeople = $state(false);
	let addPeopleIds = $state('');
	let addingPeople = $state(false);

	function openAddPeopleDialog(): void {
		if (guestSession) return;
		addPeopleIds = '';
		showAddPeople = true;
	}

	async function submitAddPeople(): Promise<void> {
		if (!activeConversation) return;
		const newIds = parseUserIds(addPeopleIds);
		if (newIds.length === 0) return;
		addingPeople = true;
		try {
			const enlarged = [...new Set([...activeConversation.memberIds, ...newIds])];
			const { channelId } = await chatApi.openDM(enlarged);
			showAddPeople = false;
			await loadConversations();
			selectChannel(channelId);
		} catch (e) {
			bannerError = errorMessage(e);
		} finally {
			addingPeople = false;
		}
	}

	// ── Create channel dialog ────────────────────────────────────────────────
	let showCreate = $state(false);
	let createName = $state('');
	let createTopic = $state('');
	let createVisibility = $state<'public' | 'private'>('public');
	let creating = $state(false);

	function openCreate() {
		if (guestSession) return;
		createName = '';
		createTopic = '';
		createVisibility = 'public';
		showCreate = true;
	}

	async function submitCreate() {
		const name = createName.trim();
		if (!name) return;
		creating = true;
		try {
			const { channelId } = await chatApi.createChannel({
				name,
				topic: createTopic.trim(),
				visibility: createVisibility,
			});
			showCreate = false;
			await loadConversations();
			selectChannel(channelId);
		} catch (e) {
			bannerError = errorMessage(e);
		} finally {
			creating = false;
		}
	}

	// ── New DM dialog ────────────────────────────────────────────────────────
	let showDm = $state(false);
	let dmUserIds = $state('');
	let openingDm = $state(false);

	function openDmDialog() {
		if (guestSession) return;
		dmUserIds = '';
		federatedAddr = '';
		showDm = true;
	}

	function parseUserIds(raw: string): number[] {
		return raw
			.split(',')
			.map((s) => Number(s.trim()))
			.filter((n) => Number.isInteger(n) && n > 0);
	}

	async function submitDm() {
		const ids = parseUserIds(dmUserIds);
		if (ids.length === 0) return;
		openingDm = true;
		try {
			const { channelId } = await chatApi.openDM(ids);
			showDm = false;
			await loadConversations();
			selectChannel(channelId);
		} catch (e) {
			bannerError = errorMessage(e);
		} finally {
			openingDm = false;
		}
	}

	// ── Pillar C1 Task 3 — "message user@domain": the ONLY user-facing entry
	// point to POST /chat/dm/federated, riding the SAME New DM dialog as the
	// local-user path above rather than a separate dialog (one compose
	// surface, two targets). 404s (feature.federation off) and BZ204 (peer
	// not allow-listed) both surface as the ordinary bannerError toast — no
	// client-side toggle check, since a route 404 already degrades cleanly. ──
	let federatedAddr = $state('');
	let openingFederatedDm = $state(false);

	async function submitFederatedDm(): Promise<void> {
		const addr = federatedAddr.trim();
		if (!addr) return;
		openingFederatedDm = true;
		try {
			const { channelId } = await chatApi.openFederatedDM(addr);
			showDm = false;
			await loadConversations();
			selectChannel(channelId);
		} catch (e) {
			bannerError = errorMessage(e);
		} finally {
			openingFederatedDm = false;
		}
	}

	// ── Browse channels dialog ───────────────────────────────────────────────
	let showBrowse = $state(false);
	let browseList = $state<BrowseChannel[]>([]);
	let browseLoading = $state(false);

	async function openBrowse() {
		if (guestSession) return;
		showBrowse = true;
		browseLoading = true;
		try {
			browseList = await chatApi.browseChannels();
		} catch (e) {
			bannerError = errorMessage(e);
		} finally {
			browseLoading = false;
		}
	}

	async function joinBrowsed(channel: BrowseChannel) {
		try {
			await chatApi.joinChannel(channel.channelId);
			browseList = browseList.map((c) => (c.channelId === channel.channelId ? { ...c, joined: true } : c));
			await loadConversations();
		} catch (e) {
			bannerError = errorMessage(e);
		}
	}

	let activeConversation = $derived(
		chatStore.conversations.find((c) => c.channelId === chatStore.activeChannelId) ?? null,
	);

	// Task 16: the mobile "push a full-screen main pane over the list" rule
	// (Global Constraints: "mobile = the existing push-view stack") now covers
	// the three fixed/search views too, not just a real open conversation.
	let mainPaneOpen = $derived(activeConversation != null || mainView !== 'conversation');
</script>

<div class="chat-app">
	{#if bannerError}
		<div class="chat-app__banner" role="alert">
			<Icon name="AlertTriangle" size={14} />
			<span>{bannerError}</span>
			<Button variant="ghost" size="sm" onclick={() => (bannerError = '')}>{t('common.close')}</Button>
		</div>
	{/if}

	{#if loading}
		<div class="chat-app__loading"><Spinner /></div>
	{:else if chatStore.conversations.length === 0}
		<div class="chat-app__empty">
			{#if guestSession}
				<EmptyState title={t('chat.empty.waiting')} />
			{:else}
				<EmptyState title={t('chat.empty.title')}>
					{#snippet action()}
						<div class="chat-app__empty-actions">
							<Button variant="primary" onclick={openCreate}>{t('chat.empty.createChannel')}</Button>
							<Button variant="secondary" onclick={openDmDialog}>{t('chat.empty.newDm')}</Button>
							<Button variant="secondary" onclick={openBrowse}>{t('chat.empty.browse')}</Button>
						</div>
					{/snippet}
				</EmptyState>
			{/if}
		</div>
	{:else}
		<div class="chat-app__body" class:chat-app__body--conversation-open={mainPaneOpen}>
			<ChannelList
				conversations={chatStore.conversations}
				activeChannelId={chatStore.activeChannelId}
				selfUserId={chatStore.selfUserId}
				showMemberActions={!guestSession}
				onSelect={selectChannel}
				onNewChannel={openCreate}
				onNewDM={openDmDialog}
				onBrowse={openBrowse}
				activeView={mainView === 'saved' ? 'saved' : mainView === 'threads' ? 'threads' : 'conversation'}
				onSelectSaved={openSaved}
				onSelectThreads={openThreads}
				onSearch={(q) => openSearch(null, q)}
			/>
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div
				class="chat-app__main-pane"
				class:chat-app__main-pane--dragover={paneDragCounter > 0}
				ondragenter={handlePaneDragEnter}
				ondragover={handlePaneDragOver}
				ondragleave={handlePaneDragLeave}
				ondrop={handlePaneDrop}
			>
				{#if mainPaneOpen}
					<div class="chat-app__mobile-back">
						<Button variant="ghost" size="sm" onclick={handleBack}>
							<Icon name="ArrowLeft" size={16} />
							{t('chat.list.title')}
						</Button>
					</div>
				{/if}
				{#if mainView === 'saved'}
					<div class="chat-app__conv-header">
						<span class="chat-app__conv-title">{t('chat.saved.title')}</span>
					</div>
					<SavedView onJump={jumpTo} />
				{:else if mainView === 'threads'}
					<div class="chat-app__conv-header">
						<span class="chat-app__conv-title">{t('chat.threads.title')}</span>
					</div>
					<MyThreadsView onJump={jumpTo} />
				{:else if mainView === 'search'}
					<div class="chat-app__conv-header">
						<span class="chat-app__conv-title">{t('chat.search.title')}</span>
					</div>
					<SearchView initialQuery={searchInitialQuery} initialChannelId={searchInitialChannelId} onJump={jumpTo} />
				{:else if activeConversation}
					{@const conv = activeConversation}
					<div class="chat-app__conv-header">
						<span class="chat-app__conv-title">{activeTitle}</span>
						<!-- Guest G2: server-derived container state, independent of
						     the active roster fetch used by person-level surfaces. -->
						{#if conv.hasExternalMembers}
							<Badge label={t('chat.externalBadge')} />
						{/if}
						<!-- Pillar C1 Task 3 — the persistent federated-DM badge (a
						     phishing + records-jurisdiction signal, ExternalSenderBanner
						     precedent). Text, not just an icon+tooltip like the WORM/
						     retention badges below — the plan's own "External · {domain}"
						     wording is meant to be read, not hovered for. -->
						{#if conv.federatedPeerDomain}
							<span class="chat-app__external-badge">
								<Icon name="AlertTriangle" size={14} />
								{t('chat.header.federatedBadge', { domain: conv.federatedPeerDomain })}
							</span>
						{/if}
						<!-- Pillar C2 Task 7 — the persistent room-federation badge,
						     hub AND spoke alike (the C1 External-badge genre: a records-
						     jurisdiction signal every member org's users must see, not
						     just the room owner). fedActiveOrgCount is 0 until the
						     roster fetch resolves — same "starts empty, fills in"
						     posture as activeRoster above. -->
						{#if conv.federatedRoomId}
							<span class="chat-app__external-badge">
								<Icon name="Globe" size={14} />
								{t('chat.header.federatedRoomBadge', { n: String(fedActiveOrgCount) })}
							</span>
						{/if}
						<!-- A4a Task 13 — deliberately minimal end-user compliance surface:
						     a WORM badge for a gxp channel (legalHold is NEVER projected,
						     design review #11 — holds stay invisible to the custodians they
						     target) and a retention indicator whenever an org policy or
						     per-channel override applies. Icon + title tooltip only, no
						     inline text (Task 13's own "small badge" spec); classification
						     is never rendered raw. -->
						{#if conv.classification === 'gxp'}
							<span class="chat-app__worm-badge" title={t('chat.compliance.wormChannel')} aria-label={t('chat.compliance.wormChannel')}>
								<Icon name="ShieldCheck" size={14} />
							</span>
						{/if}
						{#if retentionNotice(conv.classification, conv.retentionDays)}
							{@const notice = retentionNotice(conv.classification, conv.retentionDays) ?? ''}
							<span class="chat-app__retention-badge" title={notice} aria-label={notice}>
								<Icon name="Clock" size={14} />
							</span>
						{/if}
						<div class="chat-app__conv-actions">
							{#if !guestSession && conv.kind !== 'channel'}
								<Button variant="ghost" size="sm" onclick={openAddPeopleDialog}>{t('chat.thread.addPeople')}</Button>
							{/if}
							{#if !guestSession && meetEnabled}
								<IconButton
									label={t('chat.header.startCall')}
									size="sm"
									disabled={startingCall}
									onclick={() => startCall(conv.channelId, activeTitle || t('meet.app.titlePlaceholder'))}
								>
									<Icon name="Video" size={16} />
								</IconButton>
							{/if}
							<IconButton label={t('chat.search.inChannel')} size="sm" onclick={() => openSearch(conv.channelId)}>
								<Icon name="Search" size={16} />
							</IconButton>
							<IconButton label={t('chat.pins.open')} size="sm" active={showPinsPanel} onclick={togglePinsPanel}>
								<Icon name="Pin" size={16} />
							</IconButton>
							{#if conv.federatedRoomId}
								<IconButton
									label={t('chat.federation.roster.title')}
									size="sm"
									active={showFederationSheet}
									onclick={() => (showFederationSheet = true)}
								>
									<Icon name="Globe" size={16} />
								</IconButton>
							{/if}
							<IconButton label={t('chat.settings.open')} size="sm" onclick={() => (showSettingsSheet = true)}>
								<Icon name="Settings" size={16} />
							</IconButton>
						</div>
					</div>
					<!-- Pillar C2 Task 7 — the kicked/scope-revoked mirror banner. ONE
					     string covers both causes (Task 5's op:'remove' AND
					     op:'room_revoked' both land as the same federatedRoomRemoved
					     marker) — non-dismissible, matching the Meet B2 consent-banner
					     posture: this is server state, not a toast the user can wave
					     away while it's still true. -->
					{#if conv.federatedRoomRemoved}
						<div class="chat-app__federation-banner" role="alert">
							<Icon name="AlertTriangle" size={14} />
							<span>{t('chat.federation.removed.banner')}</span>
						</div>
					{/if}
					<MessageList
						channelId={conv.channelId}
						roster={activeRoster}
						selfUserId={chatStore.selfUserId}
						onOpenThread={(id) => {
							openThreadId = id;
							showPinsPanel = false;
						}}
					/>
					<Composer
						channelId={conv.channelId}
						canBroadcast={!guestSession && canBroadcast}
						disabled={composerDisabled}
						disabledMessage={conv.federatedRoomRemoved ? t('chat.federation.removed.composerNote') : undefined}
						noAttachments={!!conv.federatedRoomId}
						bind:this={composerRef}
					/>
				{:else}
					<div class="chat-app__placeholder">{t('chat.main.selectConversation')}</div>
				{/if}
			</div>
			{#if openThreadId != null && activeConversation}
				<div class="chat-app__thread-region">
					<ThreadPane
						parentId={openThreadId}
						channelId={activeConversation.channelId}
						roster={activeRoster}
						selfUserId={chatStore.selfUserId}
						canModerate={!guestSession && canBroadcast}
						canBroadcast={!guestSession && canBroadcast}
						{composerDisabled}
						composerDisabledMessage={activeConversation.federatedRoomRemoved
							? t('chat.federation.removed.composerNote')
							: undefined}
						noAttachments={!!activeConversation.federatedRoomId}
						onClose={() => (openThreadId = null)}
					/>
				</div>
			{:else if showPinsPanel && activeConversation}
				{@const pinsConv = activeConversation}
				<div class="chat-app__thread-region">
					<PinsPanel
						channelId={pinsConv.channelId}
						roster={activeRoster}
						onClose={() => (showPinsPanel = false)}
						onJump={(seq) => jumpTo(pinsConv.channelId, seq)}
					/>
				</div>
			{/if}
		</div>
	{/if}
</div>

{#if activeConversation}
	<ChannelSettingsSheet
		open={showSettingsSheet}
		channelId={activeConversation.channelId}
		kind={activeConversation.kind}
		canManage={!guestSession && canBroadcast}
		notifLevel={activeConversation.notifLevel ?? 'all'}
		postPermission={activeConversation.postPermission ?? 'all'}
		broadcastPermission={activeConversation.broadcastPermission ?? 'admins'}
		classification={activeConversation.classification ?? 'regular'}
		retentionDays={activeConversation.retentionDays ?? null}
		federatedRoomId={activeConversation.federatedRoomId ?? null}
		isFederatedRoomHub={activeConversation.isFederatedRoomHub ?? false}
		federatedRoomRemoved={activeConversation.federatedRoomRemoved ?? false}
		roster={activeRoster}
		onClose={() => (showSettingsSheet = false)}
		onSaved={() => {
			void loadConversations();
			refreshFedRoom();
		}}
	/>
	<FederationRosterSheet
		open={showFederationSheet}
		channelId={activeConversation.channelId}
		canManage={!guestSession && canBroadcast}
		onClose={() => (showFederationSheet = false)}
		onChanged={refreshFedRoom}
	/>
{/if}

<Dialog open={showCreate && !guestSession} title={t('chat.create.title')} onClose={() => (showCreate = false)}>
	<div class="chat-app__form">
		<Input label={t('chat.create.name')} bind:value={createName} />
		<Input label={t('chat.create.topic')} bind:value={createTopic} />
		<Select
			label={t('chat.create.visibility')}
			bind:value={createVisibility}
			options={[
				{ value: 'public', label: t('chat.create.visibility.public') },
				{ value: 'private', label: t('chat.create.visibility.private') },
			]}
		/>
	</div>
	{#snippet footer()}
		<Button variant="primary" disabled={creating || !createName.trim()} onclick={submitCreate}>
			{creating ? t('common.loading') : t('chat.create.submit')}
		</Button>
		<Button variant="secondary" onclick={() => (showCreate = false)}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<Dialog open={showDm && !guestSession} title={t('chat.dm.title')} onClose={() => (showDm = false)}>
	<div class="chat-app__form">
		<Input label={t('chat.dm.userIds')} hint={t('chat.dm.userIdsHint')} bind:value={dmUserIds} />
		<Button variant="primary" disabled={openingDm || parseUserIds(dmUserIds).length === 0} onclick={submitDm}>
			{openingDm ? t('common.loading') : t('chat.dm.submit')}
		</Button>
		<!-- Pillar C1 Task 3 — the federated-address entry point, a second
		     target inside the SAME dialog rather than a separate one (the
		     compose-time affordance the plan calls for; the External badge on
		     the resulting channel is the ongoing signal). -->
		<div class="chat-app__dm-divider">{t('chat.dm.federatedDivider')}</div>
		<Input
			label={t('chat.dm.federatedAddr')}
			hint={t('chat.dm.federatedAddrHint')}
			placeholder="user@domain.example"
			bind:value={federatedAddr}
		/>
		<Button variant="primary" disabled={openingFederatedDm || !federatedAddr.trim()} onclick={submitFederatedDm}>
			{openingFederatedDm ? t('common.loading') : t('chat.dm.federatedSubmit')}
		</Button>
	</div>
	{#snippet footer()}
		<Button variant="secondary" onclick={() => (showDm = false)}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<Dialog open={showAddPeople && !guestSession} title={t('chat.thread.addPeople')} onClose={() => (showAddPeople = false)}>
	<div class="chat-app__form">
		<Input label={t('chat.dm.userIds')} hint={t('chat.thread.addPeopleHint')} bind:value={addPeopleIds} />
	</div>
	{#snippet footer()}
		<Button variant="primary" disabled={addingPeople || parseUserIds(addPeopleIds).length === 0} onclick={submitAddPeople}>
			{addingPeople ? t('common.loading') : t('chat.thread.addPeopleSubmit')}
		</Button>
		<Button variant="secondary" onclick={() => (showAddPeople = false)}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<Dialog open={showBrowse && !guestSession} title={t('chat.browse.title')} onClose={() => (showBrowse = false)} wide>
	{#if browseLoading}
		<div class="chat-app__loading"><Spinner /></div>
	{:else if browseList.length === 0}
		<p class="chat-app__browse-empty">{t('chat.browse.empty')}</p>
	{:else}
		<ul class="chat-app__browse-list">
			{#each browseList as channel (channel.channelId)}
				<li class="chat-app__browse-row">
					<div class="chat-app__browse-info">
						<span class="chat-app__browse-name">{channel.name}</span>
						{#if channel.topic}<span class="chat-app__browse-topic">{channel.topic}</span>{/if}
						<span class="chat-app__browse-count">{t('chat.browse.members', { n: String(channel.memberCount) })}</span>
					</div>
					{#if channel.joined}
						<Button variant="ghost" size="sm" disabled>{t('chat.browse.joined')}</Button>
					{:else}
						<Button variant="secondary" size="sm" onclick={() => joinBrowsed(channel)}>{t('chat.browse.join')}</Button>
					{/if}
				</li>
			{/each}
		</ul>
	{/if}
	{#snippet footer()}
		<Button variant="secondary" onclick={() => (showBrowse = false)}>{t('common.close')}</Button>
	{/snippet}
</Dialog>

<style>
	.chat-app {
		display: flex;
		flex-direction: column;
		height: 100%;
		overflow: hidden;
	}
	.chat-app__banner {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-3);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}
	.chat-app__banner span {
		flex: 1;
	}
	/* Pillar C2 Task 7 — the kicked/scope-revoked room-mirror banner. Same
	   danger tokens as .chat-app__banner but scoped under the conv-header
	   (not the whole-app banner slot above) and non-dismissible (no close
	   button) — this is server state for as long as it's true, matching the
	   Meet B2 consent-banner posture. */
	.chat-app__federation-banner {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-3);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}
	.chat-app__loading,
	.chat-app__empty {
		display: flex;
		align-items: center;
		justify-content: center;
		flex: 1;
	}
	.chat-app__empty-actions {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		align-items: stretch;
	}
	.chat-app__body {
		flex: 1;
		display: flex;
		min-height: 0;
	}
	.chat-app__main-pane {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
		position: relative;
	}
	.chat-app__main-pane--dragover {
		outline: 2px dashed var(--accent);
		outline-offset: -4px;
	}
	.chat-app__mobile-back {
		display: none;
	}
	.chat-app__conv-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-3);
		min-height: 44px;
		border-bottom: 1px solid var(--border-subtle);
	}
	.chat-app__conv-title {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.chat-app__conv-actions {
		display: flex;
		align-items: center;
		gap: 2px;
		flex: none;
	}
	.chat-app__worm-badge,
	.chat-app__retention-badge {
		display: inline-flex;
		align-items: center;
		flex: none;
		color: var(--text-caption);
	}
	/* Pillar C1 Task 3 — persistent federated-DM badge (warning tokens,
	   matching ExternalSenderBanner's 'external' variant / MessageRow's own
	   per-row badge). */
	.chat-app__external-badge {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		flex: none;
		padding: 2px 8px;
		border-radius: var(--radius-full);
		background: var(--warning-bg);
		color: var(--warning-fg);
		font-size: var(--text-2xs);
		font-weight: var(--weight-semibold);
	}
	/* Desktop 3rd dock region — slides in beside the main pane exactly like
	   the main pane slides in beside ChannelList. */
	.chat-app__thread-region {
		flex-shrink: 0;
		width: clamp(280px, 32vw, 400px);
		height: 100%;
	}
	.chat-app__placeholder {
		flex: 1;
		display: flex;
		align-items: center;
		justify-content: center;
		color: var(--text-caption);
	}
	.chat-app__form {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	/* Pillar C1 Task 3 — separates the local-user DM form from the federated-
	   address form inside the SAME dialog. */
	.chat-app__dm-divider {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		margin-top: var(--space-1);
		padding-top: var(--space-2);
		border-top: 1px solid var(--border-subtle);
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
	.chat-app__browse-empty {
		padding: var(--space-3);
		color: var(--text-caption);
	}
	.chat-app__browse-list {
		list-style: none;
		margin: 0;
		padding: 0;
		max-height: 320px;
		overflow-y: auto;
	}
	.chat-app__browse-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		padding: var(--space-2) var(--space-1);
		border-bottom: 1px solid var(--border-subtle);
	}
	.chat-app__browse-info {
		display: flex;
		flex-direction: column;
		gap: 2px;
		min-width: 0;
	}
	.chat-app__browse-name {
		font-weight: 600;
		font-size: var(--text-sm);
	}
	.chat-app__browse-topic {
		font-size: var(--text-xs);
		color: var(--text-caption);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.chat-app__browse-count {
		font-size: var(--text-2xs);
		color: var(--text-caption);
	}

	/* Mobile: stack navigation — list ↔ conversation, matching /inbox's
	   list/reading-pane collapse rule. */
	@media (max-width: 767px) {
		.chat-app__main-pane {
			display: none;
		}
		.chat-app__body--conversation-open .chat-app__main-pane {
			display: flex;
			position: fixed;
			inset: 0;
			z-index: 20;
			background: var(--surface-card);
		}
		.chat-app__mobile-back {
			display: block;
			padding: var(--space-2);
			border-bottom: 1px solid var(--border-default);
		}
		/* ThreadPane: "mobile: pushed view" — a fixed overlay above the
		   conversation view, same push-navigation pattern as the conversation
		   pane above the channel list. */
		.chat-app__thread-region {
			position: fixed;
			inset: 0;
			z-index: 21;
			width: auto;
		}
	}
</style>
