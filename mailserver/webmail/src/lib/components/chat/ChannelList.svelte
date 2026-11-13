<svelte:options runes={true} />

<script lang="ts">
	// ChannelList — Task 13. Left-rail conversation list: rows show a resolved
	// title (server name for channels; roster-resolved counterpart(s) for
	// dm/group_dm, Design F12), last-message preview, an unread badge (99+
	// cap — Badge already caps; mention conversations get a distinct class
	// rather than a different component) and a presence dot for DM
	// counterparts (grill Q2 — 60s poll of the rows actually rendered here;
	// ponytail: "visible" == "in this list", no virtualization/viewport
	// intersection tracking for a list this size).
	import type { Conversation } from '$lib/chat/api';
	import * as chatApi from '$lib/chat/api';
	import { Badge, IconButton, Input } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';

	const PRESENCE_POLL_MS = 60_000; // grill Q2 — clients poll <=1/60s

	let {
		conversations,
		activeChannelId,
		selfUserId,
		onSelect,
		onNewChannel,
		onNewDM,
		onBrowse,
		// A3 QoL Task 16 — fixed Saved/My-Threads rows (Slack's "Later"/"Threads"
		// placement) + which pseudo-view (if any) is currently selected, so the
		// row can carry the same `.selected` treatment a real channel row gets.
		// Optional with no-op defaults so every pre-Task-16 test/call site
		// (this component's own + ChatApp's) keeps working unmodified.
		activeView = 'conversation',
		onSelectSaved = () => {},
		onSelectThreads = () => {},
		// Global search (Task 16) — an explicit Enter submit, not live-as-you-type
		// (a network search on every keystroke is unnecessary cost; the mail
		// app's own "Save search" affordance is the same explicit-action
		// convention). No-op default so this stays optional for every
		// pre-Task-16 call site.
		onSearch = () => {},
		showMemberActions = true,
	}: {
		conversations: Conversation[];
		activeChannelId: number | null;
		selfUserId: number | null;
		onSelect: (channelId: number) => void;
		onNewChannel: () => void;
		onNewDM: () => void;
		onBrowse: () => void;
		activeView?: 'conversation' | 'saved' | 'threads';
		onSelectSaved?: () => void;
		onSelectThreads?: () => void;
		onSearch?: (query: string) => void;
		showMemberActions?: boolean;
	} = $props();

	let searchQuery = $state('');
	function submitSearch(e: KeyboardEvent): void {
		if (e.key !== 'Enter') return;
		const q = searchQuery.trim();
		if (q) onSearch(q);
	}

	// My-Threads aggregate unread badge (Task 11's chat_my_threads, summed —
	// same shape as ChatStore.railBadge's own sum-across-rows convention).
	// Self-contained fetch, same posture as this component's own
	// listMembers/getPresence calls: refreshed whenever `conversations`
	// changes (ChatApp already reloads conversations on every message-shaped
	// push, so this rides that cadence for free rather than its own poll
	// timer).
	let threadsUnread = $state(0);
	async function loadThreadsUnread() {
		try {
			const threads = await chatApi.listMyThreads();
			threadsUnread = threads.reduce((sum, th) => sum + th.unreadCount, 0);
		} catch {
			// stale count beats a broken refresh — next conversations change retries
		}
	}

	// channelId -> resolved title, populated lazily for dm/group_dm rows that
	// carry no server-side `name` (roster join, chat_channel_roster — Task 11).
	let dmTitles = $state<Record<number, string>>({});
	// userId -> online, refreshed on a 60s poll for every DM counterpart
	// currently rendered.
	let presence = $state<Record<number, boolean>>({});

	function rowTitle(c: Conversation): string {
		if (c.name) return c.name;
		// Pillar C1 Task 3: a federated DM's roster has ONLY the local user
		// (the remote party is metadata, never a member row) — resolveDmTitles
		// below skips these entirely, so they'd otherwise sit stuck on the
		// "loading" fallback forever.
		if (c.federatedRemoteId) return c.federatedRemoteId;
		return dmTitles[c.channelId] ?? t('chat.list.loadingTitle');
	}

	function counterpartIds(c: Conversation): number[] {
		return c.memberIds.filter((id) => id !== selfUserId);
	}

	async function resolveDmTitles() {
		const targets = conversations.filter((c) => !c.name && !c.federatedRemoteId && dmTitles[c.channelId] === undefined);
		for (const c of targets) {
			try {
				const roster = await chatApi.listMembers(c.channelId);
				const names = counterpartIds(c)
					.map((id) => roster.find((m) => m.userId === id)?.displayName)
					.filter((n): n is string => !!n);
				dmTitles = { ...dmTitles, [c.channelId]: names.length > 0 ? names.join(', ') : t('chat.list.unknownDm') };
			} catch {
				// leave unresolved — rowTitle falls back to the loading label; next
				// conversations reload retries.
			}
		}
	}

	async function pollPresence() {
		const ids = new Set<number>();
		for (const c of conversations) {
			if (c.kind === 'channel') continue;
			for (const id of counterpartIds(c)) ids.add(id);
		}
		if (ids.size === 0) return;
		try {
			const result = await chatApi.getPresence([...ids]);
			const next: Record<number, boolean> = {};
			for (const id of ids) next[id] = result[String(id)] ?? false;
			presence = next;
		} catch {
			// stale presence beats a broken poll loop — next tick retries
		}
	}

	$effect(() => {
		conversations;
		void resolveDmTitles();
		void pollPresence();
		void loadThreadsUnread();
	});

	$effect(() => {
		const timer = setInterval(pollPresence, PRESENCE_POLL_MS);
		return () => clearInterval(timer);
	});

	function isOnline(c: Conversation): boolean {
		if (c.kind === 'channel') return false;
		return counterpartIds(c).some((id) => presence[id]);
	}

	function unreadLabel(n: number): string {
		return n > 99 ? '99+' : String(n);
	}

	// A3 QoL Task 16 — mute consequence: 'none' suppresses the badge outright;
	// 'mentions' shows it only for an actual mention (a plain unread count is
	// exactly what muting is meant to quiet); 'all' (or an absent field, e.g.
	// a pre-Task-7 fixture) behaves as before. NOT the same three-value
	// vocabulary as the global user_notification_prefs.chat_notifications
	// ('all'|'mentions'|'off') — see chat/AGENTS.md's "two different
	// vocabularies" note; this is the per-channel notifLevel.
	function isMuted(c: Conversation): boolean {
		return c.notifLevel === 'none';
	}
	function showBadge(c: Conversation): boolean {
		if (c.unreadCount <= 0) return false;
		if (c.notifLevel === 'none') return false;
		if (c.notifLevel === 'mentions') return c.hasMention;
		return true;
	}

	// whole-pipeline review UX #16: a voice message's `snippet` is empty
	// (chat_conversation_list's lastMessagePreview projects the message body,
	// which a voice message never has) — mirrors PinsPanel/SavedView/
	// SearchView's own snippet() mapping so the preview isn't blank.
	function previewSnippet(c: Conversation): string {
		const preview = c.lastMessagePreview;
		if (!preview) return '';
		if (preview.snippet) return preview.snippet;
		if (preview.msgType === 'voice') return t('chat.list.voiceMessage');
		return '';
	}
</script>

<div class="cl" class:cl--conversation-open={activeChannelId != null}>
	<div class="cl__head">
		<span class="cl__title">{t('chat.list.title')}</span>
		{#if showMemberActions}
			<div class="cl__head-actions">
				<IconButton label={t('chat.list.newChannel')} size="sm" onclick={onNewChannel}>
					<Icon name="Plus" size={16} />
				</IconButton>
				<IconButton label={t('chat.list.newDm')} size="sm" onclick={onNewDM}>
					<Icon name="UserPlus" size={16} />
				</IconButton>
				<IconButton label={t('chat.list.browse')} size="sm" onclick={onBrowse}>
					<Icon name="Search" size={16} />
				</IconButton>
			</div>
		{/if}
	</div>
	<div class="cl__search">
		<Input placeholder={t('chat.search.placeholder')} bind:value={searchQuery} onkeydown={submitSearch} />
	</div>
	<ul class="cl__fixed">
		<li>
			<button type="button" class="cl__row cl__row--fixed" class:selected={activeView === 'saved'} onclick={onSelectSaved}>
				<span class="cl__icon"><Icon name="Bookmark" size={16} /></span>
				<span class="cl__body"><span class="cl__name">{t('chat.saved.title')}</span></span>
			</button>
		</li>
		<li>
			<button type="button" class="cl__row cl__row--fixed" class:selected={activeView === 'threads'} onclick={onSelectThreads}>
				<span class="cl__icon"><Icon name="MessageSquare" size={16} /></span>
				<span class="cl__body"><span class="cl__name">{t('chat.threads.title')}</span></span>
				{#if threadsUnread > 0}
					<span class="cl__badge">{unreadLabel(threadsUnread)}</span>
				{/if}
			</button>
		</li>
	</ul>
	<ul class="cl__items">
		{#each conversations as c (c.channelId)}
			<li>
				<button
					type="button"
					class="cl__row"
					class:selected={activeChannelId === c.channelId}
					onclick={() => onSelect(c.channelId)}
				>
					<span class="cl__icon" class:cl__icon--meeting={c.meetingId != null}>
						{#if c.meetingId != null}
							<Icon name="Video" size={16} aria-label={t('chat.list.meetingChannel')} />
						{:else}
							<Icon name={c.kind === 'channel' ? 'MessageCircle' : 'Users'} size={16} />
						{/if}
						{#if isOnline(c)}
							<span class="cl__presence" aria-label={t('chat.list.online')}></span>
						{/if}
					</span>
					<span class="cl__body">
						<span class="cl__name" class:cl__name--muted={isMuted(c)}>
							{#if isMuted(c)}<Icon name="BellOff" size={12} aria-label={t('chat.mute.badge')} />{/if}
							{rowTitle(c)}
						</span>
						{#if c.hasExternalMembers}
							<span class="cl__external"><Badge label={t('chat.externalBadge')} /></span>
						{/if}
						{#if c.lastMessagePreview}
							<span class="cl__preview">{previewSnippet(c)}</span>
						{/if}
					</span>
					{#if showBadge(c)}
						<span class="cl__badge" class:cl__badge--mention={c.hasMention}>
							{unreadLabel(c.unreadCount)}
						</span>
					{/if}
				</button>
			</li>
		{/each}
	</ul>
</div>

<style>
	.cl {
		display: flex;
		flex-direction: column;
		height: 100%;
		width: 100%;
		border-right: 1px solid var(--border-default);
	}

	@media (min-width: 768px) {
		.cl {
			width: clamp(240px, 30vw, 320px);
			flex-shrink: 0;
		}
	}
	/* Mobile stack navigation: this pane hides itself once a conversation is
	   open, matching MailSidebar's own self-managed mobile collapse — the
	   parent (ChatApp) never needs to reach into a child's internals. */
	@media (max-width: 767px) {
		.cl.cl--conversation-open {
			display: none;
		}
	}
	.cl__head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: var(--space-3);
		border-bottom: 1px solid var(--border-subtle);
	}
	.cl__title {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-secondary);
	}
	.cl__head-actions {
		display: flex;
		gap: 2px;
	}
	.cl__search {
		padding: 0 var(--space-2) var(--space-2);
		flex-shrink: 0;
	}
	.cl__fixed {
		list-style: none;
		margin: 0;
		padding: var(--space-2) var(--space-2) 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		flex-shrink: 0;
		border-bottom: 1px solid var(--border-subtle);
		padding-bottom: var(--space-2);
	}
	.cl__items {
		list-style: none;
		margin: 0;
		padding: var(--space-2);
		overflow-y: auto;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.cl__row {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		width: 100%;
		border: none;
		background: none;
		cursor: pointer;
		padding: var(--space-2);
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
		color: var(--text-primary);
		text-align: left;
	}
	.cl__row:hover {
		background: var(--surface-hover);
	}
	.cl__row.selected {
		background: var(--surface-selected);
	}
	.cl__row:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.cl__external {
		display: inline-flex;
		align-self: flex-start;
	}
	.cl__icon {
		position: relative;
		display: flex;
		flex: none;
		color: var(--text-caption);
	}
	/* [UX #2a, pipeline review] a meeting-bridged channel (meetingId != null)
	   gets the accent treatment so it reads as a call, not an unlabeled ghost
	   channel — distinct color, not icon-shape alone (the AA convention this
	   app already follows for status). */
	.cl__icon--meeting {
		color: var(--accent);
	}
	.cl__presence {
		position: absolute;
		bottom: -2px;
		right: -2px;
		width: 8px;
		height: 8px;
		border-radius: var(--radius-full);
		background: var(--success-solid);
		border: 2px solid var(--surface-card);
	}
	.cl__body {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
		gap: 1px;
	}
	.cl__name {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	/* Mute consequence (A3 QoL Task 16): caption-color name, BellOff glyph. */
	.cl__name--muted {
		color: var(--text-caption);
	}
	.cl__preview {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
	.cl__badge {
		flex: none;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 18px;
		height: 18px;
		padding: 0 5px;
		border-radius: var(--radius-full);
		background: var(--accent);
		color: var(--text-inverse);
		font-family: var(--font-mono);
		font-size: var(--text-2xs);
		font-weight: 700;
	}
	/* Distinct mention styling (Design contract) — a mention is more urgent
	   than a plain unread count, so it gets the danger palette instead of the
	   default accent pill. */
	.cl__badge--mention {
		background: var(--danger-solid);
	}
</style>
