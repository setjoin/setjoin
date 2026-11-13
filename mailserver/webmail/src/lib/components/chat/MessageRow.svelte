<svelte:options runes={true} />

<script module lang="ts">
	// Design F1 grouping rule, exported so MessageList (its sole caller) computes
	// showHeader without duplicating the 5-minute constant.
	export const GROUP_WINDOW_MS = 5 * 60 * 1000;
	export function sameGroup(prev: { authorId: number | null; createdAt: string } | undefined, cur: { authorId: number | null; createdAt: string }): boolean {
		if (!prev || prev.authorId !== cur.authorId) return false;
		return new Date(cur.createdAt).getTime() - new Date(prev.createdAt).getTime() <= GROUP_WINDOW_MS;
	}

	// ponytail: one small fixed emoji set (M1 has no picker) — reused by the
	// react-hover-action popover here and by Composer's insert popover.
	export const COMMON_EMOJI = ['👍', '❤️', '😂', '🎉', '👀', '✅'] as const;
</script>

<script lang="ts">
	// MessageRow — Task 15. Replaces MessageList's Task-14 placeholder <li> body
	// wholesale (root element keeps the exact ml__row/--focused/data-testid
	// contract MessageList's own tests already pin, so that file is untouched).
	//
	// Per-genre body rendering (whole-pipeline review arch #9): the poll,
	// call, and voice/image/file-attachment genres are split into
	// MessageBodyPoll.svelte / MessageBodyCall.svelte / MessageAttachments.svelte
	// (each owns its own script+template+CSS; see those files for the
	// per-genre detail this comment used to carry). This file keeps the
	// dispatch chain (isDeleted/editing/isPoll/isCall/else), the ordinary
	// text/markdown/translation/unfurl body, and every row-level action
	// (react/reply/pin/save/translate/edit/delete, read receipts).
	import { chatStore, chatErrorMessage, chatErrorReason, type StoreMessage } from '$lib/chat/store.svelte';
	import { renderChatMarkdown } from '$lib/chat/markdown';
	import * as chatApi from '$lib/chat/api';
	import type { RosterMember } from '$lib/chat/api';
	import { Avatar, Badge, Dialog, Button, showToast } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t, formatRelativeTime, formatDateTime, localeCode, locale } from '$lib/i18n';
	import { effectiveCaps } from '$lib/stores/session';
	import MessageBodyPoll from './MessageBodyPoll.svelte';
	import MessageBodyCall from './MessageBodyCall.svelte';
	import MessageAttachments from './MessageAttachments.svelte';

	let {
		message,
		channelId,
		showHeader,
		focused = false,
		authorName,
		isMine,
		canModerate,
		roster = [],
		isFederatedRoom = false,
		onOpenThread,
	}: {
		message: StoreMessage;
		channelId: number;
		showHeader: boolean;
		focused?: boolean;
		authorName: string;
		isMine: boolean;
		canModerate: boolean;
		/** A3 QoL Task 15 — poll voter-name resolution only; optional/default
		 *  `[]` so every pre-existing caller (MessageList already has `roster`
		 *  in scope for its own authorName()) keeps working untouched. */
		roster?: RosterMember[];
		/** Pillar C2 Task 7 — true when this row's channel is bound to a
		 *  federated room (hub or spoke). Gates the RATIFIED Q1 divergence
		 *  warning on edit/delete (edits/deletes never propagate, Q11) —
		 *  false everywhere else, so every pre-C2 caller keeps its existing
		 *  warning-free flow untouched. */
		isFederatedRoom?: boolean;
		onOpenThread?: (messageId: number) => void;
	} = $props();

	let editing = $state(false);
	let draft = $state('');
	let reactPopoverOpen = $state(false);
	let moreOpen = $state(false);
	let rootEl = $state<HTMLDivElement | undefined>();

	let isDeleted = $derived(message.deletedAt != null);
	let isFailed = $derived(message.status === 'failed');
	// A4a Task 13 — a rate-limited (BZ196) failed send used to render Retry
	// with no reason, so the user just hammered it, burning more of the same
	// rate budget. undefined for a failure with no bespoke chat copy (the
	// row still offers Retry/Discard as before).
	let failedReason = $derived(chatErrorReason(message.errorCode));
	let isSending = $derived(message.status === 'sending');
	let isLive = $derived(!isDeleted && !isFailed && !isSending);
	let canEdit = $derived(isMine && isLive);
	let canDelete = $derived((isMine || canModerate) && isLive);
	let canReact = $derived(isLive);

	// ── pin (channel curation) + save (personal bookmark) — A3 QoL Task 15,
	// riding the Task 3 reducer rule: channels gate pin to owner/admin, but a
	// DM/group-DM's rows are ALL 'member' (V119) so any member may pin there
	// — admin-gating would make pin dead-on-arrival where users pin most.
	// chatStore.conversations already carries `kind` (T5 envelope); no new
	// prop needed to know it. ────────────────────────────────────────────
	let convKind = $derived(chatStore.conversations.find((c) => c.channelId === channelId)?.kind ?? 'channel');
	let canPin = $derived(isLive && (convKind === 'channel' ? canModerate : true));
	let canSave = $derived(isLive);
	let assistEnabled = $derived($effectiveCaps?.assist ?? false);
	let canTranslate = $derived(isLive && assistEnabled);
	let hasOverflow = $derived(canPin || canSave || canTranslate || canEdit || canDelete);
	let saved = $state(false);

	async function doTogglePin(): Promise<void> {
		moreOpen = false;
		const rows = chatStore.messagesByChannel[channelId];
		if (!rows) return;
		const idx = rows.findIndex((r) => r.messageId === message.messageId);
		const before = idx >= 0 ? rows[idx].pinned : undefined;
		if (idx >= 0) rows[idx] = { ...rows[idx], pinned: !before };
		try {
			const { pinned } = await chatApi.togglePin(message.messageId);
			const cur = rows.findIndex((r) => r.messageId === message.messageId);
			if (cur >= 0) rows[cur] = { ...rows[cur], pinned };
		} catch (err) {
			const cur = rows.findIndex((r) => r.messageId === message.messageId);
			if (cur >= 0) rows[cur] = { ...rows[cur], pinned: before };
			// [UX #7/#14, pipeline review] doTogglePin used to re-throw into this
			// bare onclick handler — an unhandled promise rejection with no user
			// feedback. Toast instead, matching the standard chat error idiom.
			showToast(chatErrorMessage(err), { variant: 'danger' });
		}
	}

	async function doToggleSave(): Promise<void> {
		moreOpen = false;
		const before = saved;
		saved = !before;
		try {
			const res = await chatApi.toggleSave(message.messageId);
			saved = res.saved;
		} catch {
			saved = before;
		}
	}

	// ── translate (reuse /assist) — A3 QoL Task 15 ──────────────────────
	let showingTranslation = $state(false);
	let translated = $state<string | null>(null);
	async function doTranslate(): Promise<void> {
		moreOpen = false;
		try {
			translated = await chatStore.translateMessage(message.messageId, $locale);
			showingTranslation = true;
		} catch (err) {
			// [UX #7/#14, pipeline review] was silent — the original body just
			// kept showing with no signal the click did anything at all.
			showToast(chatErrorMessage(err), { variant: 'danger' });
		}
	}
	function showOriginal(): void {
		showingTranslation = false;
	}

	// ── read receipts (DES-010, watermark projection) — A3 QoL Task 15 ──
	// Only ever rendered on the caller's own LATEST message in the channel
	// (matches the plan's "on my own latest messages" scoping) — computed
	// here, not passed in, since chatStore already carries everything
	// needed (messagesByChannel + selfUserId).
	let isLatestMine = $derived.by(() => {
		if (!isMine) return false;
		const rows = chatStore.messagesByChannel[channelId] ?? [];
		let lastId: number | null = null;
		for (const r of rows) {
			if (r.authorId === chatStore.selfUserId && r.status === 'sent') lastId = r.messageId;
		}
		return lastId === message.messageId;
	});
	let peerHasRead = $derived((chatStore.peerReadSeq[channelId] ?? 0) >= message.seq);

	// ── federated delivery tick (Pillar C1 Task 6, ack-as-receipt) ───────
	// `deliveredAt` (V139) is written EXCLUSIVELY by federation_ack's
	// peer-scoped receipt join (mailserver/sql/reducers/federation_ack.sql)
	// — a plain local message's delivered_at never leaves NULL, so this row
	// only ever needs to check the field, not re-derive "is this channel
	// federated" separately. isMine guards it to the sender's own outbound
	// copy (the only row Task 6 ever stamps). One check = "delivered to the
	// peer ORG" (applied to their store), never "read by the recipient" —
	// DES-010: the remote party has no member row, so read-state can't
	// federate; deliberately a single tick, not the CheckCheck double-tick
	// the local read-receipt below uses, so the two states stay visually
	// distinct.
	let isDelivered = $derived(isMine && message.deliveredAt != null);
	let channelReaderCount = $state<number | null>(null);
	$effect(() => {
		if (!isLatestMine || convKind !== 'channel') {
			channelReaderCount = null;
			return;
		}
		const cid = channelId;
		const seq = message.seq;
		const self = chatStore.selfUserId;
		chatApi
			.getChannelReaders(cid)
			.then((readers) => {
				channelReaderCount = readers.filter((r) => r.lastReadSeq >= seq && r.userId !== self).length;
			})
			.catch(() => {
				channelReaderCount = null;
			});
	});

	// isCall selects the MessageBodyCall genre in the dispatch chain below;
	// MessageAttachments re-derives isVoice from `message.msgType` itself
	// (it renders unconditionally and self-gates — nothing left in MessageRow
	// needs to know whether a given row is a voice message).
	let isCall = $derived(message.msgType === 'call');

	// ── federated-DM sender badge (Pillar C1 Task 3, ExternalSenderBanner
	// precedent) — PERSISTENT on every row of a federated inbound message
	// (never gated on showHeader — a phishing + records-jurisdiction signal
	// must not be hideable by consecutive-message grouping). The peer domain
	// is derived from federatedSenderAddr's own domain part rather than
	// threaded down as a separate prop — chat_message_to_json already gives
	// this row everything it needs. ──────────────────────────────────────
	let isFederated = $derived(message.federatedSenderAddr != null);
	let federatedDomain = $derived(message.federatedSenderAddr?.split('@')[1] ?? '');

	// ── inbound spam-scan quarantine affordance (Pillar C1 Task 4B) ──────
	// Only ever true on a federated inbound row (federation_apply_chat is
	// the sole writer of spam_quarantined) — modeled on the External badge
	// above + the mail app's tracker-blocked-image collapse: a quarantined
	// message renders COLLAPSED behind a warning + explicit reveal, never
	// auto-shown, and the reveal is per-row local state (not persisted —
	// re-opening the conversation re-collapses it, same as a tracker
	// banner). The applier already landed the message normally (seq
	// consumed, cursor advanced, acked — Task 4B's quarantine-on-apply
	// contract); this is purely a client-side display gate.
	let isQuarantined = $derived(message.spamQuarantined === true);
	let quarantineRevealed = $state(false);

	// ── question (whole-pipeline review UX #15) — B3 Task 3's msg_type
	// widening (Q&A rides ordinary chat messages, meet_qol.sql) gave
	// 'question' rows no identity outside MeetChatPanel's own Q&A tab, which
	// client-side-filters on msgType==='question' but never renders that fact
	// back into the row itself: in the meet Chat tab (the SAME MessageList
	// this component renders for) and in the standalone chat app browsing a
	// meeting's bound channel post-meeting, a question read as bare text,
	// indistinguishable from an ordinary message. Additive, not a replacement
	// branch (the voice precedent) — the body/markdown/edit/translation/
	// unfurl rendering below is unchanged; this only prepends an identifying
	// chip so a question is recognizable OUTSIDE the Q&A tab's own filtered
	// list too.
	let isQuestion = $derived(message.msgType === 'question');

	// ── polls (A3 QoL Task 9's seam, Task 15's render) ──────────────────
	// The render + vote/close dispatch logic lives in MessageBodyPoll.svelte
	// now — isPoll only selects it in the dispatch chain below.
	let isPoll = $derived(message.msgType === 'poll');

	// ── federation gap marker (Pillar C2 Task 7, Q9 coverage epochs) ─────
	// Task 5's spoke invite/re-admit applier inserts a LOCAL, author-less
	// `msg_type='system'` row whose body is machine-readable JSON —
	// `{"kind":"federation_gap","from":…,"to":…}` — recording a coverage gap
	// this org's mirror was parked/kicked through. Rendered as a centered
	// system row (the date-divider genre, not an authored message) instead
	// of falling into the ordinary text-body dispatch chain below, which
	// would otherwise print the raw JSON. A malformed/foreign 'system' body
	// (should never happen — chat_message_send refuses 'system' as user
	// input, V140) degrades to rendering nothing rather than raw JSON.
	interface FederationGapBody {
		kind: 'federation_gap';
		from: string;
		to: string;
	}
	let gapMarker = $derived.by((): FederationGapBody | null => {
		if (message.msgType !== 'system') return null;
		try {
			const parsed = JSON.parse(message.body) as Partial<FederationGapBody>;
			if (parsed.kind === 'federation_gap' && typeof parsed.from === 'string' && typeof parsed.to === 'string') {
				return parsed as FederationGapBody;
			}
		} catch {
			// fall through to null — a malformed body renders nothing, never raw JSON
		}
		return null;
	});

	// ── link unfurl card (A3 QoL Task 13's payload, Task 15's render) ───
	interface UnfurlPreview {
		url: string;
		title: string | null;
		description: string | null;
		imageSha256: string | null;
		/** med-chat-unfurl-href-001 r2 — provenance epoch marker, stamped by
		 *  chat_message_unfurl_apply (mailserver/sql/reducers/chat_unfurl.sql)
		 *  and required below. Absent (optional) on everything else. */
		appliedBy?: string;
	}
	// Trusted-preview provenance (med-chat-unfurl-href-001) — render-time
	// re-validation, the supporting check behind the reducer's controls (send
	// strips sender-supplied previews outright; unfurl apply allowlists
	// http/https). The anchor in this trusted enrichment chrome may only ever
	// carry an absolute http(s) URL: a javascript:/data:/vbscript: scheme, a
	// relative or malformed reference, or a non-string url (arbitrary stored
	// payload) renders NO card at all — gating the whole block on the URL, not
	// just the href, so attacker-authored card text can never appear here
	// either.
	//
	// Provenance epoch marker (r2): the URL check alone admits an
	// already-stored FORGED HTTPS card — send-time stripping protects new
	// messages but cannot establish legacy provenance (A3 adjudication). Only
	// a preview carrying the marker the unfurl reducer writes is rendered;
	// every pre-marker row (forged AND genuine legacy reducer output alike)
	// fails closed to no card. Marker forgery is closed going forward because
	// chat_message_send strips payload.preview and chat_message_unfurl_apply
	// is its sole remaining writer (chat_message_edit writes body only).
	//
	// Quarantine arm (r4, V252__chat_unfurl_legacy_preview_quarantine.sql):
	// V252 strips payload.preview from EVERY row present at migration time,
	// marker included — the marker's only writer, chat_message_unfurl_apply,
	// is installed by that same delta and migrations run before the new code
	// serves traffic, so an at-migration marker proves nothing (a legacy
	// attacker-controlled payload could carry the public constant). The
	// fail-closed leg above therefore guards an empty at-migration
	// population; only rows written after the migration by the reducer are
	// trusted. Honest residual, explicitly retained as unresolved (Astra
	// arm): a POST-migration row carrying a FORGED marker is client-side
	// indistinguishable from a reducer-written one — the marker is a public
	// constant, so client-side provenance cannot do better; closing it
	// requires sender/worker signing (owner decision). This gate remains the
	// go-forward check over whatever the server stores.
	const UNFURL_APPLY_MARKER = 'chat_message_unfurl_apply';
	function safeUnfurlPreview(p: UnfurlPreview | null): UnfurlPreview | null {
		if (p == null || typeof p !== 'object') return null;
		if (p.appliedBy !== UNFURL_APPLY_MARKER) return null; // legacy/forged row — no provenance, no card
		if (typeof p.url !== 'string') return null;
		try {
			const parsed = new URL(p.url);
			if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
			return p;
		} catch {
			return null; // relative/malformed reference — never an anchor
		}
	}
	let preview = $derived(safeUnfurlPreview((message.payload as { preview?: UnfurlPreview } | null | undefined)?.preview ?? null));
	let unfurlCollapsed = $state(false);

	function startEdit(): void {
		draft = message.body;
		editing = true;
	}

	async function saveEdit(): Promise<void> {
		const body = draft.trim();
		if (!body) return;
		// A4a Task 13: the store re-throws (chatStore.editMessage has no
		// try/catch of its own) — a gxp channel's BZ193 used to leave the edit
		// box just sitting there with no signal at all. The box now STAYS OPEN
		// on failure (editing is only ever set false on the success path).
		try {
			await chatStore.editMessage(channelId, message.messageId, body);
			editing = false;
		} catch (err) {
			showToast(chatErrorMessage(err), { variant: 'danger' });
		}
	}

	function cancelEdit(): void {
		editing = false;
	}

	async function doDelete(): Promise<void> {
		try {
			await chatStore.deleteMessage(channelId, message.messageId);
		} catch (err) {
			showToast(chatErrorMessage(err), { variant: 'danger' });
		}
	}

	// Pillar C2 Task 7 (Q1 grill hardening) — a federated room's delete gains
	// a confirmation dialog carrying the divergence warning ("your delete
	// stays in your org, other member orgs keep the original", Q11's
	// disclosed-divergence posture made visible in-product); an ordinary
	// channel/DM keeps the existing immediate-delete behavior untouched (no
	// confirm dialog ever existed there, and this task does not add one
	// outside the federated-room context).
	let showDeleteConfirm = $state(false);
	function requestDelete(): void {
		if (isFederatedRoom) {
			showDeleteConfirm = true;
		} else {
			void doDelete();
		}
	}
	async function confirmDelete(): Promise<void> {
		showDeleteConfirm = false;
		await doDelete();
	}

	async function react(emoji: string): Promise<void> {
		reactPopoverOpen = false;
		await chatStore.toggleReaction(channelId, message.messageId, emoji);
	}

	function retry(): void {
		if (message.clientId) chatStore.retry(message.clientId);
	}

	function discard(): void {
		if (message.clientId) chatStore.discard(message.clientId);
	}

	function replyLabel(n: number): string {
		return n === 1 ? t('chat.messageList.replyCountOne') : t('chat.messageList.replyCount', { n: String(n) });
	}

	// Task 16: locale-aware relative timestamp for recent messages ("just now" /
	// "2 minutes ago" / "3 hours ago" via the existing Intl.RelativeTimeFormat
	// wrapper, same seam OfflineStatus.svelte already uses), falling back to an
	// absolute locale clock time beyond 24h — day grouping is MessageList's
	// date-divider job, not this row's.
	function formatTime(iso: string): string {
		const diffSec = (Date.now() - new Date(iso).getTime()) / 1000;
		if (diffSec < 60) return t('chat.time.justNow');
		if (diffSec < 3600) return formatRelativeTime(-Math.round(diffSec / 60), 'minute');
		if (diffSec < 86400) return formatRelativeTime(-Math.round(diffSec / 3600), 'hour');
		return new Intl.DateTimeFormat(localeCode(), { hour: '2-digit', minute: '2-digit' }).format(new Date(iso));
	}

	$effect(() => {
		if (!reactPopoverOpen && !moreOpen) return;
		function onPointerDown(e: Event) {
			if (rootEl && !rootEl.contains(e.target as Node)) {
				reactPopoverOpen = false;
				moreOpen = false;
			}
		}
		function onKeydown(e: KeyboardEvent) {
			if (e.key === 'Escape') {
				reactPopoverOpen = false;
				moreOpen = false;
			}
		}
		document.addEventListener('pointerdown', onPointerDown);
		document.addEventListener('keydown', onKeydown);
		return () => {
			document.removeEventListener('pointerdown', onPointerDown);
			document.removeEventListener('keydown', onKeydown);
		};
	});

	// Attachment resolution (node-meta -> content-blob) + the voice/image/
	// file/lightbox rendering all live in MessageAttachments.svelte now (see
	// $lib/components/chat/MessageAttachments.svelte) — MessageRow just
	// mounts it unconditionally below; it self-gates on `message.attachments`/
	// `message.msgType` and renders nothing for a plain text row.
</script>

{#if message.msgType === 'system'}
	<!-- Pillar C2 Task 7 — every 'system' row is a purely local marker (no
	     author, no reactions/edit/delete/thread affordances), the date-
	     divider genre rather than an authored message. gapMarker is null for
	     a malformed/unrecognized body (should never happen — Task 5's
	     applier is the sole writer and chat_message_send refuses 'system' as
	     user input, V140) — that case renders NOTHING here rather than the
	     raw JSON a fallthrough to the ordinary text dispatch would show. -->
	{#if gapMarker}
		<div class="mrow__gap-marker" data-testid={`msg-${message.messageId}`} role="note">
			<Icon name="AlertTriangle" size={12} />
			<span>{t('chat.federation.gapMarker', { from: formatDateTime(gapMarker.from), to: formatDateTime(gapMarker.to) })}</span>
		</div>
	{/if}
{:else}
<div
	bind:this={rootEl}
	class="ml__row"
	class:ml__row--focused={focused}
	class:mrow--failed={isFailed}
	class:mrow--sending={isSending}
	data-testid={`msg-${message.messageId}`}
>
	{#if showHeader}
		<span class="mrow__avatar"><Avatar name={authorName} size="sm" /></span>
		<span class="ml__author">{authorName}</span>
		{#if message.authorExternal}<Badge label={t('chat.externalBadge')} />{/if}
		{#if message.authorRemoved}<Badge label={t('chat.removedBadge')} variant="warning" />{/if}
	{/if}
	<span class="ml__time">{formatTime(message.createdAt)}</span>
	{#if isFederated}
		<span
			class="mrow__external-badge"
			title={t('chat.header.federatedBadge', { domain: federatedDomain })}
			aria-label={t('chat.header.federatedBadge', { domain: federatedDomain })}
		>
			<Icon name="AlertTriangle" size={12} />
			{t('chat.header.federatedBadge', { domain: federatedDomain })}
		</span>
	{/if}

	{#if isQuarantined && !quarantineRevealed}
		<div class="mrow__quarantine" data-testid="quarantine-banner">
			<Icon name="AlertTriangle" size={14} />
			<span class="mrow__quarantine-text">{t('chat.row.quarantineWarning', { domain: federatedDomain })}</span>
			<button
				type="button"
				class="mrow__btn"
				data-testid="quarantine-reveal"
				onclick={() => (quarantineRevealed = true)}
			>
				{t('chat.row.quarantineReveal')}
			</button>
		</div>
	{:else if isDeleted}
		<p class="ml__body mrow__deleted">{t('chat.row.deleted')}</p>
	{:else if editing}
		<div class="mrow__edit">
			{#if isFederatedRoom}
				<p class="mrow__edit-warning">{t('chat.federation.edit.warning')}</p>
			{/if}
			<textarea class="mrow__edit-input" bind:value={draft} rows="2"></textarea>
			<div class="mrow__edit-actions">
				<button type="button" class="mrow__btn" onclick={saveEdit}>{t('common.save')}</button>
				<button type="button" class="mrow__btn" onclick={cancelEdit}>{t('common.cancel')}</button>
			</div>
		</div>
	{:else if isPoll}
		<MessageBodyPoll {message} {roster} {isMine} {canModerate} />
	{:else if isCall}
		<MessageBodyCall {message} />
	{:else}
		{#if isQuestion}
			<span class="mrow__question-chip" data-testid="question-chip">
				<Icon name="HelpCircle" size={12} />
				{t('chat.row.question')}
			</span>
		{/if}
		<!-- eslint-disable-next-line svelte/no-at-html-tags -->
		<p class="ml__body">{@html renderChatMarkdown(message.body)}{#if message.editedAt}<span class="mrow__edited"> {t('chat.row.edited')}</span>{/if}</p>
		{#if showingTranslation && translated != null}
			<div class="mrow__translation">
				<p class="mrow__translation-text">{translated}</p>
				<button type="button" class="mrow__btn" onclick={showOriginal}>{t('chat.row.showOriginal')}</button>
			</div>
		{/if}
		{#if preview}
			<div class="mrow__unfurl" style="min-height: 88px;">
				<button
					type="button"
					class="mrow__unfurl-toggle"
					aria-label={unfurlCollapsed ? t('chat.unfurl.expand') : t('chat.unfurl.collapse')}
					onclick={() => (unfurlCollapsed = !unfurlCollapsed)}
				>
					<Icon name={unfurlCollapsed ? 'ChevronRight' : 'ChevronDown'} size={14} />
				</button>
				{#if !unfurlCollapsed}
					<a class="mrow__unfurl-body" href={preview.url} target="_blank" rel="noopener noreferrer">
						{#if preview.imageSha256}
							<div class="mrow__unfurl-thumb"><img src={chatApi.unfurlImageUrl(preview.imageSha256)} alt="" /></div>
						{/if}
						<div class="mrow__unfurl-text">
							{#if preview.title}<div class="mrow__unfurl-title">{preview.title}</div>{/if}
							{#if preview.description}<div class="mrow__unfurl-desc">{preview.description}</div>{/if}
							<div class="mrow__unfurl-url">{preview.url}</div>
						</div>
					</a>
				{/if}
			</div>
		{/if}
	{/if}

	{#if !isQuarantined || quarantineRevealed}
		<MessageAttachments {message} />
	{/if}

	{#if message.reactions.length > 0}
		<div class="mrow__reactions">
			{#each message.reactions as r (r.emoji)}
				<button
					type="button"
					class="mrow__pill"
					class:mine={r.mine}
					onclick={() => react(r.emoji)}
				>
					{r.emoji} {r.count}
				</button>
			{/each}
		</div>
	{/if}

	{#if message.replyCount > 0}
		<button type="button" class="ml__reply-chip" onclick={() => onOpenThread?.(message.messageId)}>
			<Icon name="Reply" size={12} />
			{replyLabel(message.replyCount)}
		</button>
	{/if}

	<!-- federated delivery tick (Pillar C1 Task 6) — per-message, not a
	     watermark like the read receipts below, since delivered_at is a
	     per-message fact set once by federation_ack. -->
	{#if isDelivered}
		<span class="mrow__delivered-tick" title={t('chat.row.delivered')} aria-label={t('chat.row.delivered')}>
			<Icon name="CheckCircle" size={12} />
			{t('chat.row.delivered')}
		</span>
	{/if}

	<!-- read receipts (DES-010) — A3 QoL Task 15, my own latest message only -->
	{#if isLatestMine && convKind === 'dm' && peerHasRead}
		<span class="mrow__read-tick">
			<Icon name="CheckCheck" size={12} />
			{t('chat.row.read')}
		</span>
	{:else if isLatestMine && convKind === 'channel' && channelReaderCount != null && channelReaderCount > 0}
		<span class="mrow__read-caption">
			{channelReaderCount === 1 ? t('chat.row.readByOne') : t('chat.row.readBy', { n: String(channelReaderCount) })}
		</span>
	{/if}

	{#if isFailed}
		<div class="mrow__failed-actions">
			{#if failedReason}
				<span class="mrow__failed-reason">{failedReason}</span>
			{/if}
			<button type="button" class="mrow__btn" aria-label={t('common.retry')} onclick={retry}>
				<Icon name="RotateCcw" size={14} />
				{t('common.retry')}
			</button>
			<button type="button" class="mrow__btn" aria-label={t('chat.row.discard')} onclick={discard}>
				<Icon name="X" size={14} />
				{t('chat.row.discard')}
			</button>
		</div>
	{:else if !isSending && !editing}
		<div class="mrow__hover-actions">
			{#if canReact}
				<div class="mrow__react-wrap">
					<button
						type="button"
						class="mrow__action"
						aria-label={t('chat.row.react')}
						onclick={() => (reactPopoverOpen = !reactPopoverOpen)}
					>
						<Icon name="Smile" size={14} />
					</button>
					{#if reactPopoverOpen}
						<div class="mrow__react-popover" role="menu">
							{#each COMMON_EMOJI as emoji (emoji)}
								<button type="button" class="mrow__emoji-btn" role="menuitem" onclick={() => react(emoji)}>{emoji}</button>
							{/each}
						</div>
					{/if}
				</div>
			{/if}
			<button
				type="button"
				class="mrow__action"
				aria-label={t('chat.row.reply')}
				onclick={() => onOpenThread?.(message.messageId)}
			>
				<Icon name="Reply" size={14} />
			</button>
			{#if hasOverflow}
				<div class="mrow__more-wrap">
					<button
						type="button"
						class="mrow__action"
						aria-label={t('chat.row.more')}
						aria-haspopup="menu"
						aria-expanded={moreOpen}
						onclick={() => (moreOpen = !moreOpen)}
					>
						<Icon name="MoreHorizontal" size={14} />
					</button>
					{#if moreOpen}
						<div class="mrow__more-menu" role="menu">
							{#if canPin}
								<button type="button" class="mrow__more-item" role="menuitem" onclick={doTogglePin}>
									{message.pinned ? t('chat.row.unpin') : t('chat.row.pin')}
								</button>
							{/if}
							{#if canSave}
								<button type="button" class="mrow__more-item" role="menuitem" onclick={doToggleSave}>
									{saved ? t('chat.row.unsave') : t('chat.row.save')}
								</button>
							{/if}
							{#if canTranslate}
								<button type="button" class="mrow__more-item" role="menuitem" onclick={doTranslate}>
									{t('chat.row.translate')}
								</button>
							{/if}
							{#if canEdit}
								<button type="button" class="mrow__more-item" role="menuitem" onclick={() => { startEdit(); moreOpen = false; }}>
									{t('common.edit')}
								</button>
							{/if}
							{#if canDelete}
								<button type="button" class="mrow__more-item" role="menuitem" onclick={() => { moreOpen = false; requestDelete(); }}>
									{t('common.delete')}
								</button>
							{/if}
						</div>
					{/if}
				</div>
			{/if}
		</div>
	{/if}
</div>
{/if}

{#if isFederatedRoom}
	<Dialog open={showDeleteConfirm} title={t('chat.federation.delete.confirmTitle')} onClose={() => (showDeleteConfirm = false)}>
		<p class="mrow__delete-warning">{t('chat.federation.delete.warning')}</p>
		{#snippet footer()}
			<Button variant="danger" onclick={() => void confirmDelete()}>{t('chat.federation.delete.confirmAction')}</Button>
			<Button variant="secondary" onclick={() => (showDeleteConfirm = false)}>{t('common.cancel')}</Button>
		{/snippet}
	</Dialog>
{/if}

<style>
	.ml__row {
		position: relative;
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		gap: var(--space-2);
		padding: var(--space-1) var(--space-2);
		border-radius: var(--radius-sm);
	}
	.ml__row--focused {
		background: var(--surface-selected);
	}
	.mrow--sending {
		opacity: 0.55;
	}
	.mrow--failed {
		background: var(--danger-bg);
	}
	.mrow__avatar {
		display: flex;
	}
	.ml__author {
		font-weight: 600;
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.ml__time {
		font-size: var(--text-2xs);
		color: var(--text-caption);
	}
	.ml__body {
		margin: 0;
		flex-basis: 100%;
		font-size: var(--text-sm);
		color: var(--text-primary);
		white-space: pre-wrap;
		overflow-wrap: anywhere;
	}
	.mrow__deleted {
		font-style: italic;
		color: var(--text-caption);
	}
	.mrow__edited {
		font-size: var(--text-2xs);
		color: var(--text-caption);
		font-style: italic;
	}
	.mrow__edit {
		flex-basis: 100%;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.mrow__edit-input {
		width: 100%;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		padding: var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-card);
		color: var(--text-primary);
	}
	.mrow__edit-actions {
		display: flex;
		gap: var(--space-2);
	}
	/* Pillar C2 Task 7 — the Q1-ratified divergence warnings (edit affordance
	   + delete confirm dialog), both a muted caption, never alarming red —
	   this is a disclosure, not an error. */
	.mrow__edit-warning,
	.mrow__delete-warning {
		font-size: var(--text-xs);
		color: var(--text-caption);
		margin: 0;
	}
	/* the federation gap marker — the date-divider genre (centered, muted,
	   no avatar/actions), never an authored message row. */
	.mrow__gap-marker {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: var(--space-2);
		padding: var(--space-1) var(--space-3);
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
	.mrow__reactions,
	.mrow__failed-actions,
	.mrow__hover-actions {
		display: flex;
		gap: var(--space-1);
		align-items: center;
	}
	.mrow__failed-reason {
		font-size: var(--text-xs);
		color: var(--danger-fg);
	}
	.mrow__pill {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		min-height: 28px;
		border: 1px solid var(--border-default);
		background: var(--surface-card);
		border-radius: var(--radius-full);
		padding: 2px var(--space-2);
		font-size: var(--text-xs);
		color: var(--text-secondary);
		cursor: pointer;
	}
	/* ponytail: keep the compact visual size on mouse/desktop; grow the hit
	   area only where fat-finger accuracy actually matters (touch). */
	@media (pointer: coarse) {
		.mrow__pill {
			min-height: 44px;
		}
	}
	.mrow__pill.mine {
		border-color: var(--accent);
		background: var(--surface-selected);
		color: var(--accent);
	}
	.mrow__btn,
	.mrow__action {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		min-height: 44px;
		min-width: 44px;
		justify-content: center;
		border: none;
		background: transparent;
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		cursor: pointer;
		font-size: var(--text-xs);
		padding: 0 var(--space-2);
	}
	.mrow__btn {
		border: 1px solid var(--border-default);
		min-width: 0; /* text+icon button, not icon-only — width fits its label */
	}
	.mrow__action:hover,
	.mrow__btn:hover {
		background: var(--surface-hover);
	}
	.mrow__react-wrap {
		position: relative;
		display: inline-flex;
	}
	.mrow__react-popover {
		position: absolute;
		bottom: calc(100% + 4px);
		left: 0;
		z-index: 20;
		display: flex;
		gap: 2px;
		padding: 4px;
		background: var(--surface-raised);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-md);
	}
	.mrow__emoji-btn {
		min-height: 44px;
		min-width: 44px;
		border: none;
		background: transparent;
		border-radius: var(--radius-sm);
		font-size: var(--text-lg);
		cursor: pointer;
	}
	.mrow__emoji-btn:hover {
		background: var(--surface-hover);
	}
	.ml__reply-chip {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		min-height: 28px;
		border: 1px solid var(--border-default);
		background: var(--surface-card);
		border-radius: var(--radius-full);
		padding: 2px var(--space-2);
		font-size: var(--text-2xs);
		color: var(--text-secondary);
		cursor: pointer;
	}

	@media (pointer: coarse) {
		.ml__reply-chip {
			min-height: 44px;
		}
	}
	.ml__reply-chip:hover {
		background: var(--surface-hover);
	}

	/* ── hover/focus-reveal on fine pointers only (A3 QoL Task 15) ───────
	   Coarse pointers (no real :hover) keep the row always visible — the
	   plan's "per-row ⋯ always" for touch. jsdom has no `hover` media
	   support so this isn't asserted in unit tests; it's a pure CSS
	   progressive enhancement. */
	@media (hover: hover) {
		.mrow__hover-actions {
			opacity: 0;
			transition: opacity 0.1s;
		}
		.ml__row:hover .mrow__hover-actions,
		.ml__row:focus-within .mrow__hover-actions {
			opacity: 1;
		}
	}

	/* ── overflow (⋯) menu — A3 QoL Task 15 ─────────────────────────────── */
	.mrow__more-wrap {
		position: relative;
		display: inline-flex;
	}
	.mrow__more-menu {
		position: absolute;
		bottom: calc(100% + 4px);
		left: 0;
		z-index: 20;
		display: flex;
		flex-direction: column;
		min-width: 160px;
		padding: 4px;
		background: var(--surface-raised);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-md);
	}
	.mrow__more-item {
		display: flex;
		align-items: center;
		min-height: 36px;
		padding: 0 var(--space-2);
		border: none;
		background: transparent;
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
		color: var(--text-primary);
		cursor: pointer;
		text-align: left;
	}

	@media (pointer: coarse) {
		.mrow__more-item {
			min-height: 44px;
		}
	}
	.mrow__more-item:hover {
		background: var(--surface-hover);
	}

	/* ── read receipts (DES-010) — A3 QoL Task 15 ───────────────────────── */
	/* Pillar C1 Task 6 — federated delivery tick shares the same subtle
	   caption styling as the local read-tick (visually distinct only by
	   icon: single check = delivered-to-peer-org, double check = read). */
	.mrow__delivered-tick,
	.mrow__read-tick,
	.mrow__read-caption {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		font-size: var(--text-2xs);
		color: var(--text-caption);
	}

	/* ── translate — A3 QoL Task 15 ──────────────────────────────────────── */
	.mrow__translation {
		flex-basis: 100%;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		padding: var(--space-2);
		background: var(--surface-sunken);
		border-left: 2px solid var(--accent);
		border-radius: var(--radius-sm);
	}
	.mrow__translation-text {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-primary);
		white-space: pre-wrap;
	}

	/* Pillar C1 Task 3 — the persistent federated-DM sender badge (warning
	   tokens, matching ExternalSenderBanner's own 'external' variant). */
	.mrow__external-badge {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		padding: 0 6px;
		height: 18px;
		border-radius: var(--radius-full);
		background: var(--warning-bg);
		color: var(--warning-fg);
		font-size: var(--text-2xs);
		font-weight: var(--weight-semibold);
	}

	/* Pillar C1 Task 4B — the quarantine collapse banner (tracker-blocked-
	   image / External-badge precedent: warning tokens, an explicit reveal,
	   never auto-shown). */
	.mrow__quarantine {
		flex-basis: 100%;
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2);
		background: var(--warning-bg);
		color: var(--warning-fg);
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
	}
	.mrow__quarantine-text {
		flex: 1;
	}

	/* UX #15: the identifying chip for a msg_type='question' row, additive —
	   the ordinary body/markdown rendering below is unchanged. */
	.mrow__question-chip {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		margin-bottom: var(--space-1);
		padding: 0 7px;
		height: 20px;
		border-radius: var(--radius-full);
		background: var(--info-bg);
		color: var(--info-fg);
		font-size: var(--text-2xs);
		font-weight: var(--weight-semibold);
		letter-spacing: 0.02em;
		width: fit-content;
	}

	/* ── link unfurl card — A3 QoL Task 15 ───────────────────────────────
	   Fixed ~88px footprint (design C1's precedent): a clamped title/
	   description + a fixed thumbnail box, never a variable-height hero —
	   `min-height` is set as an inline style (see markup) for the same
	   jsdom getComputedStyle reason the thumbnail box above documents. */
	.mrow__unfurl {
		flex-basis: 100%;
		display: flex;
		gap: var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		overflow: hidden;
	}
	.mrow__unfurl-toggle {
		display: flex;
		align-items: center;
		justify-content: center;
		min-width: 28px;
		align-self: stretch;
		border: none;
		background: var(--surface-sunken);
		color: var(--text-secondary);
		cursor: pointer;
	}
	.mrow__unfurl-body {
		flex: 1;
		display: flex;
		gap: var(--space-2);
		padding: var(--space-2);
		min-width: 0;
		text-decoration: none;
		color: inherit;
	}
	.mrow__unfurl-thumb {
		flex-shrink: 0;
		width: 64px;
		height: 64px;
		border-radius: var(--radius-sm);
		overflow: hidden;
		background: var(--surface-sunken);
	}
	.mrow__unfurl-thumb img {
		width: 100%;
		height: 100%;
		object-fit: cover;
	}
	.mrow__unfurl-text {
		min-width: 0;
		display: flex;
		flex-direction: column;
		justify-content: center;
	}
	.mrow__unfurl-title {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		display: -webkit-box;
		line-clamp: 1;
		-webkit-line-clamp: 1;
		-webkit-box-orient: vertical;
	}
	.mrow__unfurl-desc {
		font-size: var(--text-xs);
		color: var(--text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		display: -webkit-box;
		line-clamp: 2;
		-webkit-line-clamp: 2;
		-webkit-box-orient: vertical;
	}
	.mrow__unfurl-url {
		font-size: var(--text-2xs);
		color: var(--text-caption);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
</style>
