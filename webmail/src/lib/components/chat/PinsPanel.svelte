<svelte:options runes={true} />

<script lang="ts">
	// PinsPanel — A3 QoL Task 16. Renders in the SAME `.chat-app__thread-region`
	// slide-in ThreadPane already uses (desktop 3rd dock region / mobile pushed
	// view — the layout CSS for that region lives in ChatApp.svelte, same
	// convention ThreadPane follows); ChatApp keeps this panel and ThreadPane
	// mutually exclusive (opening one closes the other).
	//
	// Read model: a one-shot chat_message_pins list (chatApi.listPins) — unlike
	// ThreadPane there is no live-push arm here (pin/unpin re-stamp the
	// message's seq under change_seq, DES's own replay path; this panel just
	// re-fetches on open — a stale pin list while it's open is cheap to accept,
	// same "no live fetch for invisible state" posture DES-010 already uses).
	import * as chatApi from '$lib/chat/api';
	import type { ChatMessage, RosterMember } from '$lib/chat/api';
	import { EmptyState, Spinner, Button } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t, formatRelativeTime, localeCode } from '$lib/i18n';

	let {
		channelId,
		roster = [],
		onClose,
		onJump,
	}: {
		channelId: number;
		roster?: RosterMember[];
		onClose: () => void;
		onJump: (seq: number) => void;
	} = $props();

	let rows = $state<ChatMessage[]>([]);
	let loading = $state(true);
	let lastChannelId: number | null = null;
	// [UX #7/#14, pipeline review] a fetch failure used to render identically
	// to "no pinned messages" — distinguish the two, with a retry affordance.
	let error = $state(false);

	async function load(): Promise<void> {
		loading = true;
		error = false;
		try {
			rows = await chatApi.listPins(channelId);
		} catch {
			rows = [];
			error = true;
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		const cid = channelId;
		if (lastChannelId === cid) return;
		lastChannelId = cid;
		void load();
	});

	// Pillar C1 Task 3: authorId is null for a federated inbound message —
	// fall back to the remote address (federatedSenderAddr) instead of the
	// roster lookup, which only ever contains the local member.
	function authorName(authorId: number | null, federatedSenderAddr?: string | null): string {
		if (authorId == null) return federatedSenderAddr ?? t('chat.dm.federatedUnknownSender');
		return roster.find((m) => m.userId === authorId)?.displayName ?? String(authorId);
	}

	function snippet(m: ChatMessage): string {
		if (m.body) return m.body;
		if (m.msgType === 'voice') return t('chat.list.voiceMessage');
		return '';
	}

	function formatTime(iso: string): string {
		const diffSec = (Date.now() - new Date(iso).getTime()) / 1000;
		if (diffSec < 60) return t('chat.time.justNow');
		if (diffSec < 3600) return formatRelativeTime(-Math.round(diffSec / 60), 'minute');
		if (diffSec < 86400) return formatRelativeTime(-Math.round(diffSec / 3600), 'hour');
		return new Intl.DateTimeFormat(localeCode(), { hour: '2-digit', minute: '2-digit' }).format(new Date(iso));
	}

	async function unpin(m: ChatMessage, e: Event): Promise<void> {
		e.stopPropagation();
		const before = rows;
		rows = rows.filter((r) => r.messageId !== m.messageId);
		try {
			const { pinned } = await chatApi.togglePin(m.messageId);
			if (pinned) rows = before; // server disagreed (already re-pinned elsewhere) — restore
		} catch {
			rows = before;
		}
	}
</script>

<div class="pins-panel">
	<div class="pins-panel__header">
		<span class="pins-panel__title">{t('chat.pins.title')}</span>
		<button type="button" class="pins-panel__close" aria-label={t('common.close')} onclick={onClose}>
			<Icon name="X" size={16} />
		</button>
	</div>
	<div class="pins-panel__scroll">
		{#if loading}
			<div class="pins-panel__loading"><Spinner /></div>
		{:else if error}
			<EmptyState title={t('chat.pins.error')}>
				{#snippet action()}
					<Button variant="secondary" size="sm" onclick={() => void load()}>{t('common.retry')}</Button>
				{/snippet}
			</EmptyState>
		{:else if rows.length === 0}
			<EmptyState title={t('chat.pins.empty')} />
		{:else}
			<ul class="pins-panel__list">
				{#each rows as m (m.messageId)}
					<li>
						<button type="button" class="pins-panel__row" onclick={() => onJump(m.seq)}>
							<span class="pins-panel__row-head">
								<span class="pins-panel__author">{authorName(m.authorId, m.federatedSenderAddr)}</span>
								<span class="pins-panel__time">{formatTime(m.createdAt)}</span>
							</span>
							<span class="pins-panel__snippet">{snippet(m)}</span>
						</button>
						<button type="button" class="pins-panel__unpin" aria-label={t('chat.row.unpin')} onclick={(e) => unpin(m, e)}>
							<Icon name="Pin" size={14} />
						</button>
					</li>
				{/each}
			</ul>
		{/if}
	</div>
</div>

<style>
	.pins-panel {
		display: flex;
		flex-direction: column;
		height: 100%;
		min-width: 0;
		border-left: 1px solid var(--border-default);
		background: var(--surface-card);
	}
	.pins-panel__header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: var(--space-2) var(--space-3);
		border-bottom: 1px solid var(--border-subtle);
		min-height: 44px;
	}
	.pins-panel__title {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-secondary);
	}
	.pins-panel__close {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 44px;
		min-height: 44px;
		border: none;
		background: transparent;
		color: var(--text-secondary);
		cursor: pointer;
		border-radius: var(--radius-sm);
	}
	.pins-panel__close:hover {
		background: var(--surface-hover);
	}
	.pins-panel__scroll {
		flex: 1;
		min-height: 0;
		overflow-y: auto;
	}
	.pins-panel__loading {
		display: flex;
		align-items: center;
		justify-content: center;
		height: 100%;
	}
	.pins-panel__list {
		list-style: none;
		margin: 0;
		padding: var(--space-2);
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.pins-panel__list li {
		display: flex;
		align-items: stretch;
		gap: 2px;
	}
	.pins-panel__row {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
		gap: 2px;
		text-align: left;
		border: none;
		background: none;
		cursor: pointer;
		padding: var(--space-2);
		border-radius: var(--radius-sm);
	}
	.pins-panel__row:hover {
		background: var(--surface-hover);
	}
	.pins-panel__row-head {
		display: flex;
		align-items: baseline;
		gap: var(--space-2);
	}
	.pins-panel__author {
		font-size: var(--text-xs);
		font-weight: 600;
		color: var(--text-primary);
	}
	.pins-panel__time {
		font-size: var(--text-2xs);
		color: var(--text-caption);
	}
	.pins-panel__snippet {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.pins-panel__unpin {
		flex: none;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 32px;
		border: none;
		background: transparent;
		color: var(--text-caption);
		cursor: pointer;
		border-radius: var(--radius-sm);
	}
	.pins-panel__unpin:hover {
		background: var(--surface-hover);
		color: var(--danger-solid);
	}
</style>
