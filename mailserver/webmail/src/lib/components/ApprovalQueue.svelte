<svelte:options runes={true} />
<script lang="ts">
	import { Badge, Tabs, Button, Spinner, EmptyState } from '$lib/components/ui';
	import type { TabItem } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import type { ApprovalRequest, ApprovalStatus } from '$lib/types/approvals';

	interface Props {
		pendingItems: ApprovalRequest[];
		myRequests: ApprovalRequest[];
		selectedId: number | null;
		tab: 'pending' | 'my_requests';
		loading: boolean;
		error: string;
		currentUserEmail: string;
		onSelect: (id: number) => void;
		onTabChange: (tab: 'pending' | 'my_requests') => void;
		onRetry: () => void;
	}

	let { pendingItems, myRequests, selectedId, tab, loading, error, currentUserEmail, onSelect, onTabChange, onRetry }: Props = $props();

	// SoD defense: never show the current user's own rows in Pending
	// (backend already excludes them; this is a client-side guard)
	let displayPending = $derived(pendingItems.filter(r => r.requesterEmail !== currentUserEmail));
	let displayMy = $derived(myRequests);
	let items = $derived(tab === 'pending' ? displayPending : displayMy);

	let tabs: TabItem[] = $derived([
		{ id: 'pending', label: t('approvals.tab.pending'), count: displayPending.length },
		{ id: 'my_requests', label: t('approvals.tab.my_requests') },
	]);

	// Roving tabindex state
	let focusedIndex = $state(0);
	let rowRefs: (HTMLButtonElement | null)[] = $state([]);

	function handleKeyDown(e: KeyboardEvent, index: number) {
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			const next = Math.min(index + 1, items.length - 1);
			focusedIndex = next;
			rowRefs[next]?.focus();
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			const prev = Math.max(index - 1, 0);
			focusedIndex = prev;
			rowRefs[prev]?.focus();
		}
	}

	// Reset focused index when tab changes or items change
	$effect(() => {
		void tab; void items.length;
		focusedIndex = 0;
	});

	function statusVariant(status: ApprovalStatus): 'neutral' | 'success' | 'danger' {
		if (status === 'approved' || status === 'applied') return 'success';
		if (status === 'denied' || status === 'apply_failed') return 'danger';
		return 'neutral';
	}

	function relativeAge(iso: string): string {
		const diff = Date.now() - new Date(iso).getTime();
		const m = Math.floor(diff / 60_000);
		if (m < 60) return `${m}m`;
		const h = Math.floor(m / 60);
		if (h < 24) return `${h}h`;
		return `${Math.floor(h / 24)}d`;
	}

	function consumerLabel(type: string): string {
		if (type === 'rbac.jit_activation') return t('approvals.consumer.rbac');
		if (type === 'mail.external_send') return t('approvals.consumer.mail_external');
		if (type === 'hr.leave') return t('approvals.consumer.hr_leave');
		if (type === 'hr.expense') return t('approvals.consumer.hr_expense');
		if (type === 'guest.invite') return t('approvals.consumer.guest_invite');
		return t('approvals.consumer.mail_group');
	}

	function safePayloadText(item: ApprovalRequest, key: string): string {
		const value = item.payload?.[key];
		return typeof value === 'string' ? value : '';
	}

	function requesterLabel(item: ApprovalRequest): string {
		if (item.consumerType === 'guest.invite') {
			return safePayloadText(item, 'requester_name');
		}
		return item.requesterName || item.requesterEmail || '';
	}

	function subjectLabel(item: ApprovalRequest): string {
		if (item.consumerType === 'guest.invite') {
			return safePayloadText(item, 'invited_email') || item.subject;
		}
		return item.subject;
	}
</script>

<div class="aq-root">
	<Tabs items={tabs} active={tab} onChange={(id) => onTabChange(id as 'pending' | 'my_requests')} />

	{#if loading && items.length === 0}
		<div class="aq-loading">
			<Spinner size={20} label={t('approvals.loading')} />
		</div>
	{:else if error}
		<div class="aq-error">
			<p class="aq-error__text">{t('approvals.error.load')}</p>
			<Button variant="secondary" size="sm" onclick={onRetry}>{t('approvals.retry')}</Button>
		</div>
	{:else if items.length === 0}
		{#if tab === 'pending'}
			<EmptyState watermark title={t('approvals.empty.pending_title')} />
		{:else}
			<EmptyState title={t('approvals.empty.my_requests_title')} />
		{/if}
	{:else}
		<div class="aq-list" role="listbox" aria-label={tab === 'pending' ? t('approvals.tab.pending') : t('approvals.tab.my_requests')}>
			{#each items as item, i (item.id)}
				<button
					class="aq-row"
					class:aq-row--selected={item.id === selectedId}
					role="option"
					aria-selected={item.id === selectedId}
					tabindex={i === focusedIndex ? 0 : -1}
					bind:this={rowRefs[i]}
					onclick={() => { focusedIndex = i; onSelect(item.id); }}
					onkeydown={(e) => handleKeyDown(e, i)}
				>
					<div class="aq-row__main">
						<span class="aq-row__who">{requesterLabel(item)}</span>
						<span class="aq-row__arrow" aria-hidden="true">→</span>
						<span class="aq-row__what">{subjectLabel(item)}</span>
					</div>
					<div class="aq-row__meta">
						<span class="aq-row__consumer">{consumerLabel(item.consumerType)}</span>
						<span class="aq-row__age">{relativeAge(item.createdAt)}</span>
						<Badge variant={statusVariant(item.status)} dot label={t(`approvals.status.${item.status}`)} />
					</div>
				</button>
			{/each}
		</div>
	{/if}
</div>

<style>
	.aq-root {
		display: flex;
		flex-direction: column;
		height: 100%;
		overflow: hidden;
		background: var(--surface-card);
	}
	.aq-loading, .aq-error {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: var(--space-3);
		padding: var(--space-8);
		flex: 1;
	}
	.aq-error__text {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.aq-list {
		flex: 1;
		overflow-y: auto;
	}
	.aq-row {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		width: 100%;
		padding: var(--space-3) var(--space-4);
		border: none;
		border-bottom: 1px solid var(--border-subtle);
		background: transparent;
		cursor: pointer;
		text-align: left;
		font-family: var(--font-sans);
		transition: background var(--duration-fast) var(--ease-out);
	}
	.aq-row:hover {
		background: var(--surface-hover);
	}
	.aq-row--selected {
		background: var(--surface-selected);
	}
	.aq-row:focus-visible {
		outline: none;
		box-shadow: inset 0 0 0 2px var(--accent);
	}
	.aq-row__main {
		display: flex;
		align-items: center;
		gap: var(--space-1);
		min-width: 0;
	}
	.aq-row__who {
		font-weight: var(--weight-semibold);
		font-size: var(--text-sm);
		color: var(--text-primary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
		max-width: 120px;
	}
	.aq-row__arrow {
		color: var(--text-tertiary);
		font-size: var(--text-xs);
		flex-shrink: 0;
	}
	.aq-row__what {
		font-weight: var(--weight-semibold);
		font-size: var(--text-sm);
		color: var(--text-primary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
		flex: 1;
		min-width: 0;
	}
	.aq-row__meta {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.aq-row__consumer {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.aq-row__age {
		font-size: var(--text-xs);
		font-family: var(--font-mono);
		color: var(--text-tertiary);
	}
</style>
