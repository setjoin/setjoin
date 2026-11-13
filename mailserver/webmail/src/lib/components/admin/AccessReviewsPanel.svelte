<svelte:options runes={true} />
<script lang="ts">
	import { onMount } from 'svelte';
	import { Table, Badge, Button, Dialog, Input, EmptyState } from '$lib/components/ui';
	import type { TableColumn } from '$lib/components/ui';
	import {
		listAccessReviews,
		startAccessReview,
		type AccessReviewCampaign
	} from '$lib/admin/accessReviews';
	import AccessReviewCampaignPanel from './AccessReviewCampaign.svelte';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';

	let { campaignId = $bindable(null) }: { campaignId?: number | null } = $props();

	let campaigns = $state<AccessReviewCampaign[]>([]);
	let loading = $state(true);
	let error = $state('');
	let startOpen = $state(false);
	let newName = $state('');
	let startError = $state('');
	let startBusy = $state(false);

	const COLUMNS: TableColumn[] = [
		{ key: 'name', label: t('admin.access_reviews.col_name') },
		{ key: 'status', label: t('admin.access_reviews.col_status') },
		{ key: 'reviewed', label: t('admin.access_reviews.col_reviewed') },
		{ key: 'started', label: t('admin.access_reviews.col_started') }
	];

	async function load() {
		loading = true;
		error = '';
		try {
			const all = await listAccessReviews();
			// Open first, then by createdAt desc
			campaigns = [...all].sort((a, b) => {
				if (a.status === b.status) return b.createdAt.localeCompare(a.createdAt);
				return a.status === 'open' ? -1 : 1;
			});
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	onMount(load);

	function openCampaign(id: number) {
		campaignId = id;
		setParam(id);
	}

	function back() {
		campaignId = null;
		setParam(null);
		load();
	}

	function setParam(id: number | null) {
		const u = new URL(window.location.href);
		if (id == null) u.searchParams.delete('campaign');
		else u.searchParams.set('campaign', String(id));
		history.replaceState(history.state, '', u);
	}

	async function doStart() {
		if (!newName.trim()) return;
		startBusy = true;
		startError = '';
		try {
			const id = await startAccessReview(newName.trim());
			startOpen = false;
			newName = '';
			openCampaign(id);
		} catch (e) {
			startError = parseError(e).message;
		} finally {
			startBusy = false;
		}
	}


</script>

{#if campaignId != null}
	<AccessReviewCampaignPanel id={campaignId} onBack={back} />
{:else}
	<div class="sj-arv-head">
		<div>
			<h2 class="sj-arv-title">{t('admin.access_reviews.title')}</h2>
			<p class="sj-arv-sub">{t('admin.access_reviews.subtitle')}</p>
		</div>
		<Button
			variant="primary"
			onclick={() => {
				startOpen = true;
				startError = '';
				newName = '';
			}}>{t('admin.access_reviews.start')}</Button
		>
	</div>

	{#if error}<div class="sj-alert-danger" role="alert">{error}</div>{/if}

	{#if loading}
		<div class="sj-arv-skeleton" aria-hidden="true">
			{#each [1, 2, 3] as _}<div class="sj-arv-skel-row"></div>{/each}
		</div>
	{:else if campaigns.length === 0}
		<EmptyState title={t('admin.access_reviews.empty')} />
	{:else}
		{@const rows = campaigns as unknown as Record<string, unknown>[]}
		<Table columns={COLUMNS} {rows}>
			{#snippet cell(row, col)}
				{@const c = row as unknown as AccessReviewCampaign}
				{#if col.key === 'name'}
					<button class="sj-arv-link" onclick={() => openCampaign(c.id)}>{c.name}</button>
				{:else if col.key === 'status'}
					<Badge
						variant={c.status === 'open' ? 'warning' : 'success'}
						dot={true}
						label={c.status === 'open'
							? t('admin.access_reviews.open')
							: t('admin.access_reviews.closed')}
					/>
				{:else if col.key === 'reviewed'}
					<span class="sj-arv-meta">{c.reviewed} / {c.total}</span>
				{:else if col.key === 'started'}
					<span class="sj-arv-meta">{c.createdAt?.slice(0, 10)} · {c.createdBy}</span>
				{/if}
			{/snippet}
		</Table>
	{/if}
{/if}

{#if startOpen}
	<Dialog
		open={startOpen}
		title={t('admin.access_reviews.start_title')}
		onClose={() => (startOpen = false)}
	>
		{#snippet children()}
			<p class="sj-arv-start-help">{t('admin.access_reviews.start_help')}</p>
			{#if startError}<div class="sj-alert-danger" role="alert">{startError}</div>{/if}
			<Input
				bind:value={newName}
				placeholder={t('admin.access_reviews.name_placeholder')}
			/>
		{/snippet}
		{#snippet footer()}
			<Button
				variant="primary"
				onclick={doStart}
				disabled={!newName.trim() || startBusy}>{t('admin.access_reviews.start')}</Button
			>
			<Button variant="ghost" onclick={() => (startOpen = false)}>{t('common.cancel')}</Button>
		{/snippet}
	</Dialog>
{/if}

<style>
	.sj-arv-head {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: var(--space-3);
		margin-bottom: var(--space-2);
	}
	.sj-arv-title {
		margin: 0;
		font-size: var(--text-lg);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
	}
	.sj-arv-sub {
		margin: var(--space-1) 0 0;
		color: var(--text-caption);
		font-size: var(--text-sm);
	}
	.sj-arv-meta {
		color: var(--text-caption);
		font-size: var(--text-sm);
	}
	.sj-arv-link {
		background: none;
		border: none;
		color: var(--accent);
		cursor: pointer;
		font: inherit;
		padding: 0;
		text-decoration: underline;
		text-underline-offset: 2px;
	}
	.sj-arv-link:hover {
		color: var(--accent-hover);
	}
	.sj-alert-danger {
		padding: var(--space-2) var(--space-3);
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		border: 1px solid var(--danger-fg);
		font-size: var(--text-sm);
		margin-bottom: var(--space-2);
	}
	.sj-arv-skeleton {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.sj-arv-skel-row {
		height: var(--row-height, 36px);
		background: var(--surface-sunken);
		border-radius: var(--radius-sm);
		animation: sj-pulse 1.5s ease-in-out infinite;
	}
	.sj-arv-start-help {
		margin: 0 0 var(--space-3);
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}

	@keyframes sj-pulse {
		0%,
		100% {
			opacity: 1;
		}
		50% {
			opacity: 0.5;
		}
	}
</style>
