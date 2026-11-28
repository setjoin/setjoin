<svelte:options runes={true} />

<script lang="ts">
	import * as api from '$lib/drive/api';
	import { type DriveBranch } from '$lib/drive/api';
	import { formatDateTime } from '$lib/i18n';
	import { Badge, Button, IconButton, Input, Spinner, Switch } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import { driveErrorMessage } from '$lib/drive/errors';
	import ResolveDialog from './ResolveDialog.svelte';

	let {
		nodeId,
		fromVersionId,
		canWrite,
		fileName,
		onChanged,
	}: {
		nodeId: number;
		/** The drawer's currently-selected version — the base for "New branch from this version". */
		fromVersionId: number;
		canWrite: boolean;
		/** The file's current name — ResolveDialog's keep_both default naming. */
		fileName: string;
		/** Fired after any mutation so the parent can refresh badges/lanes. */
		onChanged?: () => void;
	} = $props();

	const STATUS_VARIANT: Record<DriveBranch['status'], 'accent' | 'warning' | 'success' | 'neutral'> = {
		open: 'accent',
		review: 'warning',
		merged: 'success',
		discarded: 'neutral',
	};

	let branches = $state<DriveBranch[]>([]);
	let loading = $state(true);
	let showClosed = $state(false);
	let error = $state('');
	let renamingId = $state<number | null>(null);
	let renameValue = $state('');
	let newBranchName = $state('');
	let creating = $state(false);
	let resolvingBranch = $state<DriveBranch | null>(null);


	async function load() {
		loading = true;
		try {
			branches = await api.listBranches(nodeId, { all: showClosed });
			error = '';
		} catch (e) {
			error = driveErrorMessage(e);
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		void load();
	});

	function toggleShowClosed() {
		showClosed = !showClosed;
		void load();
	}

	async function submitNewBranch() {
		const name = newBranchName.trim();
		if (!name) return;
		creating = true;
		try {
			await api.createBranch(nodeId, name, fromVersionId);
			newBranchName = '';
			await load();
			onChanged?.();
		} catch (e) {
			error = driveErrorMessage(e);
		} finally {
			creating = false;
		}
	}

	function startRename(b: DriveBranch) {
		renamingId = b.id;
		renameValue = b.name;
	}

	async function commitRename(b: DriveBranch) {
		const v = renameValue.trim();
		renamingId = null;
		if (!v || v === b.name) return;
		try {
			await api.renameBranch(b.id, v);
			await load();
			onChanged?.();
		} catch (e) {
			error = driveErrorMessage(e);
		}
	}

	async function requestReview(b: DriveBranch) {
		try {
			await api.setBranchStatus(b.id, 'review');
			await load();
			onChanged?.();
		} catch (e) {
			error = driveErrorMessage(e);
		}
	}
</script>

<div class="bp">
	<div class="bp__head">
		<span class="bp__title">{t('drive.branch.panel')}</span>
		<Switch checked={showClosed} onchange={toggleShowClosed} label={t('drive.branch.showClosed')} />
	</div>

	{#if error}
		<p class="bp__error" role="alert">{error}</p>
	{/if}

	{#if canWrite}
		<div class="bp__create">
			<Input
				label={t('drive.branch.name')}
				placeholder={t('drive.branch.name')}
				bind:value={newBranchName}
				onkeydown={(e: KeyboardEvent) => {
					if (e.key === 'Enter') void submitNewBranch();
				}}
			/>
			<Button variant="secondary" size="sm" disabled={creating || !newBranchName.trim()} onclick={submitNewBranch}>
				<Icon name="GitBranch" size={14} />
				{t('drive.branch.create')}
			</Button>
		</div>
	{/if}

	{#if loading}
		<div class="bp__loading"><Spinner /></div>
	{:else if branches.length === 0}
		<p class="bp__empty">{t('drive.branch.empty')}</p>
	{:else}
		<ul class="bp__list">
			{#each branches as b (b.id)}
				<li class="bp__row">
					<div class="bp__row-head">
						{#if renamingId === b.id}
							<input
								class="bp__rename"
								bind:value={renameValue}
								onblur={() => commitRename(b)}
								onkeydown={(e) => {
									if (e.key === 'Enter') commitRename(b);
									if (e.key === 'Escape') renamingId = null;
								}}
							/>
						{:else}
							<span class="bp__name">{b.name}</span>
						{/if}
						<Badge variant={STATUS_VARIANT[b.status]} label={t(`drive.branch.status.${b.status}`)} />
						{#if b.autoCreated}
							<Badge variant="neutral" label={t('drive.branch.auto')} />
						{/if}
					</div>
					<div class="bp__meta">
						<span>{t('drive.branch.forkedAt', { n: String(b.forkedFromVersionId) })}</span>
						<span>{formatDateTime(b.createdAt)}</span>
					</div>
					{#if canWrite && (b.status === 'open' || b.status === 'review')}
						<div class="bp__actions">
							<IconButton label={t('drive.branch.rename')} size="sm" onclick={() => startRename(b)}>
								<Icon name="Pencil" size={14} />
							</IconButton>
							{#if b.status === 'open'}
								<Button variant="ghost" size="sm" onclick={() => requestReview(b)}>{t('drive.branch.review')}</Button>
							{:else}
								<span class="bp__review-requested">{t('drive.branch.reviewRequested')}</span>
							{/if}
							<Button variant="ghost" size="sm" onclick={() => (resolvingBranch = b)}>{t('drive.branch.resolve')}</Button>
						</div>
					{/if}
				</li>
			{/each}
		</ul>
	{/if}
</div>

{#if resolvingBranch}
	<ResolveDialog
		open={true}
		branch={resolvingBranch}
		{nodeId}
		{fileName}
		onClose={() => (resolvingBranch = null)}
		onResolved={() => {
			resolvingBranch = null;
			void load();
			onChanged?.();
		}}
	/>
{/if}

<style>
	.bp {
		width: 280px;
		flex-shrink: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		padding: var(--space-3);
		border-left: 1px solid var(--border-default);
		overflow-y: auto;
	}
	.bp__head {
		display: flex;
		align-items: center;
		justify-content: space-between;
	}
	.bp__title {
		font-weight: 600;
		font-size: var(--text-sm);
	}
	.bp__error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		padding: var(--space-2);
		border-radius: var(--radius-sm);
		margin: 0;
	}
	.bp__create {
		display: flex;
		align-items: flex-end;
		gap: var(--space-2);
	}
	.bp__loading {
		display: flex;
		justify-content: center;
		padding: var(--space-4);
	}
	.bp__empty {
		font-size: var(--text-sm);
		color: var(--text-caption);
		margin: 0;
	}
	.bp__list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.bp__row {
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-sm);
		padding: var(--space-2);
	}
	.bp__row-head {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.bp__name {
		flex: 1;
		font-size: var(--text-sm);
		font-weight: 500;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.bp__rename {
		flex: 1;
		font-size: var(--text-sm);
		border: 1px solid var(--border-focus, var(--indigo-600));
		border-radius: var(--radius-xs);
		padding: 2px 6px;
		background: var(--surface-card);
		color: var(--text-primary);
	}
	.bp__meta {
		display: flex;
		gap: var(--space-3);
		font-size: var(--text-xs);
		color: var(--text-caption);
		margin-top: var(--space-1);
	}
	.bp__actions {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		margin-top: var(--space-2);
	}
	.bp__review-requested {
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
</style>
